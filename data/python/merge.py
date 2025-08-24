import os
import re
import sys
import logging
import asyncio
import aiofiles
import hashlib
from typing import List, Tuple, Optional, Dict, Set
from pathlib import Path
from datetime import datetime

# ==================== 配置区域 ====================
class AdBlockConfig:
    """配置类"""
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow.txt'
    
    USE_BLOOM_FILTER = True
    BLOOM_INIT_CAP = 500000  # 增加初始容量
    BLOOM_ERROR_RATE = 0.001  # 稍微提高错误率以提高性能
    
    MAX_CONCURRENT = 4  # 减少并发数以避免资源竞争
    RULE_LEN_LIMIT = 10000
    SUPPORT_HOSTS_CONVERT = True
    
    LOG_LEVEL = logging.INFO
    # 新增性能相关配置
    BATCH_SIZE = 10000  # 批量处理大小
    MAX_RULES_PER_FILE = 500000  # 单文件最大规则数限制

# ==================== 日志初始化 ====================
def setup_logging() -> logging.Logger:
    """日志初始化"""
    logging.basicConfig(
        level=AdBlockConfig.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 布隆过滤器 ====================
# 导入第三方布隆过滤器
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_FILTER_AVAILABLE = True
    logger.info("使用pybloom_live布隆过滤器")
except ImportError:
    logger.error("未找到pybloom_live库，请安装: pip install pybloom_live")
    sys.exit(1)

# ==================== 规则解析器 ====================
class AdBlockRuleParser:
    """规则解析器 - 优化性能版本"""
    # 支持的AdGuard修饰符
    SUPPORTED_MODIFIERS = {
        'document', 'script', 'image', 'stylesheet', 'xmlhttprequest',
        'subdocument', 'third-party', 'first-party', 'collapse', 'generichide',
        'genericblock', 'elemhide', 'important', 'badfilter', 'redirect',
        'dnsrewrite', 'domain', 'all', 'https', 'http'
    }

    # 预编译正则表达式 - 优化性能
    COMMENT_REGEX = re.compile(r'^\s*[!#;]|\[Adblock|\[AdGuard')
    HOSTS_REGEX = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)\s+([a-zA-Z0-9.-]+)\s*$')
    DOMAIN_REGEX = re.compile(r'^(?:@@)?(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_REGEX = re.compile(r'^(?:@@)?(?:\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    ELEM_HIDE_REGEX = re.compile(r'^##|\#@#')
    MODIFIER_REGEX = re.compile(r'\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')
    # 纯域名匹配正则 - 优化性能
    PLAIN_DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    def __init__(self):
        self.bloom = self._init_bloom_filter()
        self.hash_table = {
            "domain": set(), "ip": set(), "adguard": set(), "normal": set()
        }

        self.stats = {
            'total': 0, 'valid': 0, 'invalid': 0, 'duplicate': 0, 'bloom_false_pos': 0,
            'domain': 0, 'ip': 0, 'elem_hide': 0, 'adguard': 0, 'regex': 0,
            'hosts_converted': 0, 'allow': 0, 'plain_domain': 0
        }

    def _init_bloom_filter(self) -> ScalableBloomFilter:
        """初始化布隆过滤器"""
        if AdBlockConfig.USE_BLOOM_FILTER:
            return ScalableBloomFilter(
                initial_capacity=AdBlockConfig.BLOOM_INIT_CAP,
                error_rate=AdBlockConfig.BLOOM_ERROR_RATE
            )
        return None

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否为注释或空行 - 优化性能"""
        line_stripped = line.strip()
        return not line_stripped or self.COMMENT_REGEX.match(line_stripped) is not None

    def get_rule_type(self, rule: str) -> str:
        """获取规则类型 - 优化性能"""
        # 按频率排序检查，最常见的类型先检查
        if self.DOMAIN_REGEX.match(rule) or self.PLAIN_DOMAIN_REGEX.match(rule):
            return "domain"
        elif '$' in rule or 'dnsrewrite' in rule:
            return "adguard"
        elif self.IP_REGEX.match(rule):
            return "ip"
        return "normal"

    def normalize_rule(self, rule: str) -> str:
        """规则标准化 - 优化性能"""
        rule_norm = rule.strip().lower()
        
        # 如果是纯域名，转换为标准格式
        if self.PLAIN_DOMAIN_REGEX.match(rule_norm):
            return f"@@||{rule_norm}^"
            
        if '$' not in rule_norm:
            # 优化：避免不必要的正则替换
            if rule_norm.startswith('||') and rule_norm.endswith('^'):
                rule_norm = rule_norm[2:-1]
            elif rule_norm.startswith('@@||') and rule_norm.endswith('^'):
                rule_norm = f"@@{rule_norm[4:-1]}"
            return rule_norm

        # 处理带修饰符的规则
        main_part, mod_part = rule_norm.split('$', 1)
        # 优化：避免不必要的正则替换
        if main_part.startswith('||') and main_part.endswith('^'):
            main_part = main_part[2:-1]
        elif main_part.startswith('@@||') and main_part.endswith('^'):
            main_part = f"@@{main_part[4:-1]}"
            
        sorted_mods = sorted(m.strip() for m in mod_part.split(','))
        return f"{main_part}${','.join(sorted_mods)}"

    def is_duplicate(self, rule: str) -> bool:
        """检查是否重复 - 优化性能"""
        rule_type = self.get_rule_type(rule)
        rule_norm = self.normalize_rule(rule)

        # 布隆过滤器快速过滤
        if rule_norm not in self.bloom:
            self.bloom.add(rule_norm)
            self.hash_table[rule_type].add(rule_norm)
            return False

        # 哈希表精确兜底
        if rule_norm in self.hash_table[rule_type]:
            self.stats['duplicate'] += 1
            return True
        else:
            self.stats['bloom_false_pos'] += 1
            self.hash_table[rule_type].add(rule_norm)
            return False

    def validate_modifiers(self, rule: str) -> bool:
        """验证修饰符 - 优化性能"""
        mod_match = self.MODIFIER_REGEX.search(rule)
        if not mod_match:
            return False
            
        mods = mod_match.group(1).split(',')
        # 优化：使用集合操作提高性能
        mod_names = {mod.split('=')[0] if '=' in mod else mod for mod in mods}
        return mod_names.issubset(self.SUPPORTED_MODIFIERS)

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性 - 优化性能"""
        self.stats['total'] += 1
        rule_stripped = rule.strip()

        # 长度过滤
        if len(rule_stripped) > AdBlockConfig.RULE_LEN_LIMIT:
            self.stats['invalid'] += 1
            return False

        # 修饰符验证
        if '$' in rule_stripped and not self.validate_modifiers(rule_stripped):
            self.stats['invalid'] += 1
            return False

        # 规则类型验证 - 优化性能
        if (self.DOMAIN_REGEX.match(rule_stripped) or
            self.IP_REGEX.match(rule_stripped) or
            self.ELEM_HIDE_REGEX.match(rule_stripped) or
            self.REGEX_RULE_REGEX.match(rule_stripped) or
            '$dnsrewrite' in rule_stripped or
            self.PLAIN_DOMAIN_REGEX.match(rule_stripped)):
            self.stats['valid'] += 1
            if rule_stripped.startswith('@@') or '#@#' in rule_stripped:
                self.stats['allow'] += 1
            return True

        self.stats['invalid'] += 1
        return False

    def convert_hosts(self, line: str) -> Optional[str]:
        """Hosts转AdBlock - 优化性能"""
        match = self.HOSTS_REGEX.match(line)
        if not match:
            return None

        ip, domain = match.groups()
        # 过滤本地无效规则
        if ip in ['127.0.0.1', '::1'] and domain in ['localhost', 'localhost.localdomain']:
            return None

        self.stats['hosts_converted'] += 1
        return f"||{domain}^"

    def classify_rule(self, line: str, is_hosts: bool = False) -> List[Tuple[str, bool]]:
        """规则分类 - 优化性能"""
        line_stripped = line.strip()
        if self.is_comment_or_empty(line_stripped):
            return []

        # 处理Hosts语法
        if is_hosts and AdBlockConfig.SUPPORT_HOSTS_CONVERT:
            hosts_rule = self.convert_hosts(line_stripped)
            if hosts_rule and not self.is_duplicate(hosts_rule) and self.validate_rule(hosts_rule):
                return [(hosts_rule, False)]

        # 纯域名规则（新增）
        if self.PLAIN_DOMAIN_REGEX.match(line_stripped):
            is_allow = True  # 纯域名默认为白名单规则
            rule = f"@@||{line_stripped}^"  # 转换为标准格式
            if not self.is_duplicate(rule) and self.validate_rule(rule):
                self.stats['plain_domain'] += 1
                return [(rule, is_allow)]
            return []

        # 元素隐藏规则
        if self.ELEM_HIDE_REGEX.match(line_stripped):
            is_allow = '#@#' in line_stripped
            if not self.is_duplicate(line_stripped) and self.validate_rule(line_stripped):
                self.stats['elem_hide'] += 1
                return [(line_stripped, is_allow)]
            return []

        # DNS重写规则
        if '$dnsrewrite' in line_stripped:
            if not self.is_duplicate(line_stripped) and self.validate_rule(line_stripped):
                self.stats['adguard'] += 1
                return [(line_stripped, False)]
            return []

        # IP规则
        ip_match = self.IP_REGEX.match(line_stripped)
        if ip_match:
            rule = ip_match.group(0)
            is_allow = rule.startswith('@@')
            if not self.is_duplicate(rule) and self.validate_rule(rule):
                self.stats['ip'] += 1
                return [(rule, is_allow)]
            return []

        # 正则规则
        if self.REGEX_RULE_REGEX.match(line_stripped):
            is_allow = line_stripped.startswith('@@')
            if not self.is_duplicate(line_stripped) and self.validate_rule(line_stripped):
                self.stats['regex'] += 1
                return [(line_stripped, is_allow)]
            return []

        # 域名/AdGuard规则
        domain_match = self.DOMAIN_REGEX.match(line_stripped)
        if domain_match or '$' in line_stripped:
            rule = line_stripped
            is_allow = rule.startswith('@@')
            if not self.is_duplicate(rule) and self.validate_rule(rule):
                if domain_match and '$' not in rule:
                    self.stats['domain'] += 1
                else:
                    self.stats['adguard'] += 1
                return [(rule, is_allow)]
            return []

        return []


class AdBlockMerger:
    """规则合并器 - 优化性能版本"""
    def __init__(self):
        self.parser = AdBlockRuleParser()
        self.block_rules: Set[str] = set()
        self.allow_rules: Set[str] = set()
        self.BATCH_THRESHOLD = AdBlockConfig.BATCH_SIZE

    def add_rule(self, rule: str, is_allow: bool):
        """添加规则 - 优化性能"""
        if is_allow:
            self.allow_rules.add(rule)
        else:
            self.block_rules.add(rule)

        # 定期优化内存使用
        if len(self.block_rules) > self.BATCH_THRESHOLD * 2:
            self._batch_optimize()

    def _batch_optimize(self):
        """批量优化 - 优化性能"""
        # 提取允许规则中的域名
        allow_domains = set()
        for rule in self.allow_rules:
            match = self.parser.DOMAIN_REGEX.match(rule)
            if match:
                allow_domains.add(match.group(1))

        # 过滤拦截规则
        self.block_rules = {
            rule for rule in self.block_rules
            if not self.parser.DOMAIN_REGEX.match(rule)
            or self.parser.DOMAIN_REGEX.match(rule).group(1) not in allow_domains
        }

    async def process_file(self, file_path: Path, is_hosts: bool = False) -> int:
        """处理文件 - 优化性能"""
        rule_count = 0
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    # 限制单文件最大规则数
                    if rule_count > AdBlockConfig.MAX_RULES_PER_FILE:
                        logger.warning(f"文件 {file_path.name} 超过最大规则限制，停止处理")
                        break
                        
                    for rule, is_allow in self.parser.classify_rule(line, is_hosts=is_hosts):
                        self.add_rule(rule, is_allow)
                        rule_count += 1
            logger.info(f"处理完成：{file_path.name} → 有效规则 {rule_count} 条")
        except FileNotFoundError:
            logger.warning(f"文件不存在：{file_path.name}")
        except PermissionError:
            logger.error(f"权限不足：{file_path.name}")
        except Exception as e:
            logger.error(f"处理 {file_path.name} 失败：{str(e)}")
        return rule_count

    async def process_all_files(self) -> int:
        """处理所有文件 - 优化性能"""
        tasks = []
        semaphore = asyncio.Semaphore(AdBlockConfig.MAX_CONCURRENT)

        # 处理AdBlock主文件
        for pattern in AdBlockConfig.ADBLOCK_PATTERNS:
            for file in AdBlockConfig.INPUT_DIR.glob(pattern):
                if file.is_file():
                    tasks.append(self._limited_task(file, is_hosts=True, semaphore=semaphore))

        # 处理允许规则文件
        for pattern in AdBlockConfig.ALLOW_PATTERNS:
            for file in AdBlockConfig.INPUT_DIR.glob(pattern):
                if file.is_file():
                    tasks.append(self._limited_task(file, is_hosts=False, semaphore=semaphore))

        if not tasks:
            logger.warning("未找到任何匹配的文件")
            return 0
            
        # 分批处理任务，避免内存溢出
        batch_size = AdBlockConfig.MAX_CONCURRENT * 2
        total = 0
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for res in results:
                if isinstance(res, int):
                    total += res
                elif isinstance(res, Exception):
                    logger.error(f"任务失败：{str(res)}")
                    
            # 每批处理完成后进行内存优化
            self._batch_optimize()
            
        return total

    async def _limited_task(self, file: Path, is_hosts: bool, semaphore: asyncio.Semaphore) -> int:
        """限制并发任务 - 优化性能"""
        async with semaphore:
            return await self.process_file(file, is_hosts=is_hosts)

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """获取排序后的规则 - 优化性能"""
        # 使用更高效的排序方法
        def sort_key(rule):
            if self.parser.IP_REGEX.match(rule):
                return (0, rule)
            elif self.parser.DOMAIN_REGEX.match(rule) and '$' not in rule:
                return (1, rule)
            elif '$' in rule:
                return (2, rule)
            elif self.parser.ELEM_HIDE_REGEX.match(rule):
                return (3, rule)
            else:
                return (4, rule)

        # 分批排序，避免内存峰值
        def batch_sort(rules):
            sorted_rules = []
            batch_size = AdBlockConfig.BATCH_SIZE
            for i in range(0, len(rules), batch_size):
                batch = rules[i:i+batch_size]
                sorted_rules.extend(sorted(batch, key=sort_key))
            return sorted_rules

        return batch_sort(list(self.block_rules)), batch_sort(list(self.allow_rules))

    def get_stats(self) -> Dict:
        """获取统计信息"""
        stats = self.parser.stats.copy()
        final_block = len(self.block_rules)
        final_allow = len(self.allow_rules)
        stats.update({
            'final_block': final_block,
            'final_allow': final_allow,
            'final_total': final_block + final_allow,
            'bloom_false_pos_rate': (stats['bloom_false_pos'] / stats['total'] * 100) 
                                    if stats['total'] > 0 else 0.0
        })
        return stats


def ensure_dirs():
    """确保目录存在"""
    AdBlockConfig.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    AdBlockConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"输入目录：{AdBlockConfig.INPUT_DIR.absolute()}")
    logger.info(f"输出目录：{AdBlockConfig.OUTPUT_DIR.absolute()}")


async def write_rules(block_rules: List[str], allow_rules: List[str]):
    """写入规则 - 优化性能"""
    batch_size = AdBlockConfig.BATCH_SIZE

    # 写入拦截规则
    output_block = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_BLOCK
    try:
        async with aiofiles.open(output_block, 'w', encoding='utf-8', newline='\n') as f:
            for i in range(0, len(block_rules), batch_size):
                await f.write('\n'.join(block_rules[i:i+batch_size]) + '\n')
        logger.info(f"写入拦截规则：{output_block.absolute()}（{len(block_rules)} 条）")
    except Exception as e:
        logger.error(f"写入拦截规则失败：{str(e)}")
        raise

    # 写入允许规则
    output_allow = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_ALLOW
    try:
        async with aiofiles.open(output_allow, 'w', encoding='utf-8', newline='\n') as f:
            for i in range(0, len(allow_rules), batch_size):
                await f.write('\n'.join(allow_rules[i:i+batch_size]) + '\n')
        logger.info(f"写入允许规则：{output_allow.absolute()}（{len(allow_rules)} 条）")
    except Exception as e:
        logger.error(f"写入允许规则失败：{str(e)}")
        raise


async def main():
    """主函数"""
    start = datetime.now()
    logger.info("=== 开始AdBlock规则合并优化（性能优化版） ===")

    ensure_dirs()
    merger = AdBlockMerger()

    total_processed = await merger.process_all_files()
    logger.info(f"文件处理完成：共处理 {total_processed} 条规则（去重前）")

    block_rules, allow_rules = merger.get_sorted_rules()
    await write_rules(block_rules, allow_rules)

    end = datetime.now()
    stats = merger.get_stats()
    logger.info("\n=== 处理统计报告 ===")
    logger.info(f"总耗时：{(end - start).total_seconds():.2f} 秒")
    logger.info(f"原始规则：{stats['total']} 条 | 有效：{stats['valid']} 条 | 无效：{stats['invalid']} 条")
    logger.info(f"去重：重复 {stats['duplicate']} 条 | 布隆假阳性 {stats['bloom_false_pos']} 条（{stats['bloom_false_pos_rate']:.4f}%）")
    logger.info(f"Hosts转换：{stats['hosts_converted']} 条")
    logger.info(f"纯域名规则：{stats['plain_domain']} 条")
    logger.info(f"最终规则：拦截 {stats['final_block']} 条 | 允许 {stats['final_allow']} 条 | 总计 {stats['final_total']} 条")
    logger.info(f"规则分布：域名 {stats['domain']} 条 | IP {stats['ip']} 条 | AdGuard {stats['adguard']} 条 | 元素隐藏 {stats['elem_hide']} 条")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.error("处理被用户中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"运行出错：{str(e)}", exc_info=True)
        sys.exit(1)