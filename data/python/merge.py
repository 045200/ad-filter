```python
import os
import re
import sys
import logging
import asyncio
import aiofiles
import hashlib
from typing import List, Tuple, Optional, Dict
from pathlib import Path
from datetime import datetime

# 尝试导入第三方布隆过滤器（优先使用，无则用内存优化版Set）
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_FILTER_AVAILABLE = True
except ImportError:
    BLOOM_FILTER_AVAILABLE = False

    class ScalableBloomFilter:
        """内存优化版布隆过滤器替代类（分桶Set，减少查询耗时）"""
        def __init__(self):
            self.domain_set = set()  # 域名规则桶（哈希存储）
            self.ip_set = set()      # IP规则桶
            self.adguard_set = set() # AdGuard规则桶
            self.normal_set = set()  # 其他规则桶

        def add(self, item: str, rule_type: str = "normal"):
            """按规则类型分桶添加（哈希压缩内存）"""
            item_hash = hashlib.md5(item.encode()).hexdigest()
            if rule_type == "domain":
                self.domain_set.add(item_hash)
            elif rule_type == "ip":
                self.ip_set.add(item_hash)
            elif rule_type == "adguard":
                self.adguard_set.add(item_hash)
            else:
                self.normal_set.add(item_hash)

        def __contains__(self, item: str, rule_type: str = "normal") -> bool:
            """按规则类型分桶查询"""
            item_hash = hashlib.md5(item.encode()).hexdigest()
            if rule_type == "domain":
                return item_hash in self.domain_set
            elif rule_type == "ip":
                return item_hash in self.ip_set
            elif rule_type == "adguard":
                return item_hash in self.adguard_set
            else:
                return item_hash in self.normal_set

# ==================== 核心配置（仅保留必要项） ====================
class AdBlockConfig:
    """精简配置：移除未使用项，聚焦核心功能"""
    # 路径配置（兼容Github Action）
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))

    # 输入/输出文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt', 'aghosts*.txt', 'filter*.txt']  # 含Hosts语法的主文件
    ALLOW_PATTERNS = ['allow*.txt', 'whitelist*.txt']                  # 允许规则文件
    OUTPUT_BLOCK = 'adblock_filter.txt'                                # 输出拦截规则
    OUTPUT_ALLOW = 'allow_filter.txt'                                  # 输出允许规则

    # 双重去重配置
    USE_BLOOM_FILTER = True
    BLOOM_INIT_CAP = 300000    # 布隆过滤器初始容量（预留冗余）
    BLOOM_ERROR_RATE = 0.0005  # 低误判率

    # 异步/过滤配置
    MAX_CONCURRENT = 8         # 最大并发文件数（避免资源超限）
    RULE_LEN_LIMIT = 10000     # 规则长度限制
    SUPPORT_HOSTS_CONVERT = True  # 保留Hosts转AdBlock逻辑

    # 日志配置
    LOG_LEVEL = logging.INFO

# ==================== 日志初始化（精简格式） ====================
def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=AdBlockConfig.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 规则解析器（去冗余+逻辑优化） ====================
class AdBlockRuleParser:
    """规则解析核心：合并重复逻辑，简化条件判断"""
    # 支持的AdGuard修饰符（必要项，无冗余）
    SUPPORTED_MODIFIERS = {
        'document', 'script', 'image', 'stylesheet', 'xmlhttprequest',
        'subdocument', 'third-party', 'first-party', 'collapse', 'generichide',
        'genericblock', 'elemhide', 'important', 'badfilter', 'redirect',
        'dnsrewrite', 'domain', 'all', 'https', 'http'
    }

    # 语法正则（聚焦核心格式，去除冗余匹配）
    COMMENT_REGEX = re.compile(r'^\s*[!#;]|\[Adblock|\[AdGuard')  # 注释/规则头过滤
    HOSTS_REGEX = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)\s+([a-zA-Z0-9.-]+)\s*$')
    DOMAIN_REGEX = re.compile(r'^(?:@@)?(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_REGEX = re.compile(r'^(?:@@)?(?:\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    ELEM_HIDE_REGEX = re.compile(r'^##|\#@#')
    MODIFIER_REGEX = re.compile(r'\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')

    def __init__(self):
        # 初始化双重去重组件
        self.bloom = self._init_bloom_filter()
        self.use_buckets = not BLOOM_FILTER_AVAILABLE
        if self.use_buckets:
            self.hash_table = {
                "domain": set(), "ip": set(), "adguard": set(), "normal": set()
            }
        else:
            self.hash_table = set()

        # 精简统计项（仅保留有用数据）
        self.stats = {
            'total': 0, 'valid': 0, 'invalid': 0, 'duplicate': 0, 'bloom_false_pos': 0,
            'domain': 0, 'ip': 0, 'elem_hide': 0, 'adguard': 0, 'regex': 0,
            'hosts_converted': 0, 'allow': 0
        }

    def _init_bloom_filter(self) -> ScalableBloomFilter:
        """初始化布隆过滤器（根据是否有第三方库选择实现）"""
        if AdBlockConfig.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            return ScalableBloomFilter(
                initial_capacity=AdBlockConfig.BLOOM_INIT_CAP,
                error_rate=AdBlockConfig.BLOOM_ERROR_RATE
            )
        return ScalableBloomFilter()

    def is_comment_or_empty(self, line: str) -> bool:
        """简化注释/空行判断"""
        line_stripped = line.strip()
        return not line_stripped or self.COMMENT_REGEX.match(line_stripped)

    def get_rule_type(self, rule: str) -> str:
        """简化规则类型判断（直接映射分桶）"""
        if self.IP_REGEX.match(rule):
            return "ip"
        elif '$' in rule or 'dnsrewrite' in rule:
            return "adguard"
        elif self.DOMAIN_REGEX.match(rule):
            return "domain"
        return "normal"

    def normalize_rule(self, rule: str) -> str:
        """规则标准化（统一去重基准，简化处理逻辑）"""
        rule_norm = rule.strip().lower()
        if '$' not in rule_norm:
            # 非修饰符规则：简化前缀后缀
            rule_norm = re.sub(r'^\|\|(.*)\^$', r'\1', rule_norm)
            return re.sub(r'^\@\@\|\|(.*)\^$', r'@@\1', rule_norm)

        # 修饰符规则：统一修饰符顺序
        main_part, mod_part = rule_norm.split('$', 1)
        main_part = re.sub(r'^\|\|(.*)\^$', r'\1', main_part)
        main_part = re.sub(r'^\@\@\|\|(.*)\^$', r'@@\1', main_part)
        sorted_mods = sorted(m.strip() for m in mod_part.split(','))
        return f"{main_part}${','.join(sorted_mods)}"

    def is_duplicate(self, rule: str) -> bool:
        """双重去重核心（简化判断流程）"""
        rule_type = self.get_rule_type(rule)
        rule_norm = self.normalize_rule(rule)

        if self.use_buckets:
            # 布隆过滤器快速过滤 (自定义分桶)
            if not self.bloom.__contains__(rule_norm, rule_type):
                self.bloom.add(rule_norm, rule_type)
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
        else:
            # 布隆过滤器快速过滤 (pybloom单一)
            if rule_norm not in self.bloom:
                self.bloom.add(rule_norm)
                self.hash_table.add(rule_norm)
                return False

            # 哈希表精确兜底
            if rule_norm in self.hash_table:
                self.stats['duplicate'] += 1
                return True
            else:
                self.stats['bloom_false_pos'] += 1
                self.hash_table.add(rule_norm)
                return False

    def validate_modifiers(self, rule: str) -> bool:
        """简化AdGuard修饰符验证（仅检查必要项）"""
        mod_match = self.MODIFIER_REGEX.search(rule)
        if not mod_match:
            return False
        for mod in mod_match.group(1).split(','):
            mod_name = mod.split('=')[0] if '=' in mod else mod
            if mod_name not in self.SUPPORTED_MODIFIERS:
                logger.debug(f"忽略未知修饰符规则: {rule}（{mod_name}）")
                return False
        return True

    def validate_rule(self, rule: str) -> bool:
        """简化规则有效性判断（合并条件）"""
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

        # 规则类型验证
        if any([
            self.DOMAIN_REGEX.match(rule_stripped),
            self.IP_REGEX.match(rule_stripped),
            self.ELEM_HIDE_REGEX.match(rule_stripped),
            self.REGEX_RULE_REGEX.match(rule_stripped),
            '$dnsrewrite' in rule_stripped
        ]):
            self.stats['valid'] += 1
            if rule_stripped.startswith('@@') or '#@#' in rule_stripped:
                self.stats['allow'] += 1
            return True

        self.stats['invalid'] += 1
        return False

    def convert_hosts(self, line: str) -> Optional[str]:
        """简化Hosts转AdBlock逻辑（去除冗余判断）"""
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
        """精简规则分类逻辑（去除冗余分支）"""
        line_stripped = line.strip()
        if self.is_comment_or_empty(line_stripped):
            return []

        # 处理Hosts语法（仅在is_hosts=True时触发）
        if is_hosts and AdBlockConfig.SUPPORT_HOSTS_CONVERT:
            hosts_rule = self.convert_hosts(line_stripped)
            if hosts_rule and not self.is_duplicate(hosts_rule) and self.validate_rule(hosts_rule):
                return [(hosts_rule, False)]

        # 元素隐藏规则
        if self.ELEM_HIDE_REGEX.match(line_stripped):
            is_allow = '#@#' in line_stripped
            if not self.is_duplicate(line_stripped) and self.validate_rule(line_stripped):
                self.stats['elem_hide'] += 1
                return [(line_stripped, is_allow)]
            return []

        # DNS重写规则（归为AdGuard规则）
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

# ==================== 规则合并器（精简内存占用） ====================
class AdBlockMerger:
    """规则合并核心：简化批处理逻辑，减少内存冗余"""
    def __init__(self):
        self.parser = AdBlockRuleParser()
        self.block_rules = set()
        self.allow_rules = set()
        self.BATCH_THRESHOLD = 10000  # 分批次优化阈值（控制内存）

    def add_rule(self, rule: str, is_allow: bool):
        """简化规则添加逻辑，批量优化内存"""
        if is_allow:
            self.allow_rules.add(rule)
        else:
            self.block_rules.add(rule)

        # 分批次清理被允许规则覆盖的拦截规则
        if len(self.block_rules) > self.BATCH_THRESHOLD * 2:
            self._batch_optimize()

    def _batch_optimize(self):
        """精简批量优化逻辑（聚焦核心过滤）"""
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
        """简化文件处理逻辑，统一错误捕获"""
        rule_count = 0
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    for rule, is_allow in self.parser.classify_rule(line, is_hosts=is_hosts):
                        self.add_rule(rule, is_allow)
                        rule_count += 1
            logger.info(f"处理完成：{file_path.name} → 有效规则 {rule_count} 条")
        except Exception as e:
            logger.error(f"处理 {file_path.name} 失败：{str(e)}")
        return rule_count

    async def process_all_files(self) -> int:
        """简化批量文件处理（用Path.glob统一路径，控制并发）"""
        # 收集所有任务（AdBlock文件启用Hosts处理，允许文件不启用）
        tasks = []
        semaphore = asyncio.Semaphore(AdBlockConfig.MAX_CONCURRENT)

        # 处理AdBlock主文件（含Hosts语法）
        for pattern in AdBlockConfig.ADBLOCK_PATTERNS:
            for file in AdBlockConfig.INPUT_DIR.glob(pattern):
                tasks.append(self._limited_task(file, is_hosts=True, semaphore=semaphore))

        # 处理允许规则文件
        for pattern in AdBlockConfig.ALLOW_PATTERNS:
            for file in AdBlockConfig.INPUT_DIR.glob(pattern):
                tasks.append(self._limited_task(file, is_hosts=False, semaphore=semaphore))

        # 执行并发任务
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total = 0
        for res in results:
            if isinstance(res, int):
                total += res
            else:
                logger.error(f"任务失败：{str(res)}")
        return total

    async def _limited_task(self, file: Path, is_hosts: bool, semaphore: asyncio.Semaphore) -> int:
        """简化并发控制逻辑"""
        async with semaphore:
            return await self.process_file(file, is_hosts=is_hosts)

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """简化规则排序（按类型优先级，提升可用性）"""
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

        return sorted(self.block_rules, key=sort_key), sorted(self.allow_rules, key=sort_key)

    def get_stats(self) -> Dict:
        """精简统计数据（合并最终结果）"""
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

# ==================== 工具函数（仅保留必要项） ====================
def ensure_dirs():
    """简化目录创建（仅确保输入输出目录存在）"""
    AdBlockConfig.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    AdBlockConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"输入目录：{AdBlockConfig.INPUT_DIR.absolute()}")
    logger.info(f"输出目录：{AdBlockConfig.OUTPUT_DIR.absolute()}")

async def write_rules(block_rules: List[str], allow_rules: List[str]):
    """简化规则写入（分批次避免内存峰值）"""
    batch_size = 10000

    # 写入拦截规则
    output_block = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_BLOCK
    async with aiofiles.open(output_block, 'w', encoding='utf-8', newline='\n') as f:
        for i in range(0, len(block_rules), batch_size):
            await f.write('\n'.join(block_rules[i:i+batch_size]) + '\n')
    logger.info(f"写入拦截规则：{output_block.absolute()}（{len(block_rules)} 条）")

    # 写入允许规则
    output_allow = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_ALLOW
    async with aiofiles.open(output_allow, 'w', encoding='utf-8', newline='\n') as f:
        for i in range(0, len(allow_rules), batch_size):
            await f.write('\n'.join(allow_rules[i:i+batch_size]) + '\n')
    logger.info(f"写入允许规则：{output_allow.absolute()}（{len(allow_rules)} 条）")

# ==================== 主程序（精简流程） ====================
async def main():
    start = datetime.now()
    logger.info("=== 开始AdBlock规则合并优化（精简版） ===")

    # 初始化目录与合并器
    ensure_dirs()
    merger = AdBlockMerger()

    # 处理文件与生成结果
    total_processed = await merger.process_all_files()
    logger.info(f"文件处理完成：共处理 {total_processed} 条规则（去重前）")

    block_rules, allow_rules = merger.get_sorted_rules()
    await write_rules(block_rules, allow_rules)

    # 输出统计报告
    end = datetime.now()
    stats = merger.get_stats()
    logger.info("\n=== 处理统计报告 ===")
    logger.info(f"总耗时：{(end - start).total_seconds():.2f} 秒")
    logger.info(f"原始规则：{stats['total']} 条 | 有效：{stats['valid']} 条 | 无效：{stats['invalid']} 条")
    logger.info(f"去重：重复 {stats['duplicate']} 条 | 布隆假阳性 {stats['bloom_false_pos']} 条（{stats['bloom_false_pos_rate']:.4f}%）")
    logger.info(f"Hosts转换：{stats['hosts_converted']} 条（来自adblock*.txt）")
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
```