#!/usr/bin/env python3
"""
AdGuard规则处理器 - 白名单规则优化版
专门处理包含大量白名单规则的文件
"""

import os
import re
import sys
import logging
import asyncio
import aiofiles
import hashlib
from typing import List, Set, Dict, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime

# ==================== 环境配置 ====================
class AdBlockConfig:
    """配置类 - 白名单规则优化"""
    # 基础路径配置
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))

    # 文件模式配置
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow_filter.txt'

    # 布隆过滤器配置
    BLOOM_INIT_CAP = 600000
    BLOOM_ERROR_RATE = 0.0001

    # 性能配置
    MAX_CONCURRENT = 2
    RULE_LEN_LIMIT = 15000
    BATCH_SIZE = 5000
    MAX_RULES_PER_FILE = 300000

    # 语法支持配置
    SUPPORT_HOSTS_CONVERT = True
    SUPPORT_PLAIN_DOMAIN = True
    MIN_DOMAIN_LENGTH = 2
    LENIENT_PARSING = True

# ==================== 日志初始化 ====================
def setup_logging() -> logging.Logger:
    """日志初始化"""
    logger = logging.getLogger('AdBlockProcessor')
    logger.setLevel(logging.INFO)
    
    if logger.hasHandlers():
        logger.handlers.clear()
        
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# ==================== 布隆过滤器初始化 ====================
try:
    from pybloom_live import ScalableBloomFilter
    logger.info("使用pybloom_live布隆过滤器")
except ImportError:
    logger.error("未找到pybloom_live库，请安装: pip install pybloom_live")
    sys.exit(1)

# ==================== 规则解析器 ====================
class AdBlockRuleParser:
    """
    AdGuard规则解析器 - 白名单优化版
    专门优化处理白名单规则
    """

    # 预编译正则表达式 - 白名单规则优化
    COMMENT_REGEX = re.compile(r'^\s*[!#;]|^!\s*\[Adblock|^!\s*Title|^!\s*Version|^!\s*Expires', re.IGNORECASE)
    HOSTS_REGEX = re.compile(r'^\s*(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)\s+([a-zA-Z0-9.*_-]+)\s*(?:#.*)?$')
    
    # 宽松的域名规则匹配 - 特别优化白名单规则
    DOMAIN_RULE_REGEX = re.compile(r'^(@@?)?(\|\||\|)?([^#\s]+?)(\^?|\$?[^#\s]*)?\s*(?:#.*)?$')
    
    # 元素隐藏规则 - 宽松匹配
    ELEMENT_HIDE_REGEX = re.compile(r'^#@?#([^#\s].*)$')
    
    # 修饰符解析 - 宽松匹配
    MODIFIER_REGEX = re.compile(r'\$([a-zA-Z0-9-]+(?:=[^,\s]+)?(?:,[a-zA-Z0-9-]+(?:=[^,\s]+)?)*)\s*$')
    
    # 正则表达式规则 - 宽松匹配
    REGEX_RULE_REGEX = re.compile(r'^/(.+)/\$?[^#]*(?:#.*)?$')
    
    # 纯域名检测 - 宽松条件
    PLAIN_DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9.*_-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$')

    # 支持的修饰符列表 - 扩展版
    SUPPORTED_MODIFIERS = {
        'document', 'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
        'subdocument', 'websocket', 'webrtc', 'media', 'font', 'other',
        'third-party', 'first-party', 'popup', 'collapse', 'generichide',
        'genericblock', 'elemhide', 'jsinject', 'content', 'extension',
        'important', 'badfilter', 'redirect', 'redirect-rule', 'removeparam',
        'removeheader', 'cname', 'dnsrewrite', 'dnstype', 'max-age',
        'all', 'to', 'from', 'method', 'domain', 'denyallow',
        'client', 'ctag', 'app',
        'match-case', '~third-party', '~first-party', '~image', '~script',
        '~object', '~xmlhttprequest', '~websocket', '~webrtc', '~media',
        '~font', '~other', '~document', '~stylesheet', '~subdocument'
    }

    def __init__(self):
        """初始化解析器"""
        # 双布隆过滤器 + 哈希表精确去重
        self.bloom_all = ScalableBloomFilter(
            initial_capacity=AdBlockConfig.BLOOM_INIT_CAP,
            error_rate=AdBlockConfig.BLOOM_ERROR_RATE
        )
        self.bloom_unique = ScalableBloomFilter(
            initial_capacity=AdBlockConfig.BLOOM_INIT_CAP,
            error_rate=AdBlockConfig.BLOOM_ERROR_RATE
        )
        self.confirmed_rules: Set[str] = set()

        # 规则统计
        self.stats = {
            'total_processed': 0, 'valid_rules': 0, 'invalid_rules': 0,
            'duplicates': 0, 'bloom_false_positives': 0, 'hosts_converted': 0,
            'plain_domain_converted': 0, 'lenient_accepted': 0,
            'whitelist_rules': 0  # 新增白名单规则统计
        }

    def _generate_rule_hash(self, rule: str) -> str:
        """生成规则的哈希值用于精确比较"""
        return hashlib.sha256(rule.encode('utf-8')).hexdigest()

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否为注释或空行 - 宽松模式"""
        line = line.strip()
        if not line:
            return True
            
        # 检查标准注释
        if line.startswith(('!', '#', ';')):
            # 检查是否是特殊注释（可能包含规则）
            if line.startswith('!#') or line.startswith('!+') or line.startswith('! '):
                return False
            return True
            
        # 检查Adblock Plus头部
        if line.startswith('[Adblock') or '[Adblock Plus' in line:
            return True
            
        return False

    def normalize_rule(self, rule: str) -> str:
        """规则标准化处理 - 宽松模式"""
        rule = rule.strip()
        if not rule:
            return ""

        # 分离规则主体和注释 - 宽松处理
        if '#' in rule and not rule.startswith('#'):
            parts = rule.split('#', 1)
            rule = parts[0].strip()
            # 保留可能包含重要信息的注释部分
            if len(parts) > 1 and parts[1].strip() and len(parts[1].strip()) < 20:
                rule += ' #' + parts[1].strip()

        # 对于非元素隐藏规则，转换为小写
        if not rule.startswith(('##', '#@#')):
            rule = rule.lower()

        # 处理修饰符标准化 - 宽松处理
        if '$' in rule:
            parts = rule.split('$', 1)
            base_rule = parts[0].rstrip()
            modifiers = parts[1]

            # 处理修饰符中的注释
            if '#' in modifiers:
                mod_parts = modifiers.split('#', 1)
                modifiers = mod_parts[0].strip()
                # 保留简短的注释
                if len(mod_parts) > 1 and mod_parts[1].strip() and len(mod_parts[1].strip()) < 10:
                    modifiers += ' #' + mod_parts[1].strip()

            # 分割修饰符并排序 - 宽松处理未知修饰符
            mod_list = []
            for mod in modifiers.split(','):
                mod = mod.strip()
                if not mod:
                    continue
                    
                if '=' in mod:
                    key, value = mod.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # 处理域名列表排序
                    if key == 'domain' and '|' in value:
                        domains = sorted(set(value.split('|')))
                        value = '|'.join(domains)
                    mod_list.append(f"{key}={value}")
                else:
                    # 即使是不认识的修饰符也保留
                    mod_list.append(mod)

            # 排序修饰符以确保一致性
            try:
                mod_list.sort()
            except:
                # 如果排序失败，保持原顺序
                pass
                
            rule = f"{base_rule}${','.join(mod_list)}"

        return rule

    def validate_modifiers(self, modifiers: str) -> bool:
        """验证修饰符有效性 - 宽松模式"""
        if not modifiers:
            return True

        # 宽松模式：允许任何修饰符
        if AdBlockConfig.LENIENT_PARSING:
            return True

        # 严格模式：只检查已知修饰符
        for mod in modifiers.split(','):
            mod = mod.strip()
            if '=' in mod:
                key = mod.split('=')[0].strip()
                if key not in self.SUPPORTED_MODIFIERS:
                    return False
            else:
                if mod not in self.SUPPORTED_MODIFIERS:
                    return False

        return True

    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复 - 双布隆过滤器+哈希表"""
        rule_norm = self.normalize_rule(rule)
        if not rule_norm:
            return True

        rule_hash = self._generate_rule_hash(rule_norm)
        self.stats['total_processed'] += 1

        # 第一层: 布隆过滤器初筛
        if rule_norm not in self.bloom_all:
            self.bloom_all.add(rule_norm)
            self.bloom_unique.add(rule_norm)
            self.confirmed_rules.add(rule_hash)
            return False

        # 第二层: 唯一性布隆过滤器检查
        if rule_norm not in self.bloom_unique:
            self.stats['duplicates'] += 1
            return True

        # 第三层: 哈希表精确确认
        if rule_hash in self.confirmed_rules:
            self.stats['duplicates'] += 1
            return True
        else:
            # 布隆过滤器假阳性情况
            self.stats['bloom_false_positives'] += 1
            self.confirmed_rules.add(rule_hash)
            return False

    def validate_rule(self, rule: str) -> bool:
        """验证规则基本有效性 - 宽松模式"""
        if not rule or len(rule) > AdBlockConfig.RULE_LEN_LIMIT:
            self.stats['invalid_rules'] += 1
            return False

        # 宽松模式下不严格验证修饰符
        if not AdBlockConfig.LENIENT_PARSING and '$' in rule:
            parts = rule.split('$', 1)
            if len(parts) > 1 and not self.validate_modifiers(parts[1]):
                self.stats['invalid_rules'] += 1
                return False

        self.stats['valid_rules'] += 1
        return True

    def convert_hosts_rule(self, line: str) -> Optional[str]:
        """转换Hosts规则为AdGuard格式"""
        match = self.HOSTS_REGEX.match(line)
        if not match:
            return None

        domain = match.group(1)
        if not domain or len(domain) < AdBlockConfig.MIN_DOMAIN_LENGTH:
            return None

        # 跳过本地域名
        if domain in ['localhost', 'localhost.localdomain', 'local', 'broadcasthost']:
            return None

        self.stats['hosts_converted'] += 1
        return f"||{domain}^"

    def lenient_whitelist_conversion(self, rule: str) -> Optional[Tuple[str, bool]]:
        """宽容模式下的白名单规则转换 - 专门处理白名单规则"""
        # 处理白名单规则的特殊情况
        original_rule = rule
        
        # 处理可能包含注释的规则
        if '#' in rule and not rule.startswith('#'):
            rule = rule.split('#')[0].strip()
            
        # 处理可能包含多余空格的规则
        rule = re.sub(r'\s+', ' ', rule).strip()
        
        # 确保规则以@@开头
        if not rule.startswith('@@'):
            # 尝试添加@@前缀
            rule = '@@' + rule
            
        # 分离白名单标记和规则内容
        is_allow = rule.startswith('@@')
        if is_allow:
            rule_content = rule[2:]
        else:
            rule_content = rule
            
        # 处理元素隐藏规则
        if rule_content.startswith('##') or rule_content.startswith('#@#'):
            if self.validate_rule(rule) and not self.is_duplicate(rule):
                self.stats['whitelist_rules'] += 1
                return (rule, is_allow)
                
        # 处理域名规则
        if re.match(r'^(\|\|)?[a-zA-Z0-9.*_-]+\^?$', rule_content) or re.match(r'^[a-zA-Z0-9.*_-]+\^?$', rule_content):
            if not rule_content.startswith('||') and not rule_content.startswith('|'):
                rule_content = '||' + rule_content
            if not rule_content.endswith('^'):
                rule_content += '^'
                
            final_rule = f"@@{rule_content}" if is_allow else rule_content
            if self.validate_rule(final_rule) and not self.is_duplicate(final_rule):
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += 1
                return (final_rule, is_allow)
                
        # 处理包含修饰符的规则
        if '$' in rule_content:
            final_rule = f"@@{rule_content}" if is_allow else rule_content
            if self.validate_rule(final_rule) and not self.is_duplicate(final_rule):
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += 1
                return (final_rule, is_allow)
                
        # 处理纯域名
        if AdBlockConfig.SUPPORT_PLAIN_DOMAIN and self.PLAIN_DOMAIN_REGEX.match(rule_content):
            final_rule = f"@@||{rule_content}^" if is_allow else f"||{rule_content}^"
            if self.validate_rule(final_rule) and not self.is_duplicate(final_rule):
                self.stats['lenient_accepted'] += 1
                self.stats['plain_domain_converted'] += 1
                self.stats['whitelist_rules'] += 1
                return (final_rule, is_allow)
                
        return None

    def parse_rule(self, line: str, is_hosts: bool = False) -> Optional[Tuple[str, bool]]:
        """解析单行规则，返回(规则, 是否白名单) - 白名单优化"""
        if self.is_comment_or_empty(line):
            return None

        # 处理Hosts格式规则
        if is_hosts and AdBlockConfig.SUPPORT_HOSTS_CONVERT:
            hosts_rule = self.convert_hosts_rule(line)
            if hosts_rule and self.validate_rule(hosts_rule) and not self.is_duplicate(hosts_rule):
                return (hosts_rule, False)

        rule = line.strip()
        is_allow = False

        # 确定规则类型和处理方式
        if rule.startswith('@@'):
            is_allow = True
            rule_content = rule[2:]
        else:
            rule_content = rule

        # 元素隐藏规则
        if rule_content.startswith('##') or rule_content.startswith('#@#'):
            if self.validate_rule(rule) and not self.is_duplicate(rule):
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            # 宽容模式：即使验证失败也尝试保留
            if AdBlockConfig.LENIENT_PARSING:
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            return None

        # 域名规则 (支持单竖线和双竖线)
        domain_match = self.DOMAIN_RULE_REGEX.match(rule)
        if domain_match:
            if self.validate_rule(rule) and not self.is_duplicate(rule):
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            # 宽容模式：即使验证失败也尝试保留
            if AdBlockConfig.LENIENT_PARSING:
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            return None

        # 正则表达式规则
        regex_match = self.REGEX_RULE_REGEX.match(rule)
        if regex_match:
            if self.validate_rule(rule) and not self.is_duplicate(rule):
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            # 宽容模式：即使验证失败也尝试保留
            if AdBlockConfig.LENIENT_PARSING:
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            return None

        # AdGuard修饰符规则
        if '$' in rule:
            if self.validate_rule(rule) and not self.is_duplicate(rule):
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            # 宽容模式：即使验证失败也尝试保留
            if AdBlockConfig.LENIENT_PARSING:
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += is_allow
                return (rule, is_allow)
            return None

        # 纯域名规则 (自动转换为白名单)
        if AdBlockConfig.SUPPORT_PLAIN_DOMAIN and self.PLAIN_DOMAIN_REGEX.match(rule_content):
            converted_rule = f"@@||{rule_content}^" if is_allow else f"||{rule_content}^"
            self.stats['plain_domain_converted'] += 1
            if self.validate_rule(converted_rule) and not self.is_duplicate(converted_rule):
                self.stats['whitelist_rules'] += is_allow
                return (converted_rule, is_allow)
            # 宽容模式：即使验证失败也尝试保留
            if AdBlockConfig.LENIENT_PARSING:
                self.stats['lenient_accepted'] += 1
                self.stats['whitelist_rules'] += is_allow
                return (converted_rule, is_allow)
            return None

        # 宽容模式：尝试白名单专用转换方法
        if AdBlockConfig.LENIENT_PARSING:
            result = self.lenient_whitelist_conversion(line)
            if result:
                return result

        # 无法识别的规则类型
        self.stats['invalid_rules'] += 1
        return None

# ==================== 规则处理器 ====================
class AdBlockProcessor:
    """AdGuard规则处理器"""

    def __init__(self):
        self.parser = AdBlockRuleParser()
        self.block_rules: Set[str] = set()
        self.allow_rules: Set[str] = set()
        self.processed_files = 0
        self.file_stats: Dict[str, Dict[str, int]] = {}

    async def process_file(self, file_path: Path, is_hosts: bool = False) -> int:
        """处理单个文件"""
        rule_count = 0
        file_stats = {
            'total_lines': 0,
            'comments_empty': 0,
            'invalid_rules': 0,
            'duplicates': 0,
            'valid_rules': 0,
            'whitelist_rules': 0
        }

        try:
            # 尝试多种编码
            encodings = ['utf-8', 'gbk', 'latin-1', 'iso-8859-1', 'utf-8-sig']

            for encoding in encodings:
                try:
                    async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
                        async for line in f:
                            file_stats['total_lines'] += 1

                            # 限制单文件最大规则数
                            if rule_count > AdBlockConfig.MAX_RULES_PER_FILE:
                                logger.warning(f"文件 {file_path.name} 超过最大规则限制，停止处理")
                                break

                            # 检查是否为注释或空行
                            if self.parser.is_comment_or_empty(line):
                                file_stats['comments_empty'] += 1
                                continue

                            result = self.parser.parse_rule(line, is_hosts=is_hosts)
                            if result:
                                rule, is_allow = result
                                if is_allow:
                                    self.allow_rules.add(rule)
                                else:
                                    self.block_rules.add(rule)
                                rule_count += 1
                                file_stats['valid_rules'] += 1
                                if is_allow:
                                    file_stats['whitelist_rules'] += 1
                            else:
                                file_stats['invalid_rules'] += 1

                        # 如果成功读取，跳出编码循环
                        logger.debug(f"使用编码 {encoding} 成功读取文件 {file_path.name}")
                        break
                except UnicodeDecodeError:
                    if encoding == encodings[-1]:
                        logger.error(f"无法解码文件 {file_path.name}，尝试所有编码后仍失败")
                        # 宽容模式：尝试使用错误忽略模式读取
                        try:
                            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = await f.read()
                                lines = content.split('\n')
                                for line in lines:
                                    file_stats['total_lines'] += 1
                                    if self.parser.is_comment_or_empty(line):
                                        file_stats['comments_empty'] += 1
                                        continue
                                        
                                    result = self.parser.parse_rule(line, is_hosts=is_hosts)
                                    if result:
                                        rule, is_allow = result
                                        if is_allow:
                                            self.allow_rules.add(rule)
                                        else:
                                            self.block_rules.add(rule)
                                        rule_count += 1
                                        file_stats['valid_rules'] += 1
                                        if is_allow:
                                            file_stats['whitelist_rules'] += 1
                                    else:
                                        file_stats['invalid_rules'] += 1
                        except Exception as e:
                            logger.error(f"即使使用错误忽略模式也无法读取文件 {file_path.name}: {str(e)}")
                            raise
                    continue

            self.processed_files += 1
            self.file_stats[file_path.name] = file_stats

            # 记录详细统计信息
            logger.info(f"处理完成: {file_path.name} → {rule_count} 条规则 (白名单: {file_stats['whitelist_rules']})")
            if rule_count == 0:
                logger.warning(f"文件 {file_path.name} 详细统计:")
                logger.warning(f"  总行数: {file_stats['total_lines']}")
                logger.warning(f"  注释/空行: {file_stats['comments_empty']}")
                logger.warning(f"  无效规则: {file_stats['invalid_rules']}")

        except Exception as e:
            logger.error(f"处理文件 {file_path.name} 时出错: {str(e)}")
            self.file_stats[file_path.name] = {
                'total_lines': 0,
                'comments_empty': 0,
                'invalid_rules': 0,
                'duplicates': 0,
                'valid_rules': 0,
                'whitelist_rules': 0,
                'error': str(e)
            }

        return rule_count

    async def process_all_files(self) -> int:
        """处理所有匹配的文件"""
        tasks = []
        total_rules = 0

        # 创建信号量限制并发
        semaphore = asyncio.Semaphore(AdBlockConfig.MAX_CONCURRENT)

        # 处理AdBlock规则文件
        for pattern in AdBlockConfig.ADBLOCK_PATTERNS:
            for file_path in AdBlockConfig.INPUT_DIR.glob(pattern):
                if file_path.is_file():
                    if file_path.stat().st_size == 0:
                        logger.warning(f"跳过空文件: {file_path.name}")
                        continue
                    task = self.process_file_with_semaphore(file_path, False, semaphore)
                    tasks.append(task)

        # 处理白名单规则文件 - 优先处理白名单文件
        for pattern in AdBlockConfig.ALLOW_PATTERNS:
            for file_path in AdBlockConfig.INPUT_DIR.glob(pattern):
                if file_path.is_file():
                    if file_path.stat().st_size == 0:
                        logger.warning(f"跳过空文件: {file_path.name}")
                        continue
                    task = self.process_file_with_semaphore(file_path, False, semaphore)
                    tasks.append(task)

        # 处理Hosts文件
        hosts_files = list(AdBlockConfig.INPUT_DIR.glob('hosts*'))
        for hosts_file in hosts_files:
            if hosts_file.is_file():
                if hosts_file.stat().st_size == 0:
                    logger.warning(f"跳过空文件: {hosts_file.name}")
                    continue
                task = self.process_file_with_semaphore(hosts_file, True, semaphore)
                tasks.append(task)

        if not tasks:
            logger.warning("未找到任何匹配的文件")
            return 0

        # 分批处理任务以避免内存溢出
        batch_size = AdBlockConfig.MAX_CONCURRENT
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)

            for result in results:
                if isinstance(result, int):
                    total_rules += result
                elif isinstance(result, Exception):
                    logger.error(f"任务失败: {str(result)}")

        return total_rules

    async def process_file_with_semaphore(self, file_path: Path, is_hosts: bool, semaphore: asyncio.Semaphore) -> int:
        """使用信号量限制并发处理文件"""
        async with semaphore:
            return await self.process_file(file_path, is_hosts)

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """获取排序后的规则列表"""
        def rule_sort_key(r):
            if r.startswith('##'):
                return (3, r)  # 元素隐藏规则
            elif r.startswith('/') and r.endswith('/'):
                return (2, r)  # 正则表达式规则
            else:
                return (1, r)  # 域名规则

        block_sorted = sorted(self.block_rules, key=rule_sort_key)
        allow_sorted = sorted(self.allow_rules, key=rule_sort_key)

        return block_sorted, allow_sorted

    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        stats = self.parser.stats.copy()
        stats.update({
            'processed_files': self.processed_files,
            'final_block_rules': len(self.block_rules),
            'final_allow_rules': len(self.allow_rules),
            'bloom_false_positive_rate': (
                stats['bloom_false_positives'] / stats['total_processed'] * 100 
                if stats['total_processed'] > 0 else 0
            ),
            'file_stats': self.file_stats
        })
        return stats

# ==================== 文件操作 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    AdBlockConfig.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    AdBlockConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"输入目录: {AdBlockConfig.INPUT_DIR.absolute()}")
    logger.info(f"输出目录: {AdBlockConfig.OUTPUT_DIR.absolute()}")

async def write_rules(block_rules: List[str], allow_rules: List[str]):
    """写入规则到文件"""
    # 写入拦截规则
    output_block = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_BLOCK
    try:
        async with aiofiles.open(output_block, 'w', encoding='utf-8', newline='\n') as f:
            for i in range(0, len(block_rules), AdBlockConfig.BATCH_SIZE):
                batch = block_rules[i:i + AdBlockConfig.BATCH_SIZE]
                await f.write('\n'.join(batch) + '\n')

        logger.info(f"写入拦截规则: {output_block} ({len(block_rules)} 条)")
    except Exception as e:
        logger.error(f"写入拦截规则失败: {str(e)}")
        raise

    # 写入允许规则
    output_allow = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_ALLOW
    try:
        async with aiofiles.open(output_allow, 'w', encoding='utf-8', newline='\n') as f:
            for i in range(0, len(allow_rules), AdBlockConfig.BATCH_SIZE):
                batch = allow_rules[i:i + AdBlockConfig.BATCH_SIZE]
                await f.write('\n'.join(batch) + '\n')

        logger.info(f"写入允许规则: {output_allow} ({len(allow_rules)} 条)")
    except Exception as e:
        logger.error(f"写入允许规则失败: {str(e)}")
        raise

# ==================== 主函数 ====================
async def main():
    """主处理函数"""
    start_time = datetime.now()
    logger.info("AdGuard规则处理开始 - 白名单优化模式")

    ensure_directories()

    # 初始化处理器
    processor = AdBlockProcessor()

    # 处理所有文件
    total_processed = await processor.process_all_files()
    logger.info(f"文件处理完成: 共处理 {total_processed} 条规则 (去重前)")

    # 获取排序后的规则
    block_rules, allow_rules = processor.get_sorted_rules()

    # 写入输出文件
    await write_rules(block_rules, allow_rules)

    # 输出统计信息
    end_time = datetime.now()
    stats = processor.get_stats()

    logger.info(f"总耗时: {(end_time - start_time).total_seconds():.2f} 秒")
    logger.info(f"处理文件数: {stats['processed_files']}")
    logger.info(f"处理规则数: {stats['total_processed']}")
    logger.info(f"有效规则: {stats['valid_rules']}")
    logger.info(f"无效规则: {stats['invalid_rules']}")
    logger.info(f"重复规则: {stats['duplicates']}")
    logger.info(f"布隆过滤器假阳性: {stats['bloom_false_positives']} ({stats['bloom_false_positive_rate']:.6f}%)")
    logger.info(f"Hosts规则转换: {stats['hosts_converted']}")
    logger.info(f"纯域名转换: {stats['plain_domain_converted']}")
    logger.info(f"宽容模式接受: {stats['lenient_accepted']}")
    logger.info(f"白名单规则: {stats['whitelist_rules']}")
    logger.info(f"最终拦截规则: {stats['final_block_rules']}")
    logger.info(f"最终允许规则: {stats['final_allow_rules']}")

    # 输出0规则文件的详细信息
    zero_rule_files = {name: info for name, info in stats['file_stats'].items() if info.get('valid_rules', 0) == 0}
    if zero_rule_files:
        logger.warning("以下文件未提取到任何规则:")
        for name, info in zero_rule_files.items():
            if 'error' in info:
                logger.warning(f"  {name}: 错误 - {info['error']}")
            else:
                logger.warning(f"  {name}: 总行数={info['total_lines']}, 注释/空行={info['comments_empty']}, 无效规则={info['invalid_rules']}")

    logger.info("处理完成")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.error("处理被用户中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"处理过程中发生错误: {str(e)}")
        sys.exit(1)