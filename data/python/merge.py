import os
import re
import sys
import glob
import logging
import asyncio
import aiofiles
import ipaddress
from typing import List, Tuple, Optional, Dict, Any, Set
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 尝试导入必要的第三方库
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_FILTER_AVAILABLE = True
except ImportError:
    BLOOM_FILTER_AVAILABLE = False
    class ScalableBloomFilter:
        def __init__(self, initial_capacity=10000, error_rate=0.001, mode=None):
            self.set = set()
        def add(self, item):
            self.set.add(item)
        def __contains__(self, item):
            return item in self.set

# ==================== 配置区 ====================
class Config:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))

    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']

    # 输出文件名
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow_filter.txt'

    # 布隆过滤器配置
    USE_BLOOM_FILTER = True
    BLOOM_INITIAL_CAPACITY = 200000
    BLOOM_ERROR_RATE = 0.001

    # 规则优化配置
    REMOVE_BROAD_RULES = True
    BROAD_RULE_PATTERNS = [
        r'^[^/*|]+\.[^/*|]+$',
        r'^[^/*|]+\.[^/*|]+\.[^/*|]+$',
        r'^\|\|[a-zA-Z0-9.-]+\^$',
    ]

    # 异步I/O配置
    ASYNC_ENABLED = True
    ASYNC_BUFFER_SIZE = 8192
    MAX_CONCURRENT_FILES = 5

    # 日志配置
    LOG_LEVEL = logging.INFO

    # 域名验证配置
    ALLOW_LOCAL_DOMAINS = True
    ALLOW_IP_RULES = True

    # AdGuard修饰符配置
    SUPPORTED_MODIFIERS = {
        'document', 'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
        'subdocument', 'ping', 'webrtc', 'websocket', 'other', 'popup', 'third-party',
        'first-party', 'match-case', 'collapse', 'donottrack', 'generichide',
        'genericblock', 'elemhide', 'content', 'jsinject', 'urlblock', 'important',
        'badfilter', 'empty', 'mp4', 'redirect', 'redirect-rule', 'cname', 'dnsrewrite',
        'client', 'dnstype', 'app', 'domain', 'method', 'all', 'from'
    }

    # AdGuard DNS重写配置
    DNS_REWRITE_MODIFIER = re.compile(r'\$dnsrewrite=([^;]+);([^;]+);([^$]+)')

    # 正则表达式规则标识
    REGEX_RULE_PATTERN = re.compile(r'^/(.*)/$')

# ==================== 初始化日志 ====================
def setup_logging():
    """配置日志系统"""
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 分析识别区 ====================
class RuleParser:
    """增强型规则解析器，支持完整的AdGuard/AdGuard Home语法"""
    
    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+([^#\s]+)')
    COMMENT_REGEX = re.compile(r'^\s*[!#]|\[Adblock')
    DOMAIN_REGEX = re.compile(r'^(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(\||@@\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    ELEMENT_HIDING_REGEX = re.compile(r'^##')
    HOSTS_IPV6_REGEX = re.compile(r'^([0-9a-fA-F:]+)\s+([^#\s]+)')
    ADGUARD_MODIFIER_SPLIT = re.compile(r'\$(.+)$')
    NETWORK_RULE_REGEX = re.compile(r'^(\|\|)?[a-zA-Z0-9.-]+[\^\\/*]?')
    ADGUARD_DNSREWRITE_REGEX = re.compile(r'^.+\$dnsrewrite=.+')
    ADGUARD_CLIENT_MODIFIER = re.compile(r'\$client=([^\s,]+)')
    ADGUARD_DOMAIN_MODIFIER = re.compile(r'\$domain=([^\s]+)')
    ADGUARD_DNSTYPE_MODIFIER = re.compile(r'\$dnstype=([^\s]+)')

    def __init__(self):
        if Config.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            self.filter = ScalableBloomFilter(
                initial_capacity=Config.BLOOM_INITIAL_CAPACITY,
                error_rate=Config.BLOOM_ERROR_RATE
            )
            logger.info(f"使用布隆过滤器 (初始容量: {Config.BLOOM_INITIAL_CAPACITY}, 误判率: {Config.BLOOM_ERROR_RATE})")
        else:
            self.filter = set()
            logger.info("使用简单集合进行去重")

        self.rule_stats = {
            'total_processed': 0,
            'valid_rules': 0,
            'invalid_rules': 0,
            'duplicate_rules': 0,
            'hosts_rules': 0,
            'domain_rules': 0,
            'ip_rules': 0,
            'element_hiding_rules': 0,
            'adguard_rules': 0,
            'adguard_modifier_rules': 0,
            'adguard_dnsrewrite_rules': 0,
            'regex_rules': 0,
            'client_specific_rules': 0,
            'domain_specific_rules': 0
        }

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复"""
        normalized = self.normalize_rule(rule)

        if Config.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            if normalized in self.filter:
                self.rule_stats['duplicate_rules'] += 1
                return True
            self.filter.add(normalized)
            return False
        else:
            if normalized in self.filter:
                self.rule_stats['duplicate_rules'] += 1
                return True
            self.filter.add(normalized)
            return False

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        self.rule_stats['total_processed'] += 1

        # 检查规则长度
        if len(rule) > 5000:
            logger.debug(f"跳过过长规则: {rule[:50]}...")
            self.rule_stats['invalid_rules'] += 1
            return False

        # 检查过于宽泛的规则
        if self.is_broad_rule(rule):
            logger.debug(f"跳过过于宽泛的规则: {rule}")
            self.rule_stats['invalid_rules'] += 1
            return False

        # 检查AdGuard修饰符有效性
        if not self.validate_adguard_modifiers(rule):
            logger.debug(f"跳过包含无效修饰符的规则: {rule}")
            self.rule_stats['invalid_rules'] += 1
            return False

        # 基本验证
        if rule.strip() and not rule.strip().startswith(('!', '[', '#')):
            self.rule_stats['valid_rules'] += 1
            return True

        self.rule_stats['invalid_rules'] += 1
        return False

    def validate_adguard_modifiers(self, rule: str) -> bool:
        """验证AdGuard修饰符有效性"""
        if '$' not in rule:
            return True
            
        # 提取修饰符部分
        modifier_match = self.ADGUARD_MODIFIER_SPLIT.search(rule)
        if not modifier_match:
            return False
            
        modifiers_str = modifier_match.group(1)
        modifiers = [mod.strip() for mod in modifiers_str.split(',')]
        
        # 检查每个修饰符
        for modifier in modifiers:
            # 处理带值的修饰符 (如 client=127.0.0.1)
            if '=' in modifier:
                mod_name, mod_value = modifier.split('=', 1)
                if mod_name not in Config.SUPPORTED_MODIFIERS:
                    return False
            else:
                if modifier not in Config.SUPPORTED_MODIFIERS:
                    return False
                    
        return True

    def is_broad_rule(self, rule: str) -> bool:
        """检查是否是过于宽泛的规则"""
        if not Config.REMOVE_BROAD_RULES:
            return False

        for pattern in Config.BROAD_RULE_PATTERNS:
            if re.match(pattern, rule):
                return True
        return False

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        """解析hosts规则"""
        match = self.HOSTS_REGEX.search(line)
        if match:
            domain = match.group(1)
            if self.is_valid_domain(domain):
                self.rule_stats['hosts_rules'] += 1
                return f"||{domain}^"
        return None

    def parse_ipv6_hosts_rule(self, line: str) -> Optional[str]:
        """解析IPv6 hosts规则"""
        match = self.HOSTS_IPV6_REGEX.search(line)
        if match:
            domain = match.group(2)
            if self.is_valid_domain(domain):
                self.rule_stats['hosts_rules'] += 1
                return f"||{domain}^"
        return None

    def parse_domain_rule(self, line: str) -> Optional[str]:
        """解析域名规则"""
        match = self.DOMAIN_REGEX.search(line)
        if match:
            domain = match.group(1)
            if self.is_valid_domain(domain):
                self.rule_stats['domain_rules'] += 1
                return line
        return None

    def parse_ip_rule(self, line: str) -> Optional[str]:
        """解析IP/CIDR规则"""
        match = self.IP_CIDR_REGEX.search(line)
        if match:
            prefix, ip_cidr = match.groups()
            try:
                ipaddress.ip_network(ip_cidr, strict=False)
                self.rule_stats['ip_rules'] += 1
                return line
            except:
                pass
        return None

    def is_element_hiding_rule(self, rule: str) -> bool:
        """检查是否是元素隐藏规则"""
        if self.ELEMENT_HIDING_REGEX.match(rule):
            self.rule_stats['element_hiding_rules'] += 1
            return True
        return False

    def is_adguard_rule(self, rule: str) -> bool:
        """检查是否是AdGuard规则"""
        if '$' in rule:
            self.rule_stats['adguard_rules'] += 1
            return True
        return False

    def is_regex_rule(self, rule: str) -> bool:
        """检查是否是正则表达式规则"""
        if rule.startswith('/') and rule.endswith('/'):
            self.rule_stats['regex_rules'] += 1
            return True
        return False

    def is_dnsrewrite_rule(self, rule: str) -> bool:
        """检查是否是DNS重写规则"""
        if self.ADGUARD_DNSREWRITE_REGEX.search(rule):
            self.rule_stats['adguard_dnsrewrite_rules'] += 1
            return True
        return False

    def has_client_modifier(self, rule: str) -> bool:
        """检查是否包含客户端修饰符"""
        if self.ADGUARD_CLIENT_MODIFIER.search(rule):
            self.rule_stats['client_specific_rules'] += 1
            return True
        return False

    def has_domain_modifier(self, rule: str) -> bool:
        """检查是否包含域名修饰符"""
        if self.ADGUARD_DOMAIN_MODIFIER.search(rule):
            self.rule_stats['domain_specific_rules'] += 1
            return True
        return False

    def normalize_rule(self, rule: str) -> str:
        """标准化规则格式以提高去重效率"""
        normalized = rule.strip().lower()
        
        # 移除多余通配符（但保持AdGuard语法结构）
        if normalized.startswith('||') and normalized.endswith('^'):
            domain = normalized[2:-1]
            if self.is_valid_domain(domain):
                return f"||{domain}^"
        
        # 处理通用模式
        if '*' in normalized:
            normalized = re.sub(r'\*+', '*', normalized)
        
        return normalized

    def is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or len(domain) > 253:
            return False
        
        if re.match(r'^([a-z0-9](-*[a-z0-9])*\.)+[a-z]{2,}$', domain):
            return True
            
        if Config.ALLOW_LOCAL_DOMAINS and re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', domain):
            return True
            
        return False

    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        """分类规则并返回处理后的规则和是否是允许规则"""
        original_line = line.strip()
        is_allow = original_line.startswith('@@')

        # 1. 检查注释和空行
        if self.is_comment_or_empty(original_line):
            return None, False

        # 2. 特殊处理AdGuard DNS重写规则
        if self.is_dnsrewrite_rule(original_line):
            return original_line, is_allow

        # 3. 特殊处理客户端特定规则
        if self.has_client_modifier(original_line):
            return original_line, is_allow

        # 4. 特殊处理域名特定规则
        if self.has_domain_modifier(original_line):
            return original_line, is_allow

        # 5. 特殊处理正则表达式规则
        if self.is_regex_rule(original_line):
            return original_line, is_allow

        # 6. 特殊处理AdGuard规则（带修饰符）
        if self.is_adguard_rule(original_line):
            return original_line, is_allow

        # 7. 特殊处理元素隐藏规则
        if self.is_element_hiding_rule(original_line):
            return original_line, is_allow

        # 8. 尝试解析为各种规则类型
        rule = None

        # 8.1 检查是否是hosts规则
        rule = self.parse_hosts_rule(original_line)
        if rule:
            return rule, is_allow

        # 8.2 检查是否是IPv6 hosts规则
        rule = self.parse_ipv6_hosts_rule(original_line)
        if rule:
            return rule, is_allow

        # 8.3 检查是否是域名规则
        rule = self.parse_domain_rule(original_line)
        if rule:
            return rule, is_allow

        # 8.4 检查是否是IP/CIDR规则
        if Config.ALLOW_IP_RULES:
            rule = self.parse_ip_rule(original_line)
            if rule:
                return rule, is_allow

        # 9. 如果所有解析都失败，保留原始规则
        if any(char in original_line for char in ['^', '*', '|', '/', '$']):
            return original_line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class RuleMerger:
    """规则合并器"""

    def __init__(self):
        self.parser = RuleParser()
        self.block_rules = set()
        self.allow_rules = set()
        self.rule_signatures = set()

    def add_rule_memory_efficient(self, rule: str, is_allow: bool):
        """内存高效地添加规则"""
        rule_hash = self.get_rule_signature(rule)
        
        if rule_hash in self.rule_signatures:
            self.parser.rule_stats['duplicate_rules'] += 1
            return False
            
        self.rule_signatures.add(rule_hash)
        
        if is_allow:
            self.allow_rules.add(rule)
        else:
            self.block_rules.add(rule)
            
        return True
    
    def get_rule_signature(self, rule: str) -> str:
        """生成规则签名用于快速去重"""
        normalized = self.parser.normalize_rule(rule)
        
        if len(normalized) <= 50:
            return normalized
        else:
            import hashlib
            return hashlib.md5(normalized.encode()).hexdigest()

    def batch_process_rules(self, rules: List[str], is_allow: bool = False):
        """批量处理规则以减少内存操作"""
        batch_size = 1000
        processed = 0
        
        for i in range(0, len(rules), batch_size):
            batch = rules[i:i+batch_size]
            
            for rule in batch:
                classified_rule, rule_is_allow = self.parser.classify_rule(rule)
                if classified_rule and self.parser.validate_rule(classified_rule):
                    final_is_allow = is_allow or rule_is_allow
                    self.add_rule_memory_efficient(classified_rule, final_is_allow)
                    processed += 1
                    
            if i % (batch_size * 10) == 0:
                import gc
                gc.collect()
                
        return processed

    async def process_file_async(self, file_path: Path, is_allow: bool = False):
        """异步处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        final_is_allow = is_allow or rule_is_allow
                        self.add_rule_memory_efficient(rule, final_is_allow)
                        count += 1

        except UnicodeDecodeError:
            try:
                async with aiofiles.open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    async for line in f:
                        rule, rule_is_allow = self.parser.classify_rule(line)
                        if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                            final_is_allow = is_allow or rule_is_allow
                            self.add_rule_memory_efficient(rule, final_is_allow)
                            count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except FileNotFoundError:
            logger.error(f"文件不存在: {file_path}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")

        logger.info(f"从 {file_path} 添加了 {count} 条规则")
        return count

    def process_file_sync(self, file_path: Path, is_allow: bool = False):
        """同步处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        final_is_allow = is_allow or rule_is_allow
                        self.add_rule_memory_efficient(rule, final_is_allow)
                        count += 1

        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    for line in f:
                        rule, rule_is_allow = self.parser.classify_rule(line)
                        if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                            final_is_allow = is_allow or rule_is_allow
                            self.add_rule_memory_efficient(rule, final_is_allow)
                            count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except FileNotFoundError:
            logger.error(f"文件不存在: {file_path}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")

        logger.info(f"从 {file_path} 添加了 {count} 条规则")
        return count

    async def process_files_async(self, patterns: List[str], is_allow: bool = False):
        """异步处理一组文件"""
        tasks = []
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                tasks.append(self.process_file_async(Path(file_path), is_allow))

        semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_FILES)

        async def limited_task(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(task) for task in tasks], return_exceptions=True)

        total_count = 0
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"文件处理任务出错: {result}")
            else:
                total_count += result

        return total_count

    def process_files_sync(self, patterns: List[str], is_allow: bool = False):
        """同步处理一组文件"""
        total_count = 0
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                total_count += self.process_file_sync(Path(file_path), is_allow)
        return total_count

    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从规则中提取域名部分"""
        if rule.startswith('@@||') and rule.endswith('^'):
            return rule[4:-1]
        elif rule.startswith('||') and rule.endswith('^'):
            return rule[2:-1]
        elif re.match(r'^[a-zA-Z0-9.-]+$', rule):
            return rule
        return None

    def advanced_conflict_resolution(self):
        """高级冲突解决机制"""
        allow_patterns = set()
        for allow_rule in self.allow_rules:
            domain = self.extract_domain_from_rule(allow_rule)
            if domain:
                allow_patterns.add(domain)
        
        rules_to_remove = set()
        for block_rule in self.block_rules:
            domain = self.extract_domain_from_rule(block_rule)
            if domain and domain in allow_patterns:
                rules_to_remove.add(block_rule)
                
        for allow_rule in self.allow_rules:
            if allow_rule.startswith('@@||*.'):
                base_domain = allow_rule[5:-1]
                for block_rule in list(self.block_rules):
                    if block_rule.startswith('||') and block_rule.endswith('^'):
                        block_domain = block_rule[2:-1]
                        if block_domain.endswith('.' + base_domain):
                            rules_to_remove.add(block_rule)
        
        before = len(self.block_rules)
        self.block_rules -= rules_to_remove
        after = len(self.block_rules)
        
        logger.info(f"高级冲突解决: 移除了 {before - after} 条冲突规则")

    def select_most_specific_rule(self, rules: List[str]) -> str:
        """选择最具体的规则"""
        for rule in rules:
            if '$' in rule:
                return rule
        
        def wildcard_count(rule):
            return rule.count('*')
        
        return min(rules, key=wildcard_count)

    def optimize_rules(self):
        """优化规则集，移除冗余规则"""
        domain_rules = defaultdict(list)
        for rule in self.block_rules:
            domain = self.extract_domain_from_rule(rule)
            if domain:
                domain_rules[domain].append(rule)
        
        optimized_rules = set()
        for domain, rules in domain_rules.items():
            if len(rules) == 1:
                optimized_rules.add(rules[0])
            else:
                most_specific = self.select_most_specific_rule(rules)
                optimized_rules.add(most_specific)
        
        removed = len(self.block_rules) - len(optimized_rules)
        self.block_rules = optimized_rules
        
        if removed > 0:
            logger.info(f"规则优化: 移除了 {removed} 条冗余规则")

    def remove_conflicts(self):
        """移除冲突规则（允许规则优先）"""
        self.advanced_conflict_resolution()
        self.optimize_rules()

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """获取排序后的规则列表"""
        def rule_key(rule):
            if rule.startswith('||'):
                return (0, rule)
            elif rule.startswith('@@'):
                return (1, rule)
            elif rule.startswith('/') and rule.endswith('/'):
                return (2, rule)
            else:
                return (3, rule)

        block_list = sorted(self.block_rules, key=rule_key)
        allow_list = sorted(self.allow_rules, key=rule_key)

        return block_list, allow_list

    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        stats = self.parser.rule_stats.copy()
        stats.update({
            'block_rules': len(self.block_rules),
            'allow_rules': len(self.allow_rules)
        })
        return stats

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def write_rules_async(block_rules: List[str], allow_rules: List[str]):
    """异步将规则写入文件"""
    try:
        async with aiofiles.open(Config.OUTPUT_DIR / Config.OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f:
            for rule in block_rules:
                await f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入拦截规则文件时出错: {e}")
        return

    try:
        async with aiofiles.open(Config.OUTPUT_DIR / Config.OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f:
            for rule in allow_rules:
                await f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入允许规则文件时出错: {e}")
        return

    logger.info(f"写入 {len(block_rules)} 条拦截规则到 {Config.OUTPUT_BLOCK}")
    logger.info(f"写入 {len(allow_rules)} 条允许规则到 {Config.OUTPUT_ALLOW}")

def write_rules_sync(block_rules: List[str], allow_rules: List[str]):
    """同步将规则写入文件"""
    try:
        with open(Config.OUTPUT_DIR / Config.OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f:
            for rule in block_rules:
                f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入拦截规则文件时出错: {e}")
        return

    try:
        with open(Config.OUTPUT_DIR / Config.OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f:
            for rule in allow_rules:
                f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入允许规则文件时出错: {e}")
        return

    logger.info(f"写入 {len(block_rules)} 条拦截规则到 {Config.OUTPUT_BLOCK}")
    logger.info(f"写入 {len(allow_rules)} 条允许规则到 {Config.OUTPUT_ALLOW}")

# ==================== 主程序 ====================
async def main_async():
    """异步主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    ensure_directories()

    merger = RuleMerger()

    logger.info("开始处理广告拦截规则")
    if Config.ASYNC_ENABLED:
        await merger.process_files_async(Config.ADBLOCK_PATTERNS, is_allow=False)
    else:
        merger.process_files_sync(Config.ADBLOCK_PATTERNS, is_allow=False)

    logger.info("开始处理允许规则")
    if Config.ASYNC_ENABLED:
        await merger.process_files_async(Config.ALLOW_PATTERNS, is_allow=True)
    else:
        merger.process_files_sync(Config.ALLOW_PATTERNS, is_allow=True)

    merger.remove_conflicts()

    block_rules, allow_rules = merger.get_sorted_rules()

    if Config.ASYNC_ENABLED:
        await write_rules_async(block_rules, allow_rules)
    else:
        write_rules_sync(block_rules, allow_rules)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = merger.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")

    logger.info(f"规则类型: {stats['hosts_rules']} 条hosts规则, {stats['domain_rules']} 条域名规则, {stats['ip_rules']} 条IP规则, {stats['element_hiding_rules']} 条元素隐藏规则, {stats['adguard_rules']} 条AdGuard规则, {stats.get('adguard_modifier_rules', 0)} 条带修饰符的AdGuard规则, {stats.get('adguard_dnsrewrite_rules', 0)} 条DNS重写规则, {stats.get('regex_rules', 0)} 条正则表达式规则, {stats.get('client_specific_rules', 0)} 条客户端特定规则, {stats.get('domain_specific_rules', 0)} 条域名特定规则")

def main_sync():
    """同步主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    ensure_directories()

    merger = RuleMerger()

    logger.info("开始处理广告拦截规则")
    merger.process_files_sync(Config.ADBLOCK_PATTERNS, is_allow=False)

    logger.info("开始处理允许规则")
    merger.process_files_sync(Config.ALLOW_PATTERNS, is_allow=True)

    merger.remove_conflicts()

    block_rules, allow_rules = merger.get_sorted_rules()

    write_rules_sync(block_rules, allow_rules)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = merger.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")

    logger.info(f"规则类型: {stats['hosts_rules']} 条hosts规则, {stats['domain_rules']} 条域名规则, {stats['ip_rules']} 条IP规则, {stats['element_hiding_rules']} 条元素隐藏规则, {stats['adguard_rules']} 条AdGuard规则, {stats.get('adguard_modifier_rules', 0)} 条带修饰符的AdGuard规则, {stats.get('adguard_dnsrewrite_rules', 0)} 条DNS重写规则, {stats.get('regex_rules', 0)} 条正则表达式规则, {stats.get('client_specific_rules', 0)} 条客户端特定规则, {stats.get('domain_specific_rules', 0)} 条域名特定规则")

if __name__ == '__main__':
    if Config.ASYNC_ENABLED:
        asyncio.run(main_async())
    else:
        main_sync()
