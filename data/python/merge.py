#!/usr/bin/env python3
"""
优化版广告规则合并去重脚本
支持AdBlock语法、AdGuard语法和hosts语法
"""

import os
import re
import glob
import logging
from typing import Set, List, Tuple, Optional
from pathlib import Path
from pybloom_live import BloomFilter  # 更高效的布隆过滤器实现
from adblockparser import AdblockRule
from IPy import IP

# ==================== 配置区 ====================
class Config:
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow.txt'
    
    BLOOM_CAPACITY = 300000
    BLOOM_ERROR_RATE = 0.005
    
    LRU_CACHE_SIZE = 10000
    LOG_LEVEL = logging.INFO

# ==================== 初始化日志 ====================
def setup_logging():
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 分析识别区 ====================
class EnhancedRuleParser:
    HOSTS_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+([^#\s]+)')
    HOSTS_IPV6_REGEX = re.compile(r'^(?:[0-9a-fA-F:]+)\s+([^#\s]+)')
    COMMENT_REGEX = re.compile(r'^\s*[!#]|\[Adblock')
    DOMAIN_REGEX = re.compile(r'^(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(\||@@\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    MODIFIER_REGEX = re.compile(r'^(.*?)\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')

    def __init__(self):
        self.bloom_filter = BloomFilter(
            capacity=Config.BLOOM_CAPACITY,
            error_rate=Config.BLOOM_ERROR_RATE
        )
        self.exact_seen_rules = set()
        self.lru_cache = {}

    def is_comment_or_empty(self, line: str) -> bool:
        return not line.strip() or self.COMMENT_REGEX.match(line.strip())

    def normalize_rule(self, rule: str) -> str:
        return rule.strip().lower()

    def is_duplicate(self, rule: str) -> bool:
        normalized = self.normalize_rule(rule)
        
        if normalized in self.lru_cache:
            return True
        
        if normalized in self.bloom_filter:
            if normalized in self.exact_seen_rules:
                return True
            self.exact_seen_rules.add(normalized)
            self._update_lru_cache(normalized)
            return False
        
        self.bloom_filter.add(normalized)
        self.exact_seen_rules.add(normalized)
        self._update_lru_cache(normalized)
        return False

    def _update_lru_cache(self, rule: str):
        if len(self.lru_cache) >= Config.LRU_CACHE_SIZE:
            next(iter(self.lru_cache))  # 自动淘汰最久未使用项
        self.lru_cache[rule] = True

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        match = self.HOSTS_REGEX.search(line) or self.HOSTS_IPV6_REGEX.search(line)
        return f"||{match.group(1)}^" if match else None

    def parse_modifier_rule(self, line: str) -> Optional[Tuple[str, bool]]:
        match = self.MODIFIER_REGEX.search(line)
        if match and any(m in match.group(2) for m in ['client=', 'dnstype=']):
            return line, line.startswith('@@')
        return None

    def parse_regex_rule(self, line: str) -> Optional[str]:
        return line if line.startswith('/') and line.endswith('/') else None

    def parse_domain_rule(self, line: str) -> Optional[str]:
        match = self.DOMAIN_REGEX.search(line)
        return line if match and '.' in match.group(1) else None

    def parse_ip_rule(self, line: str) -> Optional[str]:
        match = self.IP_CIDR_REGEX.search(line)
        return line if match and self._validate_ip(match.group(2)) else None

    def _validate_ip(self, ip_cidr: str) -> bool:
        try:
            IP(ip_cidr)
            return True
        except:
            return False

    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        line = line.strip()
        is_allow = line.startswith('@@')

        if self.is_comment_or_empty(line):
            return None, False

        for parser in [
            self.parse_regex_rule,
            self.parse_modifier_rule,
            self.parse_hosts_rule,
            self.parse_domain_rule,
            self.parse_ip_rule
        ]:
            result = parser(line)
            if result:
                if isinstance(result, tuple):
                    return result
                return result, is_allow

        try:
            if AdblockRule(line).is_filtering_rule:
                return line, is_allow
        except:
            pass

        if any(c in line for c in ['^', '*', '|', '/', '$']):
            return line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class EnhancedRuleMerger:
    def __init__(self):
        self.parser = EnhancedRuleParser()
        self.block_rules = set()
        self.allow_rules = set()

    def process_file(self, file_path: Path):
        logger.info(f"Processing file: {file_path}")
        count = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    rule, is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule):
                        (self.allow_rules if is_allow else self.block_rules).add(rule)
                        count += 1
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
        logger.info(f"Added {count} rules from {file_path}")

    def process_files(self, patterns: List[str], is_allow: bool = False):
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                self.process_file(Path(file_path))

    def remove_conflicts(self):
        before = len(self.block_rules)
        self.block_rules -= self.allow_rules
        logger.info(f"Removed {before - len(self.block_rules)} conflicting rules")

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        def rule_key(rule):
            if rule.startswith('||'):
                return (0, rule)
            elif rule.startswith('@@'):
                return (1, rule)
            elif rule.startswith('/') and rule.endswith('/'):
                return (2, rule)
            else:
                return (3, rule)

        return (
            sorted(self.block_rules, key=rule_key),
            sorted(self.allow_rules, key=rule_key)
        )

# ==================== 输入输出区 ====================
def ensure_directories():
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def read_existing_rules() -> Tuple[Set[str], Set[str]]:
    block_rules = set()
    allow_rules = set()
    parser = EnhancedRuleParser()

    for file_path in [Config.OUTPUT_DIR / Config.OUTPUT_BLOCK,
                      Config.OUTPUT_DIR / Config.OUTPUT_ALLOW]:
        if file_path.exists():
            is_allow = file_path.name == Config.OUTPUT_ALLOW
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        rule, _ = parser.classify_rule(line)
                        if rule:
                            (allow_rules if is_allow else block_rules).add(rule)
                            parser.is_duplicate(rule)
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
    return block_rules, allow_rules

def write_rules(block_rules: List[str], allow_rules: List[str]):
    def write_file(rules: List[str], filename: str):
        try:
            with open(Config.OUTPUT_DIR / filename, 'w', encoding='utf-8', newline='\n') as f:
                for rule in rules:
                    f.write(f"{rule}\n")
            logger.info(f"Wrote {len(rules)} rules to {filename}")
        except Exception as e:
            logger.error(f"Error writing to {filename}: {e}")

    write_file(block_rules, Config.OUTPUT_BLOCK)
    write_file(allow_rules, Config.OUTPUT_ALLOW)

# ==================== 主程序 ====================
def main():
    logger.info("Starting rule processing")
    start_time = datetime.now()

    ensure_directories()
    merger = EnhancedRuleMerger()
    
    existing_block, existing_allow = read_existing_rules()
    merger.block_rules.update(existing_block)
    merger.allow_rules.update(existing_allow)
    logger.info(f"Loaded {len(existing_block)} existing block rules and {len(existing_allow)} allow rules")

    merger.process_files(Config.ADBLOCK_PATTERNS)
    merger.process_files(Config.ALLOW_PATTERNS, is_allow=True)
    
    merger.remove_conflicts()
    block_rules, allow_rules = merger.get_sorted_rules()
    
    write_rules(block_rules, allow_rules)
    
    duration = datetime.now() - start_time
    logger.info(f"Processing completed in {duration}")
    logger.info(f"Total rules: {len(block_rules)} block, {len(allow_rules)} allow")

if __name__ == '__main__':
    main()
