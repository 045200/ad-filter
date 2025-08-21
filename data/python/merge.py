#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import xxhash
import chardet
import logging
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import List, Generator, Optional
from enum import Enum, auto
from concurrent.futures import ProcessPoolExecutor, as_completed

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_merge.txt"

MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
CHUNK_SIZE = 10000
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*", "adg*.txt", "adh*.txt", "filter*.txt"]
HASH_SALT = "adblock_salt_2024_v5"

# 规则类型枚举
class RuleType(Enum):
    IP_RULE = auto()
    SCRIPT_RULE = auto()
    CSS_RULE = auto()
    OPTION_RULE = auto()
    STANDARD_RULE = auto()
    HOSTS_RULE = auto()
    EXCEPTION_RULE = auto()
    DNS_REWRITE_RULE = auto()
    UNKNOWN = auto()

# 预编译正则表达式
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
HOSTS_LINE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
ADH_IP_RULE = re.compile(r'^(IP-CIDR|IP-CIDR6):[^,]+,[A-Za-z]+$', re.IGNORECASE)
ADG_DNSREWRITE = re.compile(r'^\|\|.*\$dnsrewrite=')
ADG_SCRIPTLET = re.compile(r'(##\+js\(|#%#//scriptlet\()')
ADG_CSS = re.compile(r'^##|^#@#')
ADG_MODIFIER = re.compile(r'^.*\$[a-zA-Z0-9_]+(=[^,]+)?(,[a-zA-Z0-9_]+(=[^,]+)?)*$')
ADG_NETWORK = re.compile(r'^\|\|.*\^')
ADG_COSMETIC = re.compile(r'^##.*')
ADB_EXCEPTION = re.compile(r'^@@')

class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.input_files = []
        self.file_hashes = set()
        self.unique_rules = OrderedDict()
        self.stats = defaultdict(int)
        self.rule_counters = defaultdict(int)

    def run(self):
        """主运行方法"""
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            logger.warning("未找到有效规则文件")
            return

        logger.info(f"发现规则文件: {len(self.input_files)}个")
        self._process_files_parallel()

        elapsed = time.time() - start_time
        logger.info(f"合并完成 | 处理文件: {len(self.input_files)} | 去重后规则数: {len(self.unique_rules)} | 耗时: {elapsed:.2f}s")
        
        self._write_output()

    def _discover_input_files(self):
        """发现输入文件"""
        for pattern in INPUT_PATTERNS:
            for file_path in TEMP_DIR.glob(pattern):
                if file_path == OUTPUT_FILE or not file_path.is_file():
                    continue

                file_hash = self._calculate_file_hash(file_path)
                if file_hash in self.file_hashes:
                    continue

                self.file_hashes.add(file_hash)
                self.input_files.append(file_path)

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值"""
        try:
            hasher = xxhash.xxh64()
            with open(file_path, 'rb') as f:
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
            return hasher.hexdigest()
        except Exception:
            return str(file_path)

    def _process_files_parallel(self):
        """并行处理文件"""
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(self._process_file, fp): fp for fp in self.input_files}

            for future in as_completed(future_to_file):
                try:
                    file_rules = future.result()
                    for rule_info in file_rules:
                        self._add_rule(rule_info)
                except Exception as e:
                    logger.error(f"处理文件时出错: {e}")

    def _process_file(self, file_path: Path) -> List[str]:
        """处理单个文件"""
        rules = []
        encoding = detect_encoding(file_path)
        
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or COMMENT.match(line) or EMPTY_LINE.match(line):
                        continue
                    
                    rule = self._parse_line(line)
                    if rule:
                        rules.append(rule)
        except Exception as e:
            logger.error(f"读取文件 {file_path} 时出错: {e}")
            
        return rules

    def _parse_line(self, line: str) -> Optional[str]:
        """解析单行规则"""
        # 移除行内注释
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        if '!' in line:
            line = line.split('!', 1)[0].strip()
        if not line:
            return None
            
        # 分类并标准化规则
        if ADB_EXCEPTION.match(line):
            return self._normalize_exception_rule(line)
        elif ADH_IP_RULE.match(line):
            return self._normalize_ip_rule(line)
        elif ADG_DNSREWRITE.search(line):
            return self._normalize_dns_rewrite_rule(line)
        elif ADG_SCRIPTLET.search(line):
            return self._normalize_script_rule(line)
        elif ADG_CSS.match(line):
            return self._normalize_css_rule(line)
        elif ADG_COSMETIC.match(line):
            return self._normalize_cosmetic_rule(line)
        elif ADG_MODIFIER.match(line) and '$' in line:
            return self._normalize_option_rule(line)
        elif ADG_NETWORK.match(line):
            return self._normalize_network_rule(line)
        elif HOSTS_LINE.match(line):
            return self._normalize_hosts_rule(line)
        else:
            return self._normalize_standard_rule(line)

    def _normalize_domain_part(self, domain_part: str) -> str:
        """标准化域名部分"""
        domain = domain_part.strip()
        if not domain:
            return ""
            
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^\*\.', '||', domain)
        domain = re.sub(r'\|$', '^', domain)
        
        if domain.startswith('|') and not domain.startswith('||'):
            domain = f"|{domain}"
            
        domain = re.sub(r'\*+', '*', domain)
        return domain

    def _add_rule(self, rule: str):
        """添加规则到唯一集合"""
        rule_hash = xxhash.xxh3_64(rule + HASH_SALT).intdigest()
        
        if rule_hash not in self.unique_rules:
            self.unique_rules[rule_hash] = rule
            # 更新统计
            rule_type = self._classify_rule(rule)
            self.rule_counters[rule_type] += 1

    def _classify_rule(self, rule: str) -> str:
        """分类规则"""
        if rule.startswith('@@'):
            return "exception_rules"
        elif rule.startswith(('IP-CIDR', 'IP-CIDR6')):
            return "ip_rules"
        elif '$dnsrewrite=' in rule:
            return "dns_rewrite_rules"
        elif '##+js(' in rule or '#%#//scriptlet(' in rule:
            return "script_rules"
        elif rule.startswith('##') or rule.startswith('#@#'):
            return "cosmetic_rules"
        elif '$' in rule:
            return "option_rules"
        elif rule.startswith('||'):
            return "network_rules"
        else:
            return "standard_rules"

    def _write_output(self):
        """写入输出文件"""
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('! 合并广告过滤规则\n')
            f.write('! 生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            f.write('! 规则总数: ' + str(len(self.unique_rules)) + '\n')
            
            for rule_type, count in self.rule_counters.items():
                f.write(f'! {rule_type}: {count}\n')
            
            f.write('!\n')
            
            for rule in self.unique_rules.values():
                f.write(rule + '\n')
                
        logger.info(f"已写入合并规则: {OUTPUT_FILE}")

def detect_encoding(file_path: Path) -> str:
    """检测文件编码"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            return result['encoding'] or 'utf-8'
    except Exception:
        return 'utf-8'

if __name__ == '__main__':
    try:
        AdblockMerger().run()
        sys.exit(0)
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)