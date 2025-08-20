#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Generator, Set


# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"

MAX_WORKERS = 4
CHUNK_SIZE = 10000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*"]

DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

MAX_RULES_IN_MEMORY = 2000000
HASH_SALT = "adblock_salt_2024"


# 预编译正则
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# AdBlock规则识别
ADBLOCK_RULE = re.compile(r'^(?P<exception>@@)?\|{1,2}(?P<domain>[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?P<separator>[\^\/\|\$]?)(?P<options>.*)?$', re.IGNORECASE)

# hosts格式支持
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+(?P<domain>[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', re.IGNORECASE)


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            chunk = []
            for line in f:
                chunk.append(line.strip())
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk
    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")


class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()

    def run(self):
        """主运行方法"""
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            print("未找到有效规则文件")
            return

        rules = self._process_files_parallel()
        self._write_output(rules)

        elapsed = time.time() - start_time
        print(f"合并完成 | 最终规则数: {len(rules)} | 耗时: {elapsed:.2f}s")

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
        
        print(f"发现规则文件: {len(self.input_files)}个")

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
            return hasher.hexdigest()
        except Exception:
            return str(file_path)

    def _process_files_parallel(self) -> List[str]:
        """并行处理文件"""
        rules = []
        rule_hashes = set()

        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(self._process_file, fp): fp for fp in self.input_files}

            for future in as_completed(future_to_file):
                try:
                    file_rules = future.result()
                    for rule in file_rules:
                        rule_hash = self._rule_hash(rule)
                        if rule_hash not in rule_hashes:
                            rules.append(rule)
                            rule_hashes.add(rule_hash)
                except Exception as e:
                    print(f"处理文件时出错: {e}")

        return rules

    def _process_file(self, file_path: Path) -> List[str]:
        """处理单个文件"""
        rules = []

        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                    continue
                    
                if not (self.len_min <= len(line) <= self.len_max):
                    continue
                    
                rule = self._process_line(line)
                if rule:
                    rules.append(rule)
                    
        return rules

    def _process_line(self, line: str) -> str:
        """处理单行规则"""
        # 尝试AdBlock格式
        adblock_match = ADBLOCK_RULE.match(line)
        if adblock_match:
            domain = adblock_match.group("domain")
            if self._is_valid_domain(domain):
                exception = adblock_match.group("exception") or ""
                separator = adblock_match.group("separator") or "^"
                return f"{exception}||{domain}{separator}"
            
        # 尝试hosts格式
        hosts_match = HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group("domain")
            if self._is_valid_domain(domain):
                return f"||{domain}^"
            
        return ""

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False
        
        if IP_ADDRESS.match(domain):
            return False
        
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False
        
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', label, re.IGNORECASE):
                return False
        
        return True

    def _rule_hash(self, rule: str) -> str:
        """生成规则哈希值"""
        # 标准化规则：域名部分小写，去除多余字符
        if rule.startswith('@@||') or rule.startswith('||'):
            parts = rule.split('^', 1)
            normalized = parts[0].lower() + ('^' + parts[1] if len(parts) > 1 else '^')
            return hashlib.sha256((normalized + HASH_SALT).encode('utf-8')).hexdigest()
        return hashlib.sha256((rule + HASH_SALT).encode('utf-8')).hexdigest()

    def _write_output(self, rules: List[str]):
        """写入输出文件"""
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')
        print(f"已写入合并规则: {OUTPUT_FILE}")


if __name__ == '__main__':
    try:
        AdblockMerger().run()
        sys.exit(0)
    except Exception as e:
        print(f"执行失败: {e}")
        sys.exit(1)