#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Generator


# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"

MAX_WORKERS = 4
CHUNK_SIZE = 10000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt"]

DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

MAX_RULES_IN_MEMORY = 2000000
HASH_SALT = "adblock_salt_2024"


# 预编译正则
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


def efficient_hash(rule: str) -> str:
    return hashlib.md5((rule + HASH_SALT).encode('utf-8')).hexdigest()


class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()

    def run(self):
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            print("未找到有效规则文件")
            return

        all_rules, _ = self._process_files_parallel()
        self._write_output(all_rules)
        self._github_actions_output()

        elapsed = time.time() - start_time
        print(f"合并完成 | 最终规则数: {len(all_rules)} | 耗时: {elapsed:.2f}s")

    def _discover_input_files(self):
        for pattern in INPUT_PATTERNS:
            for file_path in TEMP_DIR.glob(pattern):
                if file_path == OUTPUT_FILE:
                    continue

                file_hash = self._calculate_file_hash(file_path)
                if file_hash in self.file_hashes:
                    continue

                self.file_hashes.add(file_hash)
                self.input_files.append(file_path)
        print(f"发现规则文件: {len(self.input_files)}个")

    def _calculate_file_hash(self, file_path: Path) -> str:
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
            return hasher.hexdigest()
        except Exception:
            return str(file_path)

    def _process_files_parallel(self):
        all_rules = []
        global_cache = set()

        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(self._process_file, fp): fp for fp in self.input_files}

            for future in as_completed(future_to_file):
                try:
                    rules, _ = future.result()
                    new_rules = []
                    for rule in rules:
                        rule_hash = efficient_hash(rule)
                        if rule_hash not in global_cache:
                            new_rules.append(rule)
                            global_cache.add(rule_hash)

                    all_rules.extend(new_rules)

                    if len(all_rules) >= MAX_RULES_IN_MEMORY:
                        all_rules = self._merge_temp_rules(all_rules)
                except Exception:
                    pass

        return all_rules, {}

    def _process_file(self, file_path: Path):
        rules = []
        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                    continue
                if not (self.len_min <= len(line) <= self.len_max):
                    continue
                rule = self._to_adblock(line)
                if rule:
                    rules.append(rule)
        return rules, {}

    def _to_adblock(self, line: str) -> str:
        hosts_match = HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                return f"||{domain}^"

        elif PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                return f"||{line}^"

        elif ADBLOCK_DOMAIN.match(line) or ADBLOCK_WHITELIST.match(line):
            domain_match = re.search(r'\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
            if domain_match and self._is_valid_domain(domain_match.group(1)):
                return line

        return ""

    def _is_valid_domain(self, domain: str) -> bool:
        if domain in DOMAIN_BLACKLIST or IP_ADDRESS.match(domain):
            return False
        if len(domain) < 4 or len(domain) > 253:
            return False
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False
        return True

    def _write_output(self, rules: List[str]):
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')
        print(f"已写入合并规则: {OUTPUT_FILE}")

    def _merge_temp_rules(self, rules: List[str]) -> List[str]:
        temp_file = TEMP_DIR / f"temp_{int(time.time())}.txt"
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')

        merged = []
        for tf in TEMP_DIR.glob("temp_*.txt"):
            with open(tf, 'r', encoding='utf-8') as f:
                merged.extend(f.read().splitlines())
            tf.unlink()
        return merged

    def _github_actions_output(self):
        if github_output := os.getenv('GITHUB_OUTPUT'):
            with open(github_output, 'a') as f:
                f.write(f"merged_file={OUTPUT_FILE}\n")


if __name__ == '__main__':
    try:
        AdblockMerger().run()
        sys.exit(0)
    except Exception as e:
        print(f"执行失败: {e}")
        sys.exit(1)