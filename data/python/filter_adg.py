#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AdGuard规则转换工具（优化版）"""

import os
import sys
import glob
import re
import time
import hashlib
from pathlib import Path
from typing import Tuple, List, Dict


# 配置参数
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')

# 输出文件
OUTPUT_FILE = BASE_DIR / "adblock_adg.txt"
ALLOW_FILE = BASE_DIR / "allow_adg.txt"

# 性能参数
CHUNK_SIZE = 50000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock_merged.txt"]
HASH_SALT = "adguard_salt_2024"

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}


# 预编译正则表达式
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
ADGUARD_CSP = re.compile(r'^.+\$csp=')
ADGUARD_REDIRECT = re.compile(r'^.+\$redirect=')
ADGUARD_OTHER = re.compile(r'^.+\$(popup|document|script|stylesheet|object|xmlhttprequest|subdocument|ping|media|other|webrtc|websocket)$')


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE):
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
    except Exception:
        yield []


def efficient_hash(rule: str) -> str:
    """高效哈希函数，用于去重"""
    return hashlib.md5((rule + HASH_SALT).encode('utf-8')).hexdigest()


class AdGuardMerger:
    def __init__(self):
        # 确保目录存在
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # 清理原有输出文件
        for output_file in [OUTPUT_FILE, ALLOW_FILE]:
            if output_file.exists():
                output_file.unlink()

        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()

    def run(self):
        """主处理流程"""
        start_time = time.time()
        
        # 获取输入文件
        self._discover_input_files()
        if not self.input_files:
            print("未找到输入文件")
            return

        # 处理文件
        rules, allows, stats = self._process_files()

        # 写入输出文件
        self._write_output_files(rules, allows)

        # 输出统计信息
        elapsed = time.time() - start_time
        self._print_summary(stats, elapsed, len(rules), len(allows))

        # GitHub Actions输出
        self._github_actions_output()

    def _discover_input_files(self):
        """发现输入文件，并过滤重复内容"""
        for pattern in INPUT_PATTERNS:
            for file_path in glob.glob(str(TEMP_DIR / pattern)):
                path_obj = Path(file_path)
                if path_obj == OUTPUT_FILE or path_obj == ALLOW_FILE:
                    continue

                if path_obj.is_file():
                    # 文件内容去重
                    file_hash = self._calculate_file_hash(path_obj)
                    if file_hash in self.file_hashes:
                        continue

                    self.file_hashes.add(file_hash)
                    self.input_files.append(path_obj)

        print(f"发现输入文件: {len(self.input_files)}个")

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件内容的哈希值，用于去重"""
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
                return hasher.hexdigest()
        except Exception:
            return str(file_path)

    def _process_files(self) -> Tuple[List[str], List[str], Dict]:
        """处理所有文件"""
        rules = []
        allows = []
        rules_cache = set()
        allows_cache = set()
        stats = self._empty_stats()

        for file_path in self.input_files:
            file_rules, file_allows, file_stats = self._process_file(file_path)

            # 全局去重
            new_rules = []
            for rule in file_rules:
                rule_hash = efficient_hash(rule)
                if rule_hash not in rules_cache:
                    new_rules.append(rule)
                    rules_cache.add(rule_hash)

            new_allows = []
            for allow in file_allows:
                allow_hash = efficient_hash(allow)
                if allow_hash not in allows_cache:
                    new_allows.append(allow)
                    allows_cache.add(allow_hash)

            # 添加到结果
            rules.extend(new_rules)
            allows.extend(new_allows)

            # 合并统计信息
            stats = self._merge_stats(stats, file_stats)

        return rules, allows, stats

    def _process_file(self, file_path: Path) -> Tuple[List[str], List[str], Dict]:
        """处理单个文件"""
        stats = self._empty_stats()
        rules = []
        allows = []
        rules_cache = set()
        allows_cache = set()

        # 分块处理文件
        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                rule, is_allow = self._process_line(line, stats)
                if rule:
                    rule_hash = efficient_hash(rule)
                    if is_allow:
                        if rule_hash not in allows_cache:
                            allows.append(rule)
                            allows_cache.add(rule_hash)
                    else:
                        if rule_hash not in rules_cache:
                            rules.append(rule)
                            rules_cache.add(rule_hash)

        return rules, allows, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        """处理单行规则"""
        stats['total'] += 1

        # 快速过滤：空行和注释
        if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
            stats['filtered'] += 1
            return None, False

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None, False

        # 转换为AdGuard格式
        adguard_rule, is_allow = self._to_adguard(line)
        if not adguard_rule:
            stats['unsupported'] += 1
            return None, False

        stats['valid'] += 1
        return adguard_rule, is_allow

    def _to_adguard(self, line: str) -> Tuple[str, bool]:
        """将规则转换为AdGuard格式"""
        # 白名单规则（@@开头）
        if line.startswith('@@'):
            normalized = line[2:]
            if ADBLOCK_DOMAIN.match(normalized):
                return normalized, True
            return line, True

        # Hosts规则转换
        hosts_match = HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                return f"||{domain}^", False

        # 纯域名转换
        if PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                return f"||{line}^", False

        # 保留AdGuard特有规则
        if (ADGUARD_CSP.match(line) or 
            ADGUARD_REDIRECT.match(line) or 
            ADGUARD_OTHER.match(line)):
            return line, False

        # 保留标准Adblock规则
        if ADBLOCK_DOMAIN.match(line):
            domain_match = re.search(r'\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
            if domain_match and self._is_valid_domain(domain_match.group(1)):
                return line, False

        return None, False

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        # 过滤黑名单域名
        if domain in DOMAIN_BLACKLIST:
            return False

        # 过滤IP地址
        if IP_ADDRESS.match(domain):
            return False

        # 基本长度检查
        if len(domain) < 4 or len(domain) > 253:
            return False

        # 必须包含点号且不以点号开头或结尾
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False

        return True

    def _write_output_files(self, rules: List[str], allows: List[str]):
        """写入输出文件"""
        # 写入规则文件
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            if rules:
                f.write('\n'.join(rules) + '\n')

        # 写入白名单文件
        with open(ALLOW_FILE, 'w', encoding='utf-8') as f:
            if allows:
                f.write('\n'.join(allows) + '\n')

        print(f"已写入规则: {OUTPUT_FILE.name} ({len(rules)} 条)")
        print(f"已写入白名单: {ALLOW_FILE.name} ({len(allows)} 条)")

    def _print_summary(self, stats: Dict, elapsed: float, rule_count: int, allow_count: int):
        """输出处理摘要"""
        print("\n===== 处理摘要 =====")
        print(f"处理文件: {len(self.input_files)} 个")
        print(f"总行数: {stats['total']} 行")
        print(f"有效规则: {stats['valid']} 条")
        print(f"  - 拦截规则: {rule_count} 条")
        print(f"  - 白名单规则: {allow_count} 条")
        print(f"过滤行数: {stats['filtered'] + stats['unsupported']}")
        print(f"耗时: {elapsed:.2f} 秒")

    def _github_actions_output(self):
        """GitHub Actions输出"""
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"adguard_file={OUTPUT_FILE}\n")
                f.write(f"adguard_allow_file={ALLOW_FILE}\n")

    @staticmethod
    def _empty_stats() -> Dict:
        return {'total': 0, 'valid': 0, 'filtered': 0, 'unsupported': 0}

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        for key in total:
            total[key] += new[key]
        return total


if __name__ == '__main__':
    try:
        merger = AdGuardMerger()
        merger.run()
        sys.exit(0)
    except Exception as e:
        print(f"脚本执行失败: {str(e)}")
        sys.exit(1)