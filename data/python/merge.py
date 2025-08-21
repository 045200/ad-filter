#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import hashlib
import chardet
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Generator, Set, Tuple


# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_filter.txt"

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

# AdBlock 规则模式
DOMAIN_PATTERN = r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
ADBLOCK_DOMAIN = re.compile(rf'^(@@)?\|{{1,2}}({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}[\^\/\|\$]?')
HOSTS_LINE = re.compile(rf'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}')
PURE_DOMAIN = re.compile(rf'^({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}$')

# 支持的 AdBlock 语法元素
ADBLOCK_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_-]+')


def detect_encoding(file_path: Path) -> str:
    """检测文件编码"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
            # 处理中文编码
            if encoding.lower() in ['gb2312', 'gbk']:
                encoding = 'gb18030'
            return encoding
    except Exception:
        return 'utf-8'


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件（带编码检测）"""
    encoding = detect_encoding(file_path)
    try:
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
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
        # 尝试使用 UTF-8 作为备选
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                chunk = []
                for line in f:
                    chunk.append(line.strip())
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk
        except Exception as e2:
            print(f"UTF-8 读取也失败 {file_path}: {e2}")


class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()
        self.processed_files = 0
        self.total_rules = 0

    def run(self):
        """主运行方法"""
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            print("未找到有效规则文件")
            return

        print(f"发现规则文件: {len(self.input_files)}个")
        rules = self._process_files_parallel()
        self._write_output(rules)

        elapsed = time.time() - start_time
        print(f"合并完成 | 处理文件: {self.processed_files} | 最终规则数: {len(rules)} | 耗时: {elapsed:.2f}s")

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
                    self.processed_files += 1
                    self.total_rules += len(file_rules)
                    print(f"处理文件 {self.processed_files}/{len(self.input_files)}: 提取 {len(file_rules)} 条规则")
                    
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
        """处理单行规则 - 支持完整的 AdBlock 语法"""
        # 移除行内注释
        if '#' in line:
            line = line.split('#')[0].strip()
        if '!' in line:
            line = line.split('!')[0].strip()
            
        # 1. 尝试 AdBlock 格式规则
        if ADBLOCK_DOMAIN.match(line):
            # 提取域名部分和选项部分
            domain_match = re.search(r'\|{1,2}([a-zA-Z0-9.-]+)[\^\/\|\$]', line)
            if domain_match:
                domain = domain_match.group(1)
                if self._is_valid_domain(domain):
                    # 保留完整的 AdBlock 语法（包括选项）
                    return line
        
        # 2. 尝试 hosts 格式
        hosts_match = HOSTS_LINE.match(line)
        if hosts_match:
            # 提取域名
            domain_match = re.search(r'\s+([a-zA-Z0-9.-]+)$', line)
            if domain_match:
                domain = domain_match.group(1)
                if self._is_valid_domain(domain):
                    return f"||{domain}^"
        
        # 3. 尝试纯域名格式
        if PURE_DOMAIN.match(line):
            if self._is_valid_domain(line):
                return f"||{line}^"
                
        # 4. 尝试 CSS 选择器规则
        if self._is_css_selector(line):
            return line
            
        # 5. 尝试网络过滤器规则
        if self._is_network_filter(line):
            return line
            
        # 6. 尝试脚本注入规则
        if self._is_scriptlet_injection(line):
            return line
            
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

        # 放宽标签验证
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
            # 允许标签以数字开头和结尾，以及包含连字符
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', label):
                return False

        return True

    def _is_css_selector(self, line: str) -> bool:
        """检查是否是 CSS 选择器规则"""
        # CSS 选择器通常以 ## 开头
        if line.startswith('##'):
            return True
        # 或者是元素隐藏规则
        if re.search(r'#@?#[a-zA-Z]', line):
            return True
        return False

    def _is_network_filter(self, line: str) -> bool:
        """检查是否是网络过滤器规则"""
        # 包含通配符的模式
        if '*' in line and not line.startswith('!'):
            return True
        # 包含路径的模式
        if re.search(r'^[a-zA-Z0-9*.-]+/', line):
            return True
        return False

    def _is_scriptlet_injection(self, line: str) -> bool:
        """检查是否是脚本注入规则"""
        # 脚本注入规则通常以 #%# 或 #$# 开头
        if line.startswith(('#%#', '#$#')):
            return True
        return False

    def _rule_hash(self, rule: str) -> str:
        """生成规则哈希值"""
        # 标准化规则：域名部分小写，去除多余字符
        if rule.startswith('@@||') or rule.startswith('||'):
            # 分离域名和选项
            parts = re.split(r'[\^\/\|\$]', rule, 1)
            normalized = parts[0].lower()
            if len(parts) > 1:
                # 对选项部分进行排序，确保相同选项的不同顺序被视为相同规则
                options = parts[1]
                if '$' in options:
                    opt_parts = options.split('$', 1)
                    if ',' in opt_parts[1]:
                        opts = sorted(opt_parts[1].split(','))
                        normalized += '$' + ','.join(opts)
                    else:
                        normalized += '$' + opt_parts[1]
                else:
                    normalized += '^'  # 默认分隔符
            return hashlib.sha256((normalized + HASH_SALT).encode('utf-8')).hexdigest()
        return hashlib.sha256((rule + HASH_SALT).encode('utf-8')).hexdigest()

    def _write_output(self, rules: List[str]):
        """写入输出文件"""
        # 对规则进行排序（可选）
        rules.sort()
        
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('! 合并广告过滤规则\n')
            f.write('! 生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            f.write('! 规则总数: ' + str(len(rules)) + '\n')
            f.write('! 来源文件数: ' + str(self.processed_files) + '\n')
            f.write('!\n')
            f.write('\n'.join(rules) + '\n')
        print(f"已写入合并规则: {OUTPUT_FILE}")


if __name__ == '__main__':
    try:
        # 确保 chardet 可用
        try:
            import chardet
        except ImportError:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])
            import chardet
            
        AdblockMerger().run()
        sys.exit(0)
    except Exception as e:
        print(f"执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)