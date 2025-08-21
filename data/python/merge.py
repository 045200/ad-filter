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
OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"

MAX_WORKERS = 4
CHUNK_SIZE = 10000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*", "adg*.txt", "adh*.txt"]  # 新增AdGuard相关文件匹配

DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

MAX_RULES_IN_MEMORY = 2000000
HASH_SALT = "adblock_salt_2024"


# 预编译正则（新增AdGuard/AdGuard Home专属语法）
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
IP_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
IP_CIDR6 = re.compile(r'^[0-9a-fA-F:]+/\d{1,3}$')

# 基础AdBlock规则模式
DOMAIN_PATTERN = r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
ADBLOCK_DOMAIN = re.compile(rf'^(@@)?\|{{1,2}}({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}[\^\/\|\$]?')
HOSTS_LINE = re.compile(rf'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}')
PURE_DOMAIN = re.compile(rf'^({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}$')

# AdGuard/AdGuard Home特有语法正则
# 1. DNS重写规则（$dnsrewrite）
ADG_DNSREWRITE = re.compile(r'^\|\|.*\$dnsrewrite=')
# 2. 重定向规则（$redirect）
ADG_REDIRECT = re.compile(r'^\|\|.*\$redirect=')
# 3. 内容替换规则（$replace）
ADG_REPLACE = re.compile(r'^\|\|.*\$replace=')
# 4. 客户端/服务器限定符（$client/$server）
ADG_CLIENT_SERVER = re.compile(r'^\|\|.*\$(client|server)=')
# 5. 自定义过滤规则（如局部屏蔽）
ADG_CSP = re.compile(r'^\|\|.*\$csp=')
# 6. AdGuard Home的IP/CIDR规则
ADH_IP_RULE = re.compile(r'^(IP-CIDR|IP-CIDR6):[^,]+,[A-Z]+$')
# 7. AdGuard的扩展修饰符（$extension）
ADG_EXTENSION = re.compile(r'^\|\|.*\$extension=')


# 支持的AdBlock/AdGuard选项（扩展AdGuard专属选项）
ADBLOCK_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_:-]+')
ADG_SPECIFIC_OPTIONS = {
    'dnsrewrite', 'redirect', 'replace', 'client', 'server', 
    'csp', 'extension', 'rewrite', 'unblock', 'allow'
}


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
        # 尝试使用UTF-8作为备选
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
            print(f"UTF-8读取也失败 {file_path}: {e2}")


class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()
        self.processed_files = 0
        self.total_rules = 0
        # 新增AdGuard规则统计
        self.stats = {
            'adg_dnsrewrite': 0,
            'adg_redirect': 0,
            'adg_replace': 0,
            'adg_client_server': 0,
            'adh_ip_rules': 0
        }

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
        # 输出AdGuard规则统计
        print("AdGuard/AdGuard Home规则统计:")
        print(f"  DNS重写规则: {self.stats['adg_dnsrewrite']}")
        print(f"  重定向规则: {self.stats['adg_redirect']}")
        print(f"  内容替换规则: {self.stats['adg_replace']}")
        print(f"  客户端/服务器限定规则: {self.stats['adg_client_server']}")
        print(f"  AdGuard Home IP规则: {self.stats['adh_ip_rules']}")

    def _discover_input_files(self):
        """发现输入文件（新增AdGuard相关文件）"""
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
                    file_rules, file_stats = future.result()  # 接收规则和统计信息
                    self.processed_files += 1
                    self.total_rules += len(file_rules)
                    # 累加AdGuard规则统计
                    for k, v in file_stats.items():
                        self.stats[k] += v
                    print(f"处理文件 {self.processed_files}/{len(self.input_files)}: 提取 {len(file_rules)} 条规则")

                    for rule in file_rules:
                        rule_hash = self._rule_hash(rule)
                        if rule_hash not in rule_hashes:
                            rules.append(rule)
                            rule_hashes.add(rule_hash)
                except Exception as e:
                    print(f"处理文件时出错: {e}")

        return rules

    def _process_file(self, file_path: Path) -> Tuple[List[str], dict]:
        """处理单个文件（返回规则和统计）"""
        rules = []
        file_stats = {k:0 for k in self.stats.keys()}  # 单文件统计

        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                    continue

                if not (self.len_min <= len(line) <= self.len_max):
                    continue

                rule, rule_stats = self._process_line(line)  # 处理单行并获取统计
                if rule:
                    rules.append(rule)
                    # 更新单文件统计
                    for k, v in rule_stats.items():
                        file_stats[k] += v

        return rules, file_stats

    def _process_line(self, line: str) -> Tuple[str, dict]:
        """处理单行规则（扩展AdGuard/AdGuard Home语法）"""
        rule_stats = {k:0 for k in self.stats.keys()}  # 单行规则统计
        original_line = line

        # 移除行内注释
        if '#' in line:
            line = line.split('#')[0].strip()
        if '!' in line:
            line = line.split('!')[0].strip()

        # 1. 优先处理AdGuard Home的IP/CIDR规则（如IP-CIDR:192.168.1.0/24,REJECT）
        if ADH_IP_RULE.match(line):
            parts = line.split(':')
            if len(parts) == 2 and ',' in parts[1]:
                ip_part, action = parts[1].split(',', 1)
                # 验证IP/CIDR格式
                if (IP_CIDR.match(ip_part) or IP_CIDR6.match(ip_part)) and action.strip().isupper():
                    rule_stats['adh_ip_rules'] = 1
                    return original_line, rule_stats

        # 2. 处理AdGuard特有选项规则（$dnsrewrite/$redirect等）
        if '$' in line:
            # 提取选项部分
            opt_part = line.split('$', 1)[-1] if '$' in line else ''
            # 检测AdGuard专属选项
            for opt in ADG_SPECIFIC_OPTIONS:
                if opt_part.startswith(opt + '=') or re.search(r',%s=' % opt, opt_part):
                    # 验证基础域名部分
                    domain_part = line.split('$', 1)[0]
                    if ADBLOCK_DOMAIN.match(domain_part) or PURE_DOMAIN.match(domain_part.lstrip('|')):
                        # 分类统计
                        if opt == 'dnsrewrite':
                            rule_stats['adg_dnsrewrite'] = 1
                        elif opt == 'redirect':
                            rule_stats['adg_redirect'] = 1
                        elif opt == 'replace':
                            rule_stats['adg_replace'] = 1
                        elif opt in ['client', 'server']:
                            rule_stats['adg_client_server'] = 1
                        return original_line, rule_stats

        # 3. 尝试AdBlock标准规则（含AdGuard兼容规则）
        if ADBLOCK_DOMAIN.match(line):
            domain_match = re.search(r'\|{1,2}([a-zA-Z0-9.-]+)[\^\/\|\$]', line)
            if domain_match:
                domain = domain_match.group(1)
                if self._is_valid_domain(domain):
                    return original_line, rule_stats

        # 4. 尝试hosts格式
        hosts_match = HOSTS_LINE.match(line)
        if hosts_match:
            domain_match = re.search(r'\s+([a-zA-Z0-9.-]+)$', line)
            if domain_match:
                domain = domain_match.group(1)
                if self._is_valid_domain(domain):
                    return f"||{domain}^", rule_stats

        # 5. 尝试纯域名格式
        if PURE_DOMAIN.match(line):
            if self._is_valid_domain(line):
                return f"||{line}^", rule_stats

        # 6. 尝试CSS选择器规则（AdGuard支持扩展选择器）
        if self._is_css_selector(line):
            return original_line, rule_stats

        # 7. 尝试网络过滤器规则（含AdGuard扩展通配符）
        if self._is_network_filter(line):
            return original_line, rule_stats

        # 8. 尝试脚本注入规则（AdGuard支持扩展脚本）
        if self._is_scriptlet_injection(line):
            return original_line, rule_stats

        return "", rule_stats

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性（兼容AdGuard的子域名规则）"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False

        if IP_ADDRESS.match(domain):
            return False

        if len(domain) < 4 or len(domain) > 253:
            return False

        # 允许AdGuard的通配符前缀（如*.example.com）
        if domain.startswith('*.'):
            domain = domain[2:]  # 移除前缀后验证

        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False

        # 放宽标签验证（支持AdGuard的特殊域名格式）
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
            # 允许标签包含下划线（AdGuard支持）
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-_|]{0,61}[a-zA-Z0-9])?$', label):
                return False

        return True

    def _is_css_selector(self, line: str) -> bool:
        """检查是否是CSS选择器规则（AdGuard支持扩展语法）"""
        # AdGuard支持的增强CSS规则（如##+js()、##@media等）
        if line.startswith(('##', '#@#')):
            return True
        # AdGuard的脚本注入选择器（##+js(...)）
        if re.search(r'##\+js\([^)]+\)', line):
            return True
        return False

    def _is_network_filter(self, line: str) -> bool:
        """检查是否是网络过滤器规则（含AdGuard扩展）"""
        # AdGuard支持的增强通配符和路径规则
        if '*' in line and not line.startswith('!'):
            return True
        # AdGuard的URL路径过滤（如||example.com/path/*）
        if re.search(r'^[a-zA-Z0-9*.-]+/[a-zA-Z0-9*.-]+', line):
            return True
        # 包含AdGuard特有选项的规则
        if any(opt in line for opt in ADG_SPECIFIC_OPTIONS):
            return True
        return False

    def _is_scriptlet_injection(self, line: str) -> bool:
        """检查是否是脚本注入规则（AdGuard扩展）"""
        # AdGuard的脚本注入（#%#//scriptlet('...')）
        if line.startswith(('#%#', '#$#')):
            return True
        # AdGuard的扩展脚本（##+js(...)）
        if re.search(r'##\+js\([^)]+\)', line):
            return True
        return False

    def _rule_hash(self, rule: str) -> str:
        """生成规则哈希值（适配AdGuard选项）"""
        # 标准化AdGuard规则：保留特有选项，排序选项参数
        if rule.startswith(('@@||', '||', 'IP-CIDR', 'IP-CIDR6')) or '$' in rule:
            # 分离域名和选项部分
            if '$' in rule:
                domain_part, opt_part = rule.split('$', 1)
                # 解析并排序选项（确保相同选项不同顺序视为同一规则）
                opts = opt_part.split(',')
                sorted_opts = []
                for opt in opts:
                    # 对AdGuard特有选项（如client=xxx）保留原值，其他按key排序
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                        sorted_opts.append(f"{k}={v}")
                    else:
                        sorted_opts.append(opt)
                # 按选项名排序（忽略值）
                sorted_opts.sort(key=lambda x: x.split('=')[0] if '=' in x else x)
                normalized = f"{domain_part}${','.join(sorted_opts)}"
            else:
                normalized = rule  # 无选项规则直接使用原值
            return hashlib.sha256((normalized + HASH_SALT).encode('utf-8')).hexdigest()
        return hashlib.sha256((rule + HASH_SALT).encode('utf-8')).hexdigest()

    def _write_output(self, rules: List[str]):
        """写入输出文件（新增AdGuard规则标识）"""
        rules.sort()

        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('! 合并广告过滤规则（含AdGuard/AdGuard Home特有规则）\n')
            f.write('! 生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            f.write('! 规则总数: ' + str(len(rules)) + '\n')
            f.write('! AdGuard DNS重写规则: ' + str(self.stats['adg_dnsrewrite']) + '\n')
            f.write('! AdGuard Home IP规则: ' + str(self.stats['adh_ip_rules']) + '\n')
            f.write('!\n')
            f.write('\n'.join(rules) + '\n')
        print(f"已写入合并规则: {OUTPUT_FILE}")


if __name__ == '__main__':
    try:
        # 确保chardet可用
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
