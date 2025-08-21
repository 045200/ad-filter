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
from typing import List, Generator, Set, Tuple, Dict


# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"

MAX_WORKERS = 4
CHUNK_SIZE = 10000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*", "adg*.txt", "adh*.txt"]  # AdGuard相关文件匹配

# 无效域名黑名单（通用+AdGuard特殊场景）
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain', '*'
}

MAX_RULES_IN_MEMORY = 2000000
HASH_SALT = "adblock_salt_2024_v2"  # 升级盐值用于新的标准化逻辑


# 预编译正则（强化AdGuard/AdGuard Home语法支持）
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
IP_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
IP_CIDR6 = re.compile(r'^[0-9a-fA-F:]+/\d{1,3}$')

# 基础AdBlock规则模式（支持AdGuard扩展域名格式）
DOMAIN_PATTERN = r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
ADBLOCK_DOMAIN = re.compile(rf'^(@@)?\|{{1,2}}({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}[\^\/\|\$]?')
HOSTS_LINE = re.compile(rf'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}')
PURE_DOMAIN = re.compile(rf'^({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}$')

# AdGuard/AdGuard Home特有语法正则（扩展）
ADG_DNSREWRITE = re.compile(r'^\|\|.*\$dnsrewrite=')  # DNS重写
ADG_REDIRECT = re.compile(r'^\|\|.*\$redirect=')      # 重定向
ADG_REPLACE = re.compile(r'^\|\|.*\$replace=')        # 内容替换
ADG_CLIENT_SERVER = re.compile(r'^\|\|.*\$(client|server)=')  # 客户端/服务器限定
ADG_CSP = re.compile(r'^\|\|.*\$csp=')                # 内容安全策略
ADH_IP_RULE = re.compile(r'^(IP-CIDR|IP-CIDR6):[^,]+,[A-Za-z]+$')  # IP规则（忽略大小写）
ADG_EXTENSION = re.compile(r'^\|\|.*\$extension=')    # 扩展限定
ADG_SCRIPTLET = re.compile(r'(##\+js\(|#%#//scriptlet\()')  # 脚本注入
ADG_CSS = re.compile(r'^##|^#@#')                    # CSS选择器


# 支持的AdBlock/AdGuard选项（含语义等价映射）
ADBLOCK_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_:-]+')
ADG_SPECIFIC_OPTIONS = {
    'dnsrewrite', 'redirect', 'replace', 'client', 'server', 
    'csp', 'extension', 'rewrite', 'unblock', 'allow'
}
# 选项语义等价映射（如'reject'和'block'视为相同）
OPTION_EQUIVALENTS = {
    'reject': 'block',
    'deny': 'block',
    'allow': 'unblock',
    'permit': 'unblock'
}


def detect_encoding(file_path: Path) -> str:
    """检测文件编码（兼容AdGuard规则常见编码）"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
            # 优先处理中文编码
            if encoding.lower() in ['gb2312', 'gbk']:
                encoding = 'gb18030'
            return encoding
    except Exception:
        return 'utf-8'


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件（增强容错）"""
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
        # 备选编码尝试
        for alt_encoding in ['utf-8', 'latin-1']:
            try:
                with open(file_path, 'r', encoding=alt_encoding, errors='replace') as f:
                    chunk = []
                    for line in f:
                        chunk.append(line.strip())
                        if len(chunk) >= chunk_size:
                            yield chunk
                            chunk = []
                    if chunk:
                        yield chunk
                break
            except Exception:
                continue


class AdblockMerger:
    def __init__(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.len_min, self.len_max = RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()
        self.processed_files = 0
        self.total_rules = 0
        # AdGuard规则统计（细化分类）
        self.stats = {
            'adg_dnsrewrite': 0,
            'adg_redirect': 0,
            'adg_replace': 0,
            'adg_client_server': 0,
            'adg_csp': 0,
            'adg_scriptlet': 0,
            'adg_css': 0,
            'adh_ip_rules': 0,
            'standard_adblock': 0,  # 标准AdBlock规则
            'duplicates_removed': 0  # 去重数量统计
        }

    def run(self):
        """主运行方法"""
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            print("未找到有效规则文件")
            return

        print(f"发现规则文件: {len(self.input_files)}个")
        raw_rules = self._process_files_parallel()
        unique_rules = self._deduplicate_rules(raw_rules)  # 语义级去重
        self._write_output(unique_rules)

        elapsed = time.time() - start_time
        print(f"合并完成 | 处理文件: {self.processed_files} | 原始规则数: {len(raw_rules)} | 去重后规则数: {len(unique_rules)} | 去重数量: {self.stats['duplicates_removed']} | 耗时: {elapsed:.2f}s")
        # 输出AdGuard规则统计
        print("AdGuard/AdGuard Home规则统计:")
        print(f"  DNS重写规则: {self.stats['adg_dnsrewrite']}")
        print(f"  重定向规则: {self.stats['adg_redirect']}")
        print(f"  内容替换规则: {self.stats['adg_replace']}")
        print(f"  客户端/服务器限定规则: {self.stats['adg_client_server']}")
        print(f"  内容安全策略规则: {self.stats['adg_csp']}")
        print(f"  脚本注入规则: {self.stats['adg_scriptlet']}")
        print(f"  CSS选择器规则: {self.stats['adg_css']}")
        print(f"  AdGuard Home IP规则: {self.stats['adh_ip_rules']}")
        print(f"  标准AdBlock规则: {self.stats['standard_adblock']}")

    def _discover_input_files(self):
        """发现输入文件（含AdGuard特有文件）"""
        for pattern in INPUT_PATTERNS:
            for file_path in TEMP_DIR.glob(pattern):
                if file_path == OUTPUT_FILE or not file_path.is_file():
                    continue

                file_hash = self._calculate_file_hash(file_path)
                if file_hash in self.file_hashes:
                    continue  # 跳过重复文件

                self.file_hashes.add(file_hash)
                self.input_files.append(file_path)

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值（避免重复处理相同文件）"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                # 读取文件头和大小作为哈希依据
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
            return hasher.hexdigest()
        except Exception:
            return str(file_path)

    def _process_files_parallel(self) -> List[str]:
        """并行处理文件（提取规则）"""
        all_rules = []

        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {executor.submit(self._process_file, fp): fp for fp in self.input_files}

            for future in as_completed(future_to_file):
                try:
                    file_rules, file_stats = future.result()  # 接收规则和统计
                    self.processed_files += 1
                    self.total_rules += len(file_rules)
                    # 累加统计
                    for k, v in file_stats.items():
                        self.stats[k] += v
                    print(f"处理文件 {self.processed_files}/{len(self.input_files)}: 提取 {len(file_rules)} 条规则")
                    all_rules.extend(file_rules)
                except Exception as e:
                    print(f"处理文件时出错: {e}")

        return all_rules

    def _process_file(self, file_path: Path) -> Tuple[List[str], Dict[str, int]]:
        """处理单个文件（返回规则和统计）"""
        rules = []
        file_stats = {k:0 for k in self.stats.keys()}  # 单文件统计

        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                    continue  # 跳过注释和空行

                if not (self.len_min <= len(line) <= self.len_max):
                    continue  # 过滤长度异常的规则

                rule, rule_stats = self._process_line(line)  # 处理单行
                if rule:
                    rules.append(rule)
                    # 更新单文件统计
                    for k, v in rule_stats.items():
                        file_stats[k] += v

        return rules, file_stats

    def _process_line(self, line: str) -> Tuple[str, Dict[str, int]]:
        """处理单行规则（强化AdGuard规则标准化）"""
        rule_stats = {k:0 for k in self.stats.keys()}
        original_line = line.strip()

        # 移除行内注释（兼容AdGuard注释风格）
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        if '!' in line:
            line = line.split('!', 1)[0].strip()
        if not line:
            return "", rule_stats

        # 1. 处理AdGuard Home IP规则（标准化大小写和动作）
        if ADH_IP_RULE.match(line):
            ip_type, rest = line.split(':', 1)
            ip_range, action = rest.split(',', 1)
            # 标准化：IP类型大写，动作统一（如reject→block）
            ip_type = ip_type.upper()
            action = action.strip().lower()
            action = OPTION_EQUIVALENTS.get(action, action)  # 等价动作映射
            normalized_rule = f"{ip_type}:{ip_range},{action.upper()}"
            rule_stats['adh_ip_rules'] = 1
            return normalized_rule, rule_stats

        # 2. 处理AdGuard脚本注入规则（标准化参数顺序）
        if ADG_SCRIPTLET.search(line):
            # 提取脚本内容并标准化参数顺序（按参数名排序）
            script_content = re.search(r'(##\+js\(|#%#//scriptlet\()(.*?)\)', line).group(2)
            if ',' in script_content:
                params = [p.strip() for p in script_content.split(',')]
                # 简单参数按字符串排序（复杂场景可扩展）
                params.sort()
                normalized_script = ','.join(params)
                normalized_rule = line.replace(script_content, normalized_script)
            else:
                normalized_rule = line
            rule_stats['adg_scriptlet'] = 1
            return normalized_rule, rule_stats

        # 3. 处理AdGuard CSS选择器规则（标准化空格）
        if ADG_CSS.match(line):
            # 移除多余空格（如"## .class" → "##.class"）
            normalized_rule = re.sub(r'\s+', ' ', line).replace(' ##', '##').replace('## ', '##')
            rule_stats['adg_css'] = 1
            return normalized_rule, rule_stats

        # 4. 处理含选项的AdGuard规则（标准化选项）
        if '$' in line:
            domain_part, opt_part = line.split('$', 1)
            # 标准化域名部分（如"||example.com^"和"|example.com|"统一）
            domain_part = self._normalize_domain(domain_part)
            # 标准化选项部分（排序+等价替换）
            opts = opt_part.split(',')
            normalized_opts = []
            for opt in opts:
                opt = opt.strip()
                if '=' in opt:
                    k, v = opt.split('=', 1)
                    k = k.lower()
                    v = v.strip()
                    # 选项值等价替换（如client=app1→client=app1，动作统一）
                    if k in ['action', 'type']:
                        v = OPTION_EQUIVALENTS.get(v.lower(), v)
                    normalized_opts.append(f"{k}={v}")
                else:
                    # 无值选项（如"important"）
                    normalized_opts.append(opt.lower())
            # 按选项名排序（确保顺序不同但语义相同的规则一致）
            normalized_opts.sort()
            normalized_rule = f"{domain_part}${','.join(normalized_opts)}"
            # 统计具体规则类型
            if 'dnsrewrite=' in normalized_rule:
                rule_stats['adg_dnsrewrite'] = 1
            elif 'redirect=' in normalized_rule:
                rule_stats['adg_redirect'] = 1
            elif 'replace=' in normalized_rule:
                rule_stats['adg_replace'] = 1
            elif 'client=' in normalized_rule or 'server=' in normalized_rule:
                rule_stats['adg_client_server'] = 1
            elif 'csp=' in normalized_rule:
                rule_stats['adg_csp'] = 1
            return normalized_rule, rule_stats

        # 5. 处理基础AdBlock规则（标准化域名格式）
        normalized_domain = self._normalize_domain(line)
        if normalized_domain:
            # 判断是否为标准AdBlock规则
            if ADBLOCK_DOMAIN.match(normalized_domain) or PURE_DOMAIN.match(normalized_domain):
                rule_stats['standard_adblock'] = 1
                return normalized_domain, rule_stats

        # 6. 处理Hosts规则（转换为AdBlock格式）
        hosts_match = HOSTS_LINE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                normalized_rule = f"||{domain}^"
                rule_stats['standard_adblock'] = 1
                return normalized_rule, rule_stats

        # 未匹配的有效规则直接返回
        return line, rule_stats

    def _normalize_domain(self, domain_part: str) -> str:
        """标准化域名部分（解决语义相同的不同写法）"""
        domain = domain_part.strip()
        if not domain:
            return ""

        # 移除协议前缀（http://、https://）
        domain = re.sub(r'^https?://', '', domain)
        # 统一通配符格式（*.example.com → ||example.com）
        domain = re.sub(r'^\*\.', '||', domain)
        # 统一域名后缀（example.com| → ||example.com^）
        domain = re.sub(r'\|$', '^', domain)
        # 确保开头统一（|example.com → ||example.com）
        if domain.startswith('|') and not domain.startswith('||'):
            domain = f"|{domain}"
        # 移除多余通配符（***example.com → *example.com）
        domain = re.sub(r'\*+', '*', domain)

        return domain if self._is_valid_domain(domain.lstrip('|@')) else ""

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性（兼容AdGuard特殊格式）"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False

        # 允许AdGuard通配符域名（如*example.com）
        if '*' in domain:
            # 过滤纯通配符（如"*"）
            if domain.strip('*') == '':
                return False
            # 提取核心域名验证（如*example.com → example.com）
            core_domain = re.sub(r'\*', '', domain)
            if not core_domain:
                return False
            domain = core_domain

        if IP_ADDRESS.match(domain):
            return False

        if len(domain) < 4 or len(domain) > 253:
            return False

        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False

        # 验证域名标签（支持AdGuard允许的下划线）
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-_|]{0,61}[a-zA-Z0-9])?$', label):
                return False

        return True

    def _deduplicate_rules(self, rules: List[str]) -> List[str]:
        """语义级去重（基于标准化后的哈希）"""
        seen_hashes = set()
        unique_rules = []
        for rule in rules:
            rule_hash = self._rule_hash(rule)
            if rule_hash not in seen_hashes:
                seen_hashes.add(rule_hash)
                unique_rules.append(rule)
            else:
                self.stats['duplicates_removed'] += 1
        return unique_rules

    def _rule_hash(self, rule: str) -> str:
        """生成规则哈希（基于标准化后的值）"""
        return hashlib.sha256((rule + HASH_SALT).encode('utf-8')).hexdigest()

    def _write_output(self, rules: List[str]):
        """写入输出文件（分类排序）"""
        # 按规则类型排序（IP规则→脚本→CSS→普通规则）
        def rule_sort_key(rule: str) -> Tuple[int, str]:
            if rule.startswith(('IP-CIDR', 'IP-CIDR6')):
                return (0, rule)  # IP规则优先
            elif ADG_SCRIPTLET.search(rule):
                return (1, rule)  # 脚本注入
            elif ADG_CSS.match(rule):
                return (2, rule)  # CSS选择器
            elif any(opt in rule for opt in ADG_SPECIFIC_OPTIONS):
                return (3, rule)  # AdGuard特殊选项
            else:
                return (4, rule)  # 普通规则

        rules.sort(key=rule_sort_key)

        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('! 合并广告过滤规则（支持AdGuard/AdGuard Home扩展语法）\n')
            f.write('! 生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            f.write('! 规则总数: ' + str(len(rules)) + '\n')
            f.write('! 去重数量: ' + str(self.stats['duplicates_removed']) + '\n')
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
