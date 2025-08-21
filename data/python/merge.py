#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import xxhash
import chardet
import logging
import fnmatch
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import List, Generator, Set, Tuple, Dict, Optional
from dataclasses import dataclass
from enum import Enum, auto
from concurrent.futures import ProcessPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("adblock_merger.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"
CACHE_DIR = TEMP_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
CHUNK_SIZE = 10000
RULE_LEN_RANGE = (4, 253)
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*", "adg*.txt", "adh*.txt", "filter*.txt"]

# 无效域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain', '*'
}

MAX_RULES_IN_MEMORY = 2000000
HASH_SALT = "adblock_salt_2024_v5"

# 规则类型枚举
class RuleType(Enum):
    IP_RULE = auto()
    SCRIPT_RULE = auto()
    CSS_RULE = auto()
    OPTION_RULE = auto()
    STANDARD_RULE = auto()
    HOSTS_RULE = auto()
    MODIFIER_RULE = auto()
    NETWORK_RULE = auto()
    COSMETIC_RULE = auto()
    EXCEPTION_RULE = auto()
    DNS_REWRITE_RULE = auto()
    UNKNOWN = auto()

# 规则数据类
@dataclass
class RuleInfo:
    raw_text: str
    normalized: str
    rule_type: RuleType
    domain: str = ""
    options: Dict[str, str] = None
    priority: int = 0

# 预编译正则表达式 - 优化性能
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
IP_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
IP_CIDR6 = re.compile(r'^[0-9a-fA-F:]+/\d{1,3}$')

# 域名模式
DOMAIN_PATTERN = r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
ADBLOCK_DOMAIN = re.compile(rf'^(@@)?\|{{1,2}}({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}[\^\/\|\$]?')
HOSTS_LINE = re.compile(rf'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}')
PURE_DOMAIN = re.compile(rf'^({DOMAIN_PATTERN}\.)+[a-zA-Z]{{2,}}$')

# AdBlock/AdGuard 语法正则
ADB_EXCEPTION = re.compile(r'^@@')
ADB_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_:-]+')
ADB_DOMAIN_ANCHOR = re.compile(r'^\|{1,2}[^\|]')
ADB_END_ANCHOR = re.compile(r'[\^\|\*].*$')

# AdGuard/AdGuard Home 特有语法正则
ADG_DNSREWRITE = re.compile(r'^\|\|.*\$dnsrewrite=')
ADG_REDIRECT = re.compile(r'^\|\|.*\$redirect=')
ADG_REPLACE = re.compile(r'^\|\|.*\$replace=')
ADG_CLIENT_SERVER = re.compile(r'^\|\|.*\$(client|server)=')
ADG_CSP = re.compile(r'^\|\|.*\$csp=')
ADH_IP_RULE = re.compile(r'^(IP-CIDR|IP-CIDR6):[^,]+,[A-Za-z]+$', re.IGNORECASE)
ADG_EXTENSION = re.compile(r'^\|\|.*\$extension=')
ADG_SCRIPTLET = re.compile(r'(##\+js\(|#%#//scriptlet\()')
ADG_CSS = re.compile(r'^##|^#@#')
ADG_MODIFIER = re.compile(r'^.*\$[a-zA-Z0-9_]+(=[^,]+)?(,[a-zA-Z0-9_]+(=[^,]+)?)*$')
ADG_NETWORK = re.compile(r'^\|\|.*\^')
ADG_COSMETIC = re.compile(r'^##.*')
ADG_DOCUMENT = re.compile(r'.*\$document')
ADG_IMPORTANT = re.compile(r'.*\$important')

# 选项语义等价映射
OPTION_EQUIVALENTS = {
    'reject': 'block',
    'deny': 'block',
    'allow': 'unblock',
    'permit': 'unblock',
    'stylesheet': 'css',
    'script': 'js',
    'xmlhttprequest': 'xhr',
    'subdocument': 'frame'
}

# 关键选项（保持顺序）
KEY_OPTIONS = {'domain', 'denyallow', 'important', 'cookie', 'removeparam', 'ctag', 'client', 'server'}

# 修饰符优先级（数值越低优先级越高）
MODIFIER_PRIORITY = {
    'important': 10,
    'document': 20,
    'csp': 30,
    'redirect': 40,
    'removeparam': 50,
    'cookie': 60,
    'network': 70,
    'script': 80,
    'stylesheet': 90,
    'subdocument': 100,
    'image': 110,
    'object': 120,
    'font': 130,
    'media': 140,
    'ping': 150,
    'websocket': 160,
    'webrtc': 170,
    'other': 1000
}


def detect_encoding(file_path: Path) -> str:
    """检测文件编码"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
            if encoding.lower() in ['gb2312', 'gbk']:
                encoding = 'gb18030'
            return encoding
    except Exception as e:
        logger.warning(f"检测文件编码失败 {file_path}: {e}")
        return 'utf-8'


def file_chunk_reader(file_path: Path, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件"""
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
        logger.error(f"读取文件 {file_path} 时出错: {e}")
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
        
        # 使用OrderedDict保持插入顺序，同时快速查找
        self.unique_rules = OrderedDict()
        
        # 布隆过滤器 (使用xxhash模拟)
        self.bloom_filter = set()  # 简化实现，实际应使用pybloom-live
        
        # 规则统计
        self.stats = defaultdict(int)
        self.rule_types = {
            RuleType.IP_RULE: "AdGuard Home IP规则",
            RuleType.SCRIPT_RULE: "脚本注入规则",
            RuleType.CSS_RULE: "CSS选择器规则",
            RuleType.OPTION_RULE: "含选项规则",
            RuleType.STANDARD_RULE: "标准AdBlock规则",
            RuleType.HOSTS_RULE: "Hosts转换规则",
            RuleType.MODIFIER_RULE: "修饰符规则",
            RuleType.NETWORK_RULE: "网络规则",
            RuleType.COSMETIC_RULE: "元素隐藏规则",
            RuleType.EXCEPTION_RULE: "例外规则",
            RuleType.DNS_REWRITE_RULE: "DNS重写规则",
            RuleType.UNKNOWN: "未知类型规则"
        }

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
        logger.info(f"合并完成 | 处理文件: {self.processed_files} | 去重后规则数: {len(self.unique_rules)} | 去重数量: {self.stats['duplicates_removed']} | 耗时: {elapsed:.2f}s")
        
        # 输出规则统计
        logger.info("规则统计:")
        for rule_type, count in self.stats.items():
            if count > 0 and rule_type != 'duplicates_removed':
                logger.info(f"  {rule_type.replace('_', ' ')}: {count}")
                
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
            # 使用xxhash提高性能
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
                    self.processed_files += 1
                    self.total_rules += len(file_rules)
                    logger.info(f"处理文件 {self.processed_files}/{len(self.input_files)}: 提取 {len(file_rules)} 条规则")
                    
                    # 处理并去重规则
                    for rule_info in file_rules:
                        self._add_rule(rule_info)
                        
                except Exception as e:
                    logger.error(f"处理文件时出错: {e}")

    def _process_file(self, file_path: Path) -> List[RuleInfo]:
        """处理单个文件"""
        rules = []
        
        for chunk in file_chunk_reader(file_path):
            # 并行处理块中的每一行
            with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_line = {executor.submit(self._parse_line, line): line for line in chunk}
                
                for future in as_completed(future_to_line):
                    try:
                        rule_info = future.result()
                        if rule_info:
                            rules.append(rule_info)
                    except Exception as e:
                        logger.error(f"解析行时出错: {e}")
                    
        return rules

    def _parse_line(self, line: str) -> Optional[RuleInfo]:
        """解析单行规则"""
        original_line = line.strip()
        
        # 移除行内注释
        line = self._remove_inline_comments(line)
        if not line:
            return None
            
        # 确定规则类型并标准化
        rule_type, normalized = self._classify_and_normalize(line)
        if not normalized:
            return None
            
        # 提取域名（如果适用）
        domain = self._extract_domain(normalized, rule_type)
        
        # 提取选项（如果适用）
        options = self._extract_options(normalized) if rule_type == RuleType.OPTION_RULE else None
        
        # 计算优先级
        priority = self._calculate_priority(normalized, rule_type, options)
        
        return RuleInfo(
            raw_text=original_line,
            normalized=normalized,
            rule_type=rule_type,
            domain=domain,
            options=options,
            priority=priority
        )

    def _remove_inline_comments(self, line: str) -> str:
        """移除行内注释"""
        # 处理AdBlock注释
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        # 处理AdGuard注释
        if '!' in line:
            line = line.split('!', 1)[0].strip()
        return line

    def _classify_and_normalize(self, line: str) -> Tuple[RuleType, str]:
        """分类并标准化规则"""
        # 1. 处理例外规则 (优先级最高)
        if ADB_EXCEPTION.match(line):
            return self._normalize_exception_rule(line)
            
        # 2. 处理AdGuard Home IP规则
        if ADH_IP_RULE.match(line):
            return self._normalize_ip_rule(line)
            
        # 3. 处理DNS重写规则
        if ADG_DNSREWRITE.search(line):
            return RuleType.DNS_REWRITE_RULE, self._normalize_dns_rewrite_rule(line)
            
        # 4. 处理脚本规则
        if ADG_SCRIPTLET.search(line):
            return RuleType.SCRIPT_RULE, self._normalize_script_rule(line)
            
        # 5. 处理CSS规则
        if ADG_CSS.match(line):
            return RuleType.CSS_RULE, self._normalize_css_rule(line)
            
        # 6. 处理元素隐藏规则
        if ADG_COSMETIC.match(line):
            return RuleType.COSMETIC_RULE, self._normalize_cosmetic_rule(line)
            
        # 7. 处理含选项的规则
        if ADG_MODIFIER.match(line) and '$' in line:
            return self._normalize_option_rule(line)
            
        # 8. 处理网络规则
        if ADG_NETWORK.match(line):
            return RuleType.NETWORK_RULE, self._normalize_network_rule(line)
            
        # 9. 处理Hosts规则
        if HOSTS_LINE.match(line):
            return RuleType.HOSTS_RULE, self._normalize_hosts_rule(line)
            
        # 10. 处理标准AdBlock规则
        if ADBLOCK_DOMAIN.match(line) or PURE_DOMAIN.match(line):
            return RuleType.STANDARD_RULE, self._normalize_standard_rule(line)
            
        # 11. 未知规则（保留但标准化）
        return RuleType.UNKNOWN, self._normalize_unknown_rule(line)

    def _normalize_exception_rule(self, line: str) -> Tuple[RuleType, str]:
        """标准化例外规则"""
        # 移除@@前缀，标准化剩余部分
        normalized = self._normalize_domain_part(line[2:])
        return RuleType.EXCEPTION_RULE, f"@@{normalized}" if normalized else line

    def _normalize_ip_rule(self, line: str) -> Tuple[RuleType, str]:
        """标准化IP规则"""
        try:
            ip_type, rest = line.split(':', 1)
            ip_range, action = rest.split(',', 1)
            ip_type = ip_type.upper()
            action = action.strip().lower()
            action = OPTION_EQUIVALENTS.get(action, action)
            normalized = f"{ip_type}:{ip_range.strip()},{action.upper()}"
            return RuleType.IP_RULE, normalized
        except:
            return RuleType.UNKNOWN, line

    def _normalize_dns_rewrite_rule(self, line: str) -> str:
        """标准化DNS重写规则（保持参数顺序）"""
        # 只做最小标准化，保持参数顺序
        return re.sub(r'\s+', ' ', line).strip()

    def _normalize_script_rule(self, line: str) -> str:
        """标准化脚本规则（保持参数顺序）"""
        return re.sub(r'\s+', ' ', line).strip()

    def _normalize_css_rule(self, line: str) -> str:
        """标准化CSS规则"""
        return re.sub(r'\s+', ' ', line).strip()

    def _normalize_cosmetic_rule(self, line: str) -> str:
        """标准化元素隐藏规则"""
        return re.sub(r'\s+', ' ', line).strip()

    def _normalize_option_rule(self, line: str) -> Tuple[RuleType, str]:
        """标准化含选项的规则"""
        try:
            domain_part, opt_part = line.split('$', 1)
            domain_part = self._normalize_domain_part(domain_part)
            if not domain_part:
                return RuleType.UNKNOWN, line
                
            # 标准化选项部分
            opts = [opt.strip() for opt in opt_part.split(',')]
            normalized_opts = self._normalize_options(opts)
            
            normalized = f"{domain_part}${','.join(normalized_opts)}"
            return RuleType.OPTION_RULE, normalized
        except:
            return RuleType.UNKNOWN, line

    def _normalize_network_rule(self, line: str) -> str:
        """标准化网络规则"""
        return self._normalize_domain_part(line)

    def _normalize_hosts_rule(self, line: str) -> str:
        """标准化Hosts规则"""
        match = HOSTS_LINE.match(line)
        if match:
            domain = match.group(2)
            if self._is_valid_domain(domain):
                return f"||{domain}^"
        return line

    def _normalize_standard_rule(self, line: str) -> str:
        """标准化标准AdBlock规则"""
        return self._normalize_domain_part(line)

    def _normalize_unknown_rule(self, line: str) -> str:
        """标准化未知规则（最小处理）"""
        return re.sub(r'\s+', ' ', line).strip()

    def _normalize_domain_part(self, domain_part: str) -> str:
        """标准化域名部分"""
        domain = domain_part.strip()
        if not domain:
            return ""
            
        # 移除协议前缀
        domain = re.sub(r'^https?://', '', domain)
        # 统一通配符格式
        domain = re.sub(r'^\*\.', '||', domain)
        # 统一域名后缀
        domain = re.sub(r'\|$', '^', domain)
        # 确保开头统一
        if domain.startswith('|') and not domain.startswith('||'):
            domain = f"|{domain}"
        # 移除多余通配符
        domain = re.sub(r'\*+', '*', domain)
        
        return domain if self._is_valid_domain(domain.lstrip('|@')) else ""

    def _normalize_options(self, options: List[str]) -> List[str]:
        """标准化选项（关键选项保持顺序）"""
        normalized_opts = []
        key_opts = []
        other_opts = []
        
        for opt in options:
            if '=' in opt:
                k, v = opt.split('=', 1)
                k = k.lower().strip()
                v = v.strip()
                
                # 处理等价选项
                if k in ['action', 'type']:
                    v = OPTION_EQUIVALENTS.get(v.lower(), v)
                
                normalized_opt = f"{k}={v}"
                
                # 分离关键选项和非关键选项
                if k in KEY_OPTIONS:
                    key_opts.append(normalized_opt)
                else:
                    other_opts.append(normalized_opt)
            else:
                # 无值选项
                opt = opt.lower().strip()
                if opt in KEY_OPTIONS:
                    key_opts.append(opt)
                else:
                    other_opts.append(opt)
        
        # 关键选项保持原顺序，其他选项排序
        normalized_opts.extend(key_opts)
        other_opts.sort()
        normalized_opts.extend(other_opts)
        
        return normalized_opts

    def _extract_domain(self, rule: str, rule_type: RuleType) -> str:
        """从规则中提取域名"""
        if rule_type in [RuleType.STANDARD_RULE, RuleType.NETWORK_RULE, RuleType.OPTION_RULE, RuleType.EXCEPTION_RULE]:
            # 提取域名部分
            domain_part = rule.split('$')[0] if '$' in rule else rule
            domain_part = re.sub(r'^@@\|{1,2}', '', domain_part)  # 移除例外标记和锚点
            domain_part = re.sub(r'[\^\|\*].*$', '', domain_part)  # 移除修饰符
            
            # 验证并返回域名
            if self._is_valid_domain(domain_part):
                return domain_part
                
        return ""

    def _extract_options(self, rule: str) -> Dict[str, str]:
        """从规则中提取选项"""
        options = {}
        if '$' in rule:
            _, opt_part = rule.split('$', 1)
            for opt in opt_part.split(','):
                opt = opt.strip()
                if '=' in opt:
                    k, v = opt.split('=', 1)
                    options[k.lower()] = v.strip()
                else:
                    options[opt.lower()] = ""
        return options

    def _calculate_priority(self, rule: str, rule_type: RuleType, options: Dict[str, str]) -> int:
        """计算规则优先级"""
        priority = 0
        
        # 基本类型优先级
        if rule_type == RuleType.EXCEPTION_RULE:
            priority = 10  # 例外规则优先级最高
        elif rule_type == RuleType.IP_RULE:
            priority = 20
        elif rule_type == RuleType.DNS_REWRITE_RULE:
            priority = 30
        elif rule_type == RuleType.OPTION_RULE:
            priority = 40
        elif rule_type == RuleType.NETWORK_RULE:
            priority = 50
        elif rule_type == RuleType.STANDARD_RULE:
            priority = 60
        elif rule_type == RuleType.HOSTS_RULE:
            priority = 70
        elif rule_type == RuleType.SCRIPT_RULE:
            priority = 80
        elif rule_type == RuleType.CSS_RULE:
            priority = 90
        elif rule_type == RuleType.COSMETIC_RULE:
            priority = 100
        else:
            priority = 1000
            
        # 根据修饰符调整优先级
        if options:
            for opt in options:
                priority += MODIFIER_PRIORITY.get(opt, MODIFIER_PRIORITY['other'])
                
        return priority

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False

        # 允许通配符域名
        if '*' in domain:
            if domain.strip('*') == '':
                return False
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

        # 验证域名标签
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-_|]{0,61}[a-zA-Z0-9])?$', label):
                return False

        return True

    def _add_rule(self, rule_info: RuleInfo):
        """添加规则到唯一集合"""
        rule_hash = self._calculate_rule_hash(rule_info)
        
        # 使用布隆过滤器预检查
        if rule_hash in self.bloom_filter:
            # 可能重复，需要精确检查
            if rule_hash in self.unique_rules:
                self.stats['duplicates_removed'] += 1
                return
        
        # 添加到布隆过滤器和唯一规则集
        self.bloom_filter.add(rule_hash)
        self.unique_rules[rule_hash] = rule_info
        
        # 更新统计
        rule_type_name = self.rule_types[rule_info.rule_type].replace(' ', '_').lower()
        self.stats[rule_type_name] += 1

    def _calculate_rule_hash(self, rule_info: RuleInfo) -> int:
        """计算规则哈希（使用xxhash提高性能）"""
        # 使用xxhash代替标准哈希库
        h = xxhash.xxh64()
        h.update(rule_info.normalized.encode('utf-8'))
        h.update(HASH_SALT.encode('utf-8'))
        return h.intdigest()

    def _write_output(self):
        """写入输出文件（分类排序）"""
        def rule_sort_key(rule_info: RuleInfo) -> Tuple[int, str]:
            # 按优先级和规则内容排序
            return (rule_info.priority, rule_info.normalized)

        sorted_rules = sorted(self.unique_rules.values(), key=rule_sort_key)

        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('! 合并广告过滤规则（支持AdBlock/AdGuard/AdGuard Home全语法）\n')
            f.write('! 生成时间: ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            f.write('! 规则总数: ' + str(len(sorted_rules)) + '\n')
            f.write('! 去重数量: ' + str(self.stats['duplicates_removed']) + '\n')
            
            # 输出各类型规则统计
            for rule_type, count in self.stats.items():
                if count > 0 and rule_type != 'duplicates_removed':
                    f.write(f'! {rule_type.replace("_", " ")}: {count}\n')
            
            f.write('!\n')
            
            # 写入规则
            for rule_info in sorted_rules:
                f.write(rule_info.normalized + '\n')
                
        logger.info(f"已写入合并规则: {OUTPUT_FILE}")


if __name__ == '__main__':
    try:
        # 确保必要的库可用
        try:
            import chardet
        except ImportError:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])
            import chardet
            
        try:
            import xxhash
        except ImportError:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "xxhash"])
            import xxhash

        merger = AdblockMerger()
        merger.run()
        sys.exit(0)
    except Exception as e:
        logger.error(f"执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)