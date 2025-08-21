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
from collections import defaultdict
from typing import List, Optional, Callable
from concurrent.futures import ProcessPoolExecutor, as_completed

# 配置日志（适配GitHub Action）
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',  # 简化格式，GitHub会自动添加时间
    stream=sys.stdout  # 确保日志输出到stdout，GitHub Action能捕获
)
logger = logging.getLogger(__name__)

# 读取GitHub环境变量（用于日志标记）
GITHUB_RUN_ID = os.getenv('GITHUB_RUN_ID', 'unknown-run')
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = TEMP_DIR / "adblock_filter.txt"

MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
INPUT_PATTERNS = ["adblock*.txt", "allow*.txt", "hosts*", "adg*.txt", "adh*.txt", "filter*.txt"]
HASH_SALT = "adblock_salt_2024_v5"

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
        # 确保临时目录存在
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.input_files: List[Path] = []
        self.file_hashes: set[str] = set()
        self.unique_rules: dict[int, str] = {}  # 用普通字典替代OrderedDict
        self.rule_counters: defaultdict[str, int] = defaultdict(int)
        # 规则归一化方法映射（确保调用与定义一致）
        self._normalize_map: dict[str, Callable[[str], str]] = {
            "exception": self._normalize_exception_rule,
            "ip": self._normalize_ip_rule,
            "dns_rewrite": self._normalize_dns_rewrite_rule,
            "script": self._normalize_script_rule,
            "css": self._normalize_css_rule,
            "cosmetic": self._normalize_cosmetic_rule,
            "option": self._normalize_option_rule,
            "network": self._normalize_network_rule,
            "hosts": self._normalize_hosts_rule,
            "standard": self._normalize_standard_rule,
        }

    def run(self) -> None:
        """主运行方法"""
        start_time = time.time()
        self._discover_input_files()

        if not self.input_files:
            logger.warning(f"[Run {GITHUB_RUN_ID}] 未找到有效规则文件（匹配模式：{INPUT_PATTERNS}）")
            return

        logger.info(f"[Run {GITHUB_RUN_ID}] 发现规则文件: {len(self.input_files)} 个，开始处理...")
        self._process_files_parallel()

        elapsed = time.time() - start_time
        logger.info(
            f"[Run {GITHUB_RUN_ID}] 合并完成 | "
            f"处理文件: {len(self.input_files)} | "
            f"去重后规则数: {len(self.unique_rules)} | "
            f"耗时: {elapsed:.2f}s"
        )

        self._write_output()

    def _discover_input_files(self) -> None:
        """发现输入文件（去重）"""
        for pattern in INPUT_PATTERNS:
            for file_path in TEMP_DIR.glob(pattern):
                if file_path == OUTPUT_FILE or not file_path.is_file():
                    continue

                file_hash = self._calculate_file_hash(file_path)
                if file_hash in self.file_hashes:
                    logger.debug(f"[Run {GITHUB_RUN_ID}] 跳过重复文件: {file_path}")
                    continue

                self.file_hashes.add(file_hash)
                self.input_files.append(file_path)

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值（用于去重）"""
        try:
            hasher = xxhash.xxh64()
            with open(file_path, 'rb') as f:
                # 读取文件头部和大小作为哈希依据（避免全量读取大文件）
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
            return hasher.hexdigest()
        except IOError as e:
            logger.error(f"[Run {GITHUB_RUN_ID}] 计算文件哈希失败 {file_path}: {e}")
            return str(file_path)  # 失败时用路径作为哈希（仅作保底）

    def _process_files_parallel(self) -> None:
        """并行处理文件（适配GitHub Action资源限制）"""
        try:
            with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_file = {executor.submit(self._process_file, fp): fp for fp in self.input_files}

                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_rules = future.result()
                        for rule in file_rules:
                            self._add_rule(rule)
                        logger.debug(f"[Run {GITHUB_RUN_ID}] 完成处理文件: {file_path}（规则数：{len(file_rules)}）")
                    except UnicodeDecodeError as e:
                        logger.error(f"[Run {GITHUB_RUN_ID}] 文件编码错误 {file_path}: {e}")
                    except Exception as e:
                        logger.error(f"[Run {GITHUB_RUN_ID}] 处理文件失败 {file_path}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"[Run {GITHUB_RUN_ID}] 线程池初始化失败: {e}")

    def _process_file(self, file_path: Path) -> List[str]:
        """处理单个文件，返回归一化后的规则列表"""
        rules: List[str] = []
        encoding = detect_encoding(file_path)

        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or COMMENT.match(line) or EMPTY_LINE.match(line):
                        continue

                    try:
                        rule = self._parse_line(line)
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        logger.warning(
                            f"[Run {GITHUB_RUN_ID}] 解析规则失败（{file_path}:{line_num}）: "
                            f"内容={line[:50]}... | 错误={e}"
                        )
        except IOError as e:
            logger.error(f"[Run {GITHUB_RUN_ID}] 读取文件失败 {file_path}: {e}")

        return rules

    def _parse_line(self, line: str) -> Optional[str]:
        """解析单行规则并归一化"""
        # 移除行内注释
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        if '!' in line:
            line = line.split('!', 1)[0].strip()
        if not line:
            return None

        # 分类并归一化规则（基于映射表确保方法存在）
        if ADB_EXCEPTION.match(line):
            return self._normalize_map["exception"](line)
        elif ADH_IP_RULE.match(line):
            return self._normalize_map["ip"](line)
        elif ADG_DNSREWRITE.search(line):
            return self._normalize_map["dns_rewrite"](line)
        elif ADG_SCRIPTLET.search(line):
            return self._normalize_map["script"](line)
        elif ADG_CSS.match(line):
            return self._normalize_map["css"](line)
        elif ADG_COSMETIC.match(line):
            return self._normalize_map["cosmetic"](line)
        elif ADG_MODIFIER.match(line) and '$' in line:
            return self._normalize_map["option"](line)
        elif ADG_NETWORK.match(line):
            return self._normalize_map["network"](line)
        elif HOSTS_LINE.match(line):
            return self._normalize_map["hosts"](line)
        else:
            return self._normalize_map["standard"](line)

    def _normalize_domain_part(self, domain_part: str) -> str:
        """标准化域名部分（通用逻辑）"""
        domain = domain_part.strip()
        if not domain:
            return ""

        domain = re.sub(r'^https?://', '', domain)  # 移除协议头
        domain = re.sub(r'^\*\.', '||', domain)      # 转换*.domain为||domain
        domain = re.sub(r'\|$', '^', domain)         # 转换domain|为domain^
        domain = re.sub(r'\*+', '*', domain)         # 合并连续星号
        return domain

    def _add_rule(self, rule: str) -> None:
        """添加规则到去重集合"""
        rule_hash = xxhash.xxh3_64(rule + HASH_SALT).intdigest()
        if rule_hash not in self.unique_rules:
            self.unique_rules[rule_hash] = rule
            rule_type = self._classify_rule(rule)
            self.rule_counters[rule_type] += 1

    def _classify_rule(self, rule: str) -> str:
        """规则分类（用于统计）"""
        if rule.startswith('@@'):
            return "exception_rules"
        elif rule.startswith(('IP-CIDR', 'IP-CIDR6')):
            return "ip_rules"
        elif '$dnsrewrite=' in rule:
            return "dns_rewrite_rules"
        elif '##+js(' in rule or '#%#//scriptlet(' in rule:
            return "script_rules"
        elif rule.startswith(('##', '#@#')):
            return "cosmetic_rules"
        elif '$' in rule:
            return "option_rules"
        elif rule.startswith('||'):
            return "network_rules"
        else:
            return "standard_rules"

    def _write_output(self) -> None:
        """写入合并结果（适配GitHub Action输出路径）"""
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(f'! 合并广告过滤规则（GitHub Run ID: {GITHUB_RUN_ID}）\n')
                f.write(f'! 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}\n')
                f.write(f'! 规则总数: {len(self.unique_rules)}\n')

                for rule_type, count in self.rule_counters.items():
                    f.write(f'! {rule_type}: {count}\n')

                f.write('!\n')
                for rule in self.unique_rules.values():
                    f.write(rule + '\n')

            logger.info(f"[Run {GITHUB_RUN_ID}] 已写入合并规则: {OUTPUT_FILE}（大小：{OUTPUT_FILE.stat().st_size//1024}KB）")
        except IOError as e:
            logger.error(f"[Run {GITHUB_RUN_ID}] 写入输出文件失败 {OUTPUT_FILE}: {e}")
            sys.exit(1)

    # 规则归一化方法（完整实现）
    def _normalize_exception_rule(self, rule: str) -> str:
        """标准化例外规则（@@开头）"""
        return self._normalize_domain_part(rule)

    def _normalize_ip_rule(self, rule: str) -> str:
        """标准化IP规则（IP-CIDR/IP-CIDR6）"""
        return rule.strip().upper()  # 统一大写格式（如IP-CIDR而非ip-cidr）

    def _normalize_dns_rewrite_rule(self, rule: str) -> str:
        """标准化DNS重写规则"""
        return rule.strip()

    def _normalize_script_rule(self, rule: str) -> str:
        """标准化脚本规则（scriptlet）"""
        return rule.strip()

    def _normalize_css_rule(self, rule: str) -> str:
        """标准化CSS规则"""
        return rule.strip()

    def _normalize_cosmetic_rule(self, rule: str) -> str:
        """标准化美化规则"""
        return rule.strip()

    def _normalize_option_rule(self, rule: str) -> str:
        """标准化带选项的规则（含$）"""
        return rule.strip()

    def _normalize_network_rule(self, rule: str) -> str:
        """标准化网络规则（||开头）"""
        return self._normalize_domain_part(rule)

    def _normalize_hosts_rule(self, rule: str) -> str:
        """将hosts规则转换为adblock格式（||domain^）"""
        match = HOSTS_LINE.match(rule)
        if match:
            domain = match.group(2)
            return f"||{domain}^"
        return self._normalize_standard_rule(rule)

    def _normalize_standard_rule(self, rule: str) -> str:
        """标准化标准规则"""
        return self._normalize_domain_part(rule)


def detect_encoding(file_path: Path) -> str:
    """检测文件编码（适配多编码场景）"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)  # 读取前4KB检测编码
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
            # 修正常见编码误判
            if encoding in ['ISO-8859-1', 'Windows-1252']:
                return 'utf-8'
            return encoding
    except IOError as e:
        logger.warning(f"[Run {GITHUB_RUN_ID}] 检测编码失败 {file_path}: {e}，使用默认utf-8")
        return 'utf-8'


if __name__ == '__main__':
    try:
        AdblockMerger().run()
        sys.exit(0)
    except Exception as e:
        logger.error(f"[Run {GITHUB_RUN_ID}] 执行失败: {e}", exc_info=True)
        sys.exit(1)
