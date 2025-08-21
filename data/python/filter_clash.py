#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path
from typing import Set
from datetime import datetime


# 基础配置（仅处理黑名单，输出YAML）
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"


# 预编译正则表达式
ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|\$.*)?$')
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
DOMAIN_ONLY = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
URL_RULE = re.compile(r'^https?://[^\s]+$')
WILDCARD_RULE = re.compile(r'^\*[^*]+\*$')
ELEMENT_HIDING = re.compile(r'^.*##[^#]+$')
ADBLOCK_WHITELIST = re.compile(r'^@@')


# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}


def github_log(message: str, level: str = "notice") -> None:
    """输出符合GitHub Actions规范的日志"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if level == "notice":
        print(f"[{timestamp}] ::notice:: {message}")
    elif level == "error":
        print(f"[{timestamp}] ::error:: {message}")
    elif level == "warning":
        print(f"[{timestamp}] ::warning:: {message}")


class AdBlockToYAMLConverter:
    """仅转换黑名单规则为目标YAML格式（+.域名）"""

    def __init__(self):
        self.blacklist_rules = set()  # 黑名单规则集
        self.rejected_count = 0  # 被拒绝的规则数
        self.stats = {
            "total": 0,
            "converted": 0,
            "skipped_whitelist": 0,
            "skipped_element": 0
        }

    def process_file(self) -> Set[str]:
        """处理输入文件，提取并转换黑名单规则"""
        if not INPUT_FILE.exists():
            github_log(f"输入文件不存在: {INPUT_FILE}", "error")
            sys.exit(1)

        try:
            with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    self.stats["total"] += 1

                    # 跳过非黑名单规则
                    skip_reason = self._should_skip(line)
                    if skip_reason:
                        if skip_reason == "whitelist":
                            self.stats["skipped_whitelist"] += 1
                        elif skip_reason == "element":
                            self.stats["skipped_element"] += 1
                        continue

                    # 处理黑名单规则
                    self._process_line(line)

            github_log(
                f"规则处理完成 - 总规则: {self.stats['total']}, "
                f"转换成功: {self.stats['converted']}, "
                f"被拒绝: {self.rejected_count}"
            )
            return self.blacklist_rules

        except Exception as e:
            github_log(f"文件处理失败: {str(e)}", "error")
            sys.exit(1)

    def _should_skip(self, line: str) -> str:
        """判断是否跳过当前行，返回跳过原因（空字符串表示不跳过）"""
        if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
            return "empty/comment"
        if ADBLOCK_WHITELIST.match(line):
            return "whitelist"
        if ELEMENT_HIDING.match(line):
            return "element"
        return ""

    def _process_line(self, line: str):
        """处理单行黑名单规则，转换为 +.域名 格式"""
        try:
            # 处理AdBlock标准规则（||domain.com）
            if ADBLOCK_DOMAIN.match(line):
                domain = ADBLOCK_DOMAIN.match(line).group(1)
                if self._is_valid_domain(domain):
                    self.blacklist_rules.add(f"+.{domain}")
                    self.stats["converted"] += 1
                else:
                    self.rejected_count += 1
                return

            # 处理Hosts规则（0.0.0.0 domain.com）
            if HOSTS_RULE.match(line):
                domain = HOSTS_RULE.match(line).group(2)
                if self._is_valid_domain(domain):
                    self.blacklist_rules.add(f"+.{domain}")
                    self.stats["converted"] += 1
                else:
                    self.rejected_count += 1
                return

            # 处理URL规则（https://domain.com）
            if URL_RULE.match(line):
                domain_match = re.search(r'://([^/]+)', line)
                if domain_match:
                    domain = domain_match.group(1).split(':')[0]  # 移除端口
                    if self._is_valid_domain(domain):
                        self.blacklist_rules.add(f"+.{domain}")
                        self.stats["converted"] += 1
                    else:
                        self.rejected_count += 1
                else:
                    self.rejected_count += 1
                return

            # 处理纯域名（domain.com）
            if DOMAIN_ONLY.match(line) and self._is_valid_domain(line):
                self.blacklist_rules.add(f"+.{line}")
                self.stats["converted"] += 1
                return

            # 处理通配符规则（*domain.com*）
            if WILDCARD_RULE.match(line):
                domain = re.sub(r'\*', '', line)  # 移除通配符
                if self._is_valid_domain(domain):
                    self.blacklist_rules.add(f"+.{domain}")
                    self.stats["converted"] += 1
                else:
                    self.rejected_count += 1
                return

            # 无法识别的规则格式
            self.rejected_count += 1

        except Exception:
            self.rejected_count += 1

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False
        if len(domain) > 253:
            return False
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        # 校验域名各部分格式
        return all(re.match(r'^[a-zA-Z0-9-]+$', part) for part in parts[:-1]) and re.match(r'^[a-zA-Z]+$', parts[-1])

    def write_output(self):
        """写入YAML输出文件"""
        if not self.blacklist_rules:
            github_log("无有效规则可输出", "error")
            sys.exit(1)

        # 排序规则并写入
        sorted_rules = sorted(self.blacklist_rules)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in sorted_rules:
                f.write(f"  - '{rule}'\n")

        github_log(f"成功生成 {len(sorted_rules)} 条规则到 {OUTPUT_FILE}")


def main():
    """主函数"""
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 处理规则并输出
    converter = AdBlockToYAMLConverter()
    converter.process_file()
    converter.write_output()

    github_log("黑名单规则转换完成")


if __name__ == '__main__':
    main()
