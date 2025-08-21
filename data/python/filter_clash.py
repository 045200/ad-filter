#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path
from typing import Set
from datetime import datetime


# 基础配置（仅处理基础黑名单规则）
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"


# 预编译正则表达式（仅匹配基础语法）
# 1. AdBlock/AdGuard基础域名规则（||domain.com 或 ||domain.com^，无复杂选项）
ADBLOCK_BASE = re.compile(r'^\|\|([\w.-]+)(\^)?$')  # 仅支持||domain.com或||domain.com^
# 2. 基础Hosts规则（IP + 域名，无注释或复杂格式）
HOSTS_BASE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
# 3. 纯域名（直接域名，无通配符或修饰符）
PURE_DOMAIN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
# 4. 简单通配符（仅首尾*，如*domain.com或domain.com*或*domain.com*）
SIMPLE_WILDCARD = re.compile(r'^\*?([\w.-]+)\*?$')  # 排除中间含*的复杂通配符

# 排除规则（非基础语法）
COMMENT = re.compile(r'^[!#]')  # 注释行
EMPTY_LINE = re.compile(r'^\s*$')  # 空行
WHITELIST = re.compile(r'^@@')  # 白名单（@@开头）
ADVANCED_OPTIONS = re.compile(r'\$')  # 含$选项的复杂规则（排除）
ELEMENT_RULE = re.compile(r'##')  # 元素隐藏规则（排除）
URL_RULE = re.compile(r'^https?://')  # URL完整路径规则（非基础域名规则，排除）


# 域名黑名单（无效/保留域名）
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


class BasicAdBlockConverter:
    """仅转换AdBlock/AdGuard/AdGuard Home的基础域名规则"""

    def __init__(self):
        self.blacklist = set()  # 基础规则集（+.域名格式）
        self.stats = {
            "total": 0,  # 总处理行数
            "converted": 0,  # 成功转换的基础规则
            "skipped_whitelist": 0,  # 跳过的白名单
            "skipped_advanced": 0,  # 跳过的高级规则（非基础语法）
            "invalid": 0  # 无效域名规则
        }

    def process_file(self) -> Set[str]:
        """处理输入文件，仅提取基础规则"""
        if not INPUT_FILE.exists():
            github_log(f"输入文件不存在: {INPUT_FILE}", "error")
            sys.exit(1)

        try:
            with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    self.stats["total"] += 1
                    self._process_line(line)

            github_log(
                f"基础规则处理统计 - 总行数: {self.stats['total']}, "
                f"转换成功: {self.stats['converted']}, "
                f"跳过高级规则: {self.stats['skipped_advanced']}, "
                f"无效规则: {self.stats['invalid']}"
            )
            return self.blacklist

        except Exception as e:
            github_log(f"文件处理失败: {str(e)}", "error")
            sys.exit(1)

    def _process_line(self, line: str):
        """仅处理基础语法规则，跳过高级/复杂规则"""
        # 跳过注释、空行、白名单
        if not line:
            return
        if COMMENT.match(line) or EMPTY_LINE.match(line):
            return
        if WHITELIST.match(line):
            self.stats["skipped_whitelist"] += 1
            return

        # 跳过高级规则（含选项、元素隐藏、URL路径等）
        if ADVANCED_OPTIONS.search(line) or ELEMENT_RULE.search(line) or URL_RULE.match(line):
            self.stats["skipped_advanced"] += 1
            return

        # 1. 处理AdBlock/AdGuard基础规则（||domain.com 或 ||domain.com^）
        if ADBLOCK_BASE.match(line):
            domain = ADBLOCK_BASE.match(line).group(1)
            if self._is_valid_domain(domain):
                self.blacklist.add(f"+.{domain}")
                self.stats["converted"] += 1
            else:
                self.stats["invalid"] += 1
            return

        # 2. 处理Hosts基础规则（IP + 域名）
        if HOSTS_BASE.match(line):
            domain = HOSTS_BASE.match(line).group(2)
            if self._is_valid_domain(domain):
                self.blacklist.add(f"+.{domain}")
                self.stats["converted"] += 1
            else:
                self.stats["invalid"] += 1
            return

        # 3. 处理纯域名（直接域名，无修饰）
        if PURE_DOMAIN.match(line):
            if self._is_valid_domain(line):
                self.blacklist.add(f"+.{line}")
                self.stats["converted"] += 1
            else:
                self.stats["invalid"] += 1
            return

        # 4. 处理简单通配符（仅首尾*，如*domain.com → domain.com）
        if SIMPLE_WILDCARD.match(line):
            domain = SIMPLE_WILDCARD.match(line).group(1)  # 移除首尾*
            if self._is_valid_domain(domain):
                self.blacklist.add(f"+.{domain}")
                self.stats["converted"] += 1
            else:
                self.stats["invalid"] += 1
            return

        # 未匹配的规则（非基础语法）
        self.stats["skipped_advanced"] += 1

    def _is_valid_domain(self, domain: str) -> bool:
        """验证基础域名有效性（符合AdBlock/AdGuard基础规范）"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False
        if len(domain) > 253:  # 域名最大长度限制
            return False
        # 拆分域名部分（至少2部分，如example.com）
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        # 基础域名格式校验（仅字母、数字、连字符，无特殊字符）
        return all(
            re.match(r'^[a-zA-Z0-9-]+$', part) and part[0] != '-' and part[-1] != '-'
            for part in parts
        )

    def write_output(self):
        """写入基础规则YAML文件"""
        if not self.blacklist:
            github_log("无有效基础规则可输出", "error")
            sys.exit(1)

        # 排序并去重（基础规则天然去重）
        sorted_rules = sorted(self.blacklist)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for rule in sorted_rules:
                f.write(f"  - '{rule}'\n")

        github_log(f"成功生成 {len(sorted_rules)} 条基础规则到 {OUTPUT_FILE}")


def main():
    """主函数"""
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    converter = BasicAdBlockConverter()
    converter.process_file()
    converter.write_output()

    github_log("AdBlock/AdGuard基础规则转换完成")


if __name__ == '__main__':
    main()
