#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path
from typing import Tuple, List, Set


# 配置参数
INPUT_FILE = Path(os.getenv("INPUT_FILE", "adblock_merged.txt"))
BLACKLIST_OUTPUT = Path(os.getenv("BLACKLIST_OUTPUT", "adblock_adg.txt"))
WHITELIST_OUTPUT = Path(os.getenv("WHITELIST_OUTPUT", "allow_adg.txt"))

# 原生支持的规则模式
SUPPORTED = [
    re.compile(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^?(\$[a-z0-9_,=;]+)?$', re.IGNORECASE),
    re.compile(r'^([a-z0-9-]+\.)+[a-z]{2,}##.+$', re.IGNORECASE),
    re.compile(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^?(\$[a-z0-9_,=;]+)?$', re.IGNORECASE)
]

# 转换规则
CONVERT = {
    'hosts': lambda d: f"||{d}^",
    'plain': lambda d: f"||{d}^",
    'wildcard': lambda d: f"||{d}^"
}

# 忽略模式
IGNORE = [re.compile(r'^[!#]'), re.compile(r'^\s*$')]


class Converter:
    def __init__(self):
        self.black = set()
        self.white = set()
        self.total = 0

    def run(self):
        if not INPUT_FILE.exists():
            print(f"错误：输入文件不存在 {INPUT_FILE}", file=sys.stderr)
            return

        # 处理规则
        black, white = self._process()

        # 写入结果
        with open(BLACKLIST_OUTPUT, 'w') as f:
            f.write('\n'.join(black))
        with open(WHITELIST_OUTPUT, 'w') as f:
            f.write('\n'.join(white))

        print(f"处理完成 | 黑名单: {len(black)} 条 | 白名单: {len(white)} 条")

    def _process(self) -> Tuple[List[str], List[str]]:
        black = []
        white = []
        with open(INPUT_FILE, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                self.total += 1
                rule, is_white = self._parse(line)
                if not rule:
                    continue
                if is_white:
                    if rule not in self.white:
                        white.append(rule)
                        self.white.add(rule)
                else:
                    if rule not in self.black:
                        black.append(rule)
                        self.black.add(rule)
        return black, white

    def _parse(self, line: str) -> Tuple[str, bool]:
        # 忽略注释/空行
        if any(p.match(line) for p in IGNORE):
            return "", False

        # 白名单标记
        is_white = line.startswith('@@')

        # 原生支持规则
        if any(p.match(line) for p in SUPPORTED):
            return line, is_white

        # 转换处理
        clean = line.lstrip('@')
        # Hosts规则
        m = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9-]+\.)+[a-z]{2,}$', clean, re.I)
        if m and self._valid(m.group(2)):
            rule = CONVERT['hosts'](m.group(2))
        # 纯域名
        elif (m := re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', clean, re.I)) and self._valid(m.group(1)):
            rule = CONVERT['plain'](m.group(1))
        # 简单通配符
        elif (m := re.match(r'^\*?([a-z0-9-]+\.)+[a-z]{2,}\*?$', clean, re.I)) and self._valid(m.group(1).strip('*')):
            rule = CONVERT['wildcard'](m.group(1).strip('*'))
        else:
            return "", False

        # 补全白名单前缀
        if is_white and not rule.startswith('@@'):
            rule = f"@@{rule}"
        return rule, is_white

    def _valid(self, domain: str) -> bool:
        return len(domain) <= 253 and '..' not in domain and not (domain.startswith('.') or domain.endswith('.'))


if __name__ == '__main__':
    try:
        Converter().run()
    except Exception as e:
        print(f"失败: {e}", file=sys.stderr)
        sys.exit(1)
