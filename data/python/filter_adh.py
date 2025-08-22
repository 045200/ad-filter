#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import hashlib
from pathlib import Path

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adh.txt"
OUTPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adh.txt"

# AdGuard Home 支持的修饰符 (DNS过滤层面)[citation:1]
SUPPORTED_MODIFIERS = {'$important', '~third-party', '$third-party', '$domain', '$client', '$dnstype', '$ctag', '$badfilter'}
# 不支持的元素 (如元素隐藏、页面脚本规则)
UNSUPPORTED_ELEMENTS = {'##', '#@#', '#%#', '#$#'}
# 不支持的重定向和移除类修饰符
UNSUPPORTED_ACTIONS = {'$removeparam', '$removeheader', '$redirect', '$csp', '$replace'}

def is_compatible(rule):
    """检查规则是否与AdGuard Home兼容[citation:1]"""
    if any(element in rule for element in UNSUPPORTED_ELEMENTS):
        return False
    for action in UNSUPPORTED_ACTIONS:
        if action in rule:
            return False
    return True

def convert_rule(rule, is_allow=False):
    """转换单条规则（此处主要进行过滤，AdGuard Home兼容AdGuard语法[citation:1]）"""
    if not is_compatible(rule):
        return None
    return rule

def process_file(input_path, is_allow=False):
    """处理输入文件"""
    output_rules = []
    seen_hashes = set()
    if not input_path.exists():
        print(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    output_rules.append(line)
                    continue

                converted_rule = convert_rule(line, is_allow)
                if converted_rule is None:
                    continue

                rule_hash = hashlib.md5(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    output_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    except Exception as e:
        print(f"处理文件 {input_path} 时出错: {e}")
    return output_rules

def main():
    block_rules = process_file(INPUT_BLOCK, is_allow=False)
    allow_rules = process_file(INPUT_ALLOW, is_allow=True)

    try:
        with open(OUTPUT_BLOCK, 'w', encoding='utf-8') as f:
            f.write('\n'.join(block_rules) + '\n')
        with open(OUTPUT_ALLOW, 'w', encoding='utf-8') as f:
            f.write('\n'.join(allow_rules) + '\n')
        print(f"AdGuard Home 规则转换完成。拦截: {len(block_rules)} 条, 允许: {len(allow_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())