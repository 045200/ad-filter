#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import hashlib
from pathlib import Path

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_ubo.txt"
OUTPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_ubo.txt"

# uBlock Origin 不支持的修饰符 (相比AdGuard)
UBO_UNSUPPORTED_MODIFIERS = {'$dnsrewrite', '$cname', '$client', '$dnstype', '$denyallow', '$ctag', '$badfilter', '$redirect', '$removeheader', '$removeparam', '$app'}

def convert_to_ubo_format(rule, is_allow=False):
    """将AdGuard规则转换为uBlock Origin格式[citation:2]"""
    if rule.strip().startswith(('!', '#')) or not rule.strip():
        return rule

    for modifier in UBO_UNSUPPORTED_MODIFIERS:
        if modifier in rule:
            return None

    return rule

def process_file(input_path, is_allow=False):
    """处理输入文件，生成uBlock Origin规则[citation:2]"""
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

                converted_rule = convert_to_ubo_format(line, is_allow)
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
        print(f"uBlock Origin 规则转换完成。拦截: {len(block_rules)} 条, 允许: {len(allow_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())