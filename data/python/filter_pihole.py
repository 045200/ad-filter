#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import hashlib
import sys
from pathlib import Path

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_pihole.txt"
OUTPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_pihole.txt"

DOMAIN_PATTERN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
WHITELIST_PATTERN = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)

def extract_domain_from_rule(rule):
    """从AdGuard规则中提取域名[citation:4]"""
    if rule.startswith('@@'):
        clean_rule = rule[2:]
    else:
        clean_rule = rule

    domain_match = DOMAIN_PATTERN.match(clean_rule)
    if domain_match:
        return clean_rule.strip('||^')
    return None

def process_file(input_path, is_allow=False):
    """处理输入文件，提取Pi-hole兼容的域名规则[citation:4]"""
    output_rules = []
    seen_domains = set()
    if not input_path.exists():
        print(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    continue

                domain = extract_domain_from_rule(line)
                if domain and domain not in seen_domains:
                    if is_allow:
                        output_rules.append(f"@@{domain}")
                    else:
                        output_rules.append(domain)
                    seen_domains.add(domain)
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
        print(f"Pi-hole 规则转换完成。拦截: {len(block_rules)} 条, 允许: {len(allow_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())