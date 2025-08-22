#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
from pathlib import Path
# 1. 导入pyyaml库（需提前安装）
import yaml

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_CLASH = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
OUTPUT_SURGE = Path(GITHUB_WORKSPACE) / "adblock_surge.conf"

# 正则表达式部分保持不变
DOMAIN_PATTERN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
IP_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
REGEX_PATTERN = re.compile(r'^\/([^\/]+)\/$')

# convert_to_clash_format、convert_to_surge_format、process_file 函数完全保持不变
def convert_to_clash_format(rule, is_allow=False):
    rules = []
    is_exception = rule.startswith('@@')
    clean_rule = rule[2:] if is_exception else rule

    domain_match = DOMAIN_PATTERN.match(clean_rule)
    if domain_match:
        domain = clean_rule.strip('||^')
        action = 'DIRECT' if (is_allow or is_exception) else 'REJECT'
        rules.append(f"DOMAIN-SUFFIX,{domain},{action}")
        rules.append(f"DOMAIN,{domain},{action}")

    ip_match = IP_PATTERN.match(clean_rule)
    if ip_match:
        ip = ip_match.group(1)
        action = 'DIRECT' if (is_allow or is_exception) else 'REJECT'
        rules.append(f"IP-CIDR,{ip},{action}")

    regex_match = REGEX_PATTERN.match(clean_rule)
    if regex_match:
        keyword = regex_match.group(1)
        action = 'DIRECT' if (is_allow or is_exception) else 'REJECT'
        rules.append(f"DOMAIN-KEYWORD,{keyword},{action}")

    return rules

def convert_to_surge_format(rule, is_allow=False):
    if rule.startswith('@@'):
        clean_rule = rule[2:]
        is_exception = True
    else:
        clean_rule = rule
        is_exception = False

    domain_match = DOMAIN_PATTERN.match(clean_rule)
    if domain_match:
        domain = clean_rule.strip('||^')
        action = 'DIRECT' if (is_allow or is_exception) else 'REJECT'
        return f"DOMAIN-SUFFIX,{domain},{action}"
    return None

def process_file(input_path, is_allow=False, convert_func=None):
    output_rules = []
    seen_rules = set()
    if not input_path.exists():
        print(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    continue

                converted_rules = convert_func(line, is_allow)
                for rule in converted_rules:
                    if rule and rule not in seen_rules:
                        output_rules.append(rule)
                        seen_rules.add(rule)
    except Exception as e:
        print(f"处理文件 {input_path} 时出错: {e}")
    return output_rules

def main():
    # 规则处理逻辑保持不变（生成Clash/Surge规则列表）
    clash_rules = []
    clash_rules += process_file(INPUT_BLOCK, is_allow=False, convert_func=convert_to_clash_format)
    clash_rules += process_file(INPUT_ALLOW, is_allow=True, convert_func=convert_to_clash_format)

    surge_rules = []
    surge_rules += process_file(INPUT_BLOCK, is_allow=False, convert_func=convert_to_surge_format)
    surge_rules += process_file(INPUT_ALLOW, is_allow=True, convert_func=convert_to_surge_format)

    try:
        # 2. 用pyyaml生成标准YAML（替代手动拼接"payload:"头）
        with open(OUTPUT_CLASH, 'w', encoding='utf-8') as f:
            # 构建YAML字典结构（key为"payload"，value为规则列表）
            clash_yaml_data = {"payload": clash_rules}
            # 调用yaml.dump生成标准YAML，sort_keys=False确保"payload"键位置不变
            yaml.dump(clash_yaml_data, f, encoding='utf-8', allow_unicode=True, sort_keys=False)

        # Surge文件逻辑保持不变
        with open(OUTPUT_SURGE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(surge_rules) + '\n')

        print(f"规则转换完成。Clash规则: {len(clash_rules)} 条, Surge规则: {len(surge_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
