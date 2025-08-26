#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
from pathlib import Path
import yaml

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_CLASH = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
OUTPUT_SURGE = Path(GITHUB_WORKSPACE) / "adblock_surge.conf"
OUTPUT_ALLOW_CLASH = Path(GITHUB_WORKSPACE) / "allow_clash.txt"

# 正则表达式模式
DOMAIN_PATTERN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
IP_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
REGEX_PATTERN = re.compile(r'^\/([^\/]+)\/$')

def convert_rule(rule, is_allow=False, target_format="clash"):
    """通用规则转换函数"""
    rules = []
    is_exception = rule.startswith('@@')
    clean_rule = rule[2:] if is_exception else rule

    # 确定动作
    action = 'DIRECT' if (is_allow or is_exception) else 'REJECT'

    # 处理域名规则
    domain_match = DOMAIN_PATTERN.match(clean_rule)
    if domain_match:
        domain = clean_rule.strip('||^')
        if target_format == "clash":
            # Clash格式使用'+.'前缀
            rules.append(f"+.{domain}")
        elif target_format == "clash_allow":
            # 白名单Clash格式使用'+.'前缀
            rules.append(f"+.{domain}")
        else:  # surge
            rules.append(f"DOMAIN-SUFFIX,{domain},{action}")

    # 处理IP规则
    ip_match = IP_PATTERN.match(clean_rule)
    if ip_match:
        ip = ip_match.group(1)
        if target_format == "clash":
            rules.append(f"IP-CIDR,{ip},{action}")
        elif target_format == "clash_allow":
            # 白名单Clash格式不处理IP规则
            pass
        else:  # surge
            rules.append(f"IP-CIDR,{ip},{action}")

    # 处理正则表达式规则
    regex_match = REGEX_PATTERN.match(clean_rule)
    if regex_match:
        keyword = regex_match.group(1)
        if target_format == "clash":
            rules.append(f"DOMAIN-KEYWORD,{keyword},{action}")
        elif target_format == "clash_allow":
            # 白名单Clash格式不处理正则表达式规则
            pass
        else:  # surge
            rules.append(f"DOMAIN-KEYWORD,{keyword},{action}")

    return rules

def process_file(input_path, is_allow=False, target_format="clash"):
    """处理输入文件"""
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

                converted_rules = convert_rule(line, is_allow, target_format)
                for rule in converted_rules:
                    if rule and rule not in seen_rules:
                        output_rules.append(rule)
                        seen_rules.add(rule)
    except Exception as e:
        print(f"处理文件 {input_path} 时出错: {e}")

    return output_rules

def main():
    # 处理Clash规则
    clash_rules = []
    clash_rules += process_file(INPUT_BLOCK, is_allow=False, target_format="clash")
    clash_rules += process_file(INPUT_ALLOW, is_allow=True, target_format="clash")

    # 处理Surge规则
    surge_rules = []
    surge_rules += process_file(INPUT_BLOCK, is_allow=False, target_format="surge")
    surge_rules += process_file(INPUT_ALLOW, is_allow=True, target_format="surge")
    
    # 处理白名单Clash规则
    allow_clash_rules = process_file(INPUT_ALLOW, is_allow=True, target_format="clash_allow")

    try:
        # 生成Clash YAML配置
        with open(OUTPUT_CLASH, 'w', encoding='utf-8') as f:
            clash_yaml_data = {"payload": clash_rules}
            yaml.dump(clash_yaml_data, f, encoding='utf-8', allow_unicode=True, sort_keys=False)

        # 生成Surge配置
        with open(OUTPUT_SURGE, 'w', encoding='utf-8') as f:
            f.write("[Rule]\n")
            f.write('\n'.join(surge_rules) + '\n')
            f.write("FINAL,DIRECT\n")  # Surge需要FINAL规则
            
        # 生成白名单Clash配置
        with open(OUTPUT_ALLOW_CLASH, 'w', encoding='utf-8') as f:
            f.write('\n'.join(allow_clash_rules) + '\n')

        print(f"规则转换完成。Clash规则: {len(clash_rules)} 条, Surge规则: {len(surge_rules)} 条, 白名单Clash规则: {len(allow_clash_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())