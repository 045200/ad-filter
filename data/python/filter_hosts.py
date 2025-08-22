#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
from pathlib import Path

# 路径配置（可根据实际需求修改）
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_AGH = Path(GITHUB_WORKSPACE) / "adblock_adh.txt"  # 输入AdGuard Home规则文件
OUTPUT_HOSTS = Path(GITHUB_WORKSPACE) / "hosts.txt"  # 输出hosts文件

# 匹配AdGuard Home规则的正则表达式（覆盖主流语法）
# 1. 标准域名拦截规则（如 ||example.com^、||sub.example.com^）
# 2. IP形式拦截规则（如 0.0.0.0 example.com）
# 3. 排除例外规则（如 @@||example.com^ 会被过滤掉）
DOMAIN_RULE_PATTERN = re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^?$')
IP_RULE_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
EXCEPTION_RULE_PATTERN = re.compile(r'^@@\|\|.*$')  # 例外规则（允许访问）


def convert_to_hosts(rule):
    """将AdGuard Home规则转换为hosts格式"""
    # 跳过例外规则（hosts仅处理拦截，允许规则无需写入）
    if EXCEPTION_RULE_PATTERN.match(rule):
        return None
    
    # 处理域名拦截规则（如 ||example.com^ → 0.0.0.0 example.com）
    domain_match = DOMAIN_RULE_PATTERN.match(rule)
    if domain_match:
        domain = domain_match.group(1).strip()
        return f"0.0.0.0 {domain}"
    
    # 处理IP形式规则（如 0.0.0.0 example.com → 直接保留有效格式）
    ip_match = IP_RULE_PATTERN.match(rule)
    if ip_match:
        domain = ip_match.group(1).strip()
        return f"0.0.0.0 {domain}"
    
    # 不支持的规则类型（如正则、路径规则等）返回None
    return None


def process_agh_rules(input_path):
    """处理AdGuard Home规则文件，生成去重后的hosts规则"""
    hosts_rules = []
    seen_domains = set()  # 用于去重（避免同一域名重复拦截）
    
    if not input_path.exists():
        print(f"警告：输入文件 {input_path} 不存在，已跳过处理。")
        return hosts_rules
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # 跳过空行和注释行（AdGuard注释以!或#开头）
                if not line or line.startswith(('!', '#')):
                    continue
                
                # 转换规则
                converted = convert_to_hosts(line)
                if converted:
                    # 提取域名部分用于去重（避免0.0.0.0重复绑定同一域名）
                    domain = converted.split()[1]
                    if domain not in seen_domains:
                        hosts_rules.append(converted)
                        seen_domains.add(domain)
    except Exception as e:
        print(f"处理文件时出错：{e}")
    
    return hosts_rules


def main():
    # 处理规则并生成hosts内容
    hosts_rules = process_agh_rules(INPUT_AGH)
    
    # 写入输出文件（纯净规则，无任何多余信息）
    try:
        with open(OUTPUT_HOSTS, 'w', encoding='utf-8') as f:
            f.write('\n'.join(hosts_rules) + '\n')
        print(f"转换完成：共生成 {len(hosts_rules)} 条hosts规则，已写入 {OUTPUT_HOSTS}")
    except Exception as e:
        print(f"写入文件失败：{e}")
        return 1
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
