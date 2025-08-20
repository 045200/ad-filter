#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adguard_home.txt"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"

# 预编译正则表达式
ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|\$.*)?$')
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|\$.*)?$')
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
DOMAIN_ONLY = re.compile(r'^([\w.-]+)$')

# AdGuard Home 不支持的修饰符
UNSUPPORTED_MODIFIERS = {
    '$csp', '$redirect', '$removeparam', '$removeheader',
    '$hiden', '$jsonprune', '$replace'
}


def process_file():
    """处理输入文件并生成AdGuard Home规则"""
    rules = set()
    
    if not INPUT_FILE.exists():
        print(f"错误: 输入文件不存在 {INPUT_FILE}")
        return rules
    
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue
                
            # 跳过AdGuard Home不支持的修饰符规则
            if any(mod in line for mod in UNSUPPORTED_MODIFIERS):
                continue
                
            # 处理白名单规则 (AdGuard Home 使用 @@ 前缀)
            if ADBLOCK_WHITELIST.match(line):
                rules.add(line)
                continue
                
            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line):
                # 简化规则，移除AdGuard Home不需要的部分
                simplified = simplify_rule(line)
                if simplified:
                    rules.add(simplified)
                continue
                
            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if not IP_ADDRESS.match(domain):
                    rules.add(f"||{domain}^")
                continue
                
            # 处理纯域名
            if DOMAIN_ONLY.match(line) and not IP_ADDRESS.match(line):
                rules.add(f"||{line}^")
    
    return rules


def simplify_rule(rule):
    """简化规则以适应AdGuard Home"""
    # 移除不必要的修饰符
    if '$' in rule:
        # 保留基本修饰符，移除复杂修饰符
        parts = rule.split('$')
        if len(parts) > 1:
            modifier = parts[1]
            # 只保留简单修饰符
            if modifier in ['important', 'script', 'image', 'stylesheet', 'object', 'xmlhttprequest', 'object-subrequest', 'subdocument', 'document', 'elemhide', 'generichide', 'genericblock', 'popup', 'third-party', 'match-case', 'collapse', 'badfilter']:
                return rule
            else:
                # 移除复杂修饰符
                return parts[0] + '^'
    
    return rule


def write_output(rules):
    """写入输出文件"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(rules)) + '\n')
    
    print(f"生成AdGuard Home规则: {len(rules)} 条")


def github_actions_output():
    """GitHub Actions输出"""
    if github_output := os.getenv('GITHUB_OUTPUT'):
        with open(github_output, 'a') as f:
            f.write(f"adguard_home_file={OUTPUT_FILE}\n")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 处理文件
    rules = process_file()
    
    # 写入输出
    write_output(rules)
    
    # GitHub Actions输出
    github_actions_output()