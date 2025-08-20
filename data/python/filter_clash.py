#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "clash.yaml"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"

# 预编译正则表达式
ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|\$.*)?$')
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|\$.*)?$')
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
DOMAIN_ONLY = re.compile(r'^([\w.-]+)$')


def process_file():
    """处理输入文件并生成Clash规则"""
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
                
            # 处理白名单规则(Clash使用DOMAIN和+前缀)
            if ADBLOCK_WHITELIST.match(line):
                domain_match = ADBLOCK_WHITELIST.match(line)
                if domain_match:
                    domain = domain_match.group(1)
                    if not IP_ADDRESS.match(domain):
                        rules.add(f"+.{domain}")
                continue
                
            # 处理标准Adblock规则
            adblock_match = ADBLOCK_DOMAIN.match(line)
            if adblock_match:
                domain = adblock_match.group(1)
                if not IP_ADDRESS.match(domain):
                    rules.add(f".{domain}")
                continue
                
            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if not IP_ADDRESS.match(domain):
                    rules.add(f".{domain}")
                continue
                
            # 处理纯域名
            if DOMAIN_ONLY.match(line) and not IP_ADDRESS.match(line):
                rules.add(f".{line}")
    
    return rules


def write_output(rules):
    """写入输出文件"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('payload:\n')
        for rule in sorted(rules):
            f.write(f"  - '{rule}'\n")
    
    print(f"生成Clash规则: {len(rules)} 条")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 处理文件
    rules = process_file()
    
    # 写入输出
    write_output(rules)