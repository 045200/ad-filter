#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
BLOCK_FILE = Path(GITHUB_WORKSPACE) / "adblock_pihole.txt"
ALLOW_FILE = Path(GITHUB_WORKSPACE) / "allow_pihole.txt"
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
    """处理输入文件并生成Pi-hole规则"""
    block_domains = set()
    allow_domains = set()
    
    if not INPUT_FILE.exists():
        print(f"错误: 输入文件不存在 {INPUT_FILE}")
        return block_domains, allow_domains
    
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue
                
            # 处理白名单规则
            whitelist_match = ADBLOCK_WHITELIST.match(line)
            if whitelist_match:
                domain = whitelist_match.group(1)
                if not IP_ADDRESS.match(domain):
                    allow_domains.add(domain)
                continue
                
            # 处理标准Adblock规则
            adblock_match = ADBLOCK_DOMAIN.match(line)
            if adblock_match:
                domain = adblock_match.group(1)
                if not IP_ADDRESS.match(domain):
                    block_domains.add(domain)
                continue
                
            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if not IP_ADDRESS.match(domain):
                    block_domains.add(domain)
                continue
                
            # 处理纯域名
            if DOMAIN_ONLY.match(line) and not IP_ADDRESS.match(line):
                block_domains.add(line)
    
    return block_domains, allow_domains


def write_output(block_domains, allow_domains):
    """写入输出文件"""
    # 写入拦截列表
    with open(BLOCK_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(block_domains)) + '\n')
    
    # 写入白名单
    with open(ALLOW_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(allow_domains)) + '\n')
    
    print(f"生成Pi-hole拦截列表: {len(block_domains)} 条域名")
    print(f"生成Pi-hole白名单: {len(allow_domains)} 条域名")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 处理文件
    block_domains, allow_domains = process_file()
    
    # 写入输出
    write_output(block_domains, allow_domains)