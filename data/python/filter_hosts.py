#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "hosts.txt"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"

# 预编译正则表达式
ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|\$.*)?$')
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|\$.*)?$')
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
DOMAIN_ONLY = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
WILDCARD_RULE = re.compile(r'^\*[^*]+\*$')
ELEMENT_HIDING = re.compile(r'^.*##[^#]+$')
ELEMENT_HIDING_EXCEPTION = re.compile(r'^.*#@#[^#]+$')
URL_RULE = re.compile(r'^https?://[^\s]+$')
GENERIC_RULE = re.compile(r'^\|\|.*\^$')
REGEX_RULE = re.compile(r'^/.*/$')

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}


def process_file():
    """处理输入文件并生成Hosts规则"""
    domains = set()

    if not INPUT_FILE.exists():
        print(f"错误: 输入文件不存在 {INPUT_FILE}")
        return domains

    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue

            # 跳过白名单规则(Hosts文件不支持白名单)
            if line.startswith('@@'):
                continue

            # 跳过元素隐藏规则（Hosts文件不支持）
            if ELEMENT_HIDING.match(line) or ELEMENT_HIDING_EXCEPTION.match(line):
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                domain_match = ADBLOCK_DOMAIN.match(line) or re.search(r'\|\|([\w.-]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        domains.add(domain)
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    domains.add(domain)
                continue

            # 处理URL规则
            if URL_RULE.match(line):
                # 提取域名部分
                domain_match = re.search(r'://([^/]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    # 移除端口号
                    domain = domain.split(':')[0]
                    if is_valid_domain(domain):
                        domains.add(domain)
                continue

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and is_valid_domain(line):
                domains.add(line)
                continue

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                # 提取可能的域名部分
                domain_match = re.search(r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+', line)
                if domain_match:
                    domain = domain_match.group(0)
                    if is_valid_domain(domain):
                        domains.add(domain)
                continue

            # 处理其他规则（如果包含域名）
            domain_match = re.search(r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+', line)
            if domain_match:
                domain = domain_match.group(0)
                if is_valid_domain(domain):
                    domains.add(domain)
                continue

    return domains


def is_valid_domain(domain):
    """验证域名有效性"""
    if not domain or domain in DOMAIN_BLACKLIST:
        return False
    
    # 检查是否是IP地址
    if IP_ADDRESS.match(domain):
        return False
    
    # 基本长度检查
    if len(domain) < 4 or len(domain) > 253:
        return False
    
    # 检查域名格式
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return False
    
    # 检查TLD部分
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1]
    if len(tld) < 2 or len(tld) > 10:
        return False
    
    return True


def write_output(domains):
    """写入输出文件，不包含头信息"""
    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            f.write(f"0.0.0.0 {domain}\n")

    print(f"生成Hosts规则: {len(domains)} 条域名")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 处理文件
    domains = process_file()

    # 写入输出
    write_output(domains)