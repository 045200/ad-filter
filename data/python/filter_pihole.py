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

            # 跳过元素隐藏规则（Pi-hole不支持）
            if ELEMENT_HIDING.match(line) or ELEMENT_HIDING_EXCEPTION.match(line):
                continue

            # 处理白名单规则
            if line.startswith('@@'):
                # 处理标准白名单规则
                if ADBLOCK_WHITELIST.match(line):
                    domain_match = ADBLOCK_WHITELIST.match(line)
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        allow_domains.add(domain)
                    continue
                
                # 处理其他白名单规则
                simplified = simplify_rule(line[2:])  # 移除@@前缀
                if simplified:
                    # 提取域名部分
                    domain_match = re.search(r'\|\|([\w.-]+)', simplified)
                    if domain_match:
                        domain = domain_match.group(1)
                        if is_valid_domain(domain):
                            allow_domains.add(domain)
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                domain_match = ADBLOCK_DOMAIN.match(line) or re.search(r'\|\|([\w.-]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        block_domains.add(domain)
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    block_domains.add(domain)
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
                        block_domains.add(domain)
                continue

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and is_valid_domain(line):
                block_domains.add(line)
                continue

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                # 提取可能的域名部分
                domain_match = re.search(r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+', line)
                if domain_match:
                    domain = domain_match.group(0)
                    if is_valid_domain(domain):
                        block_domains.add(domain)
                continue

            # 处理其他规则（如果包含域名）
            domain_match = re.search(r'[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+', line)
            if domain_match:
                domain = domain_match.group(0)
                if is_valid_domain(domain):
                    block_domains.add(domain)
                continue

    return block_domains, allow_domains


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


def simplify_rule(rule):
    """简化规则以适应Pi-hole"""
    # 移除修饰符部分
    if '$' in rule:
        parts = rule.split('$')
        return parts[0]
    
    return rule


def write_output(block_domains, allow_domains):
    """写入输出文件，不包含头信息"""
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