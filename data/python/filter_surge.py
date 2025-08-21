#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_surge.conf"
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

# Surge 支持的规则类型
SURGE_RULE_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR',
    'GEOIP', 'DST-PORT', 'SRC-PORT', 'PROCESS-NAME', 'MATCH'
}

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}


def process_file():
    """处理输入文件并生成Surge规则"""
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

            # 跳过元素隐藏规则（Surge不支持）
            if ELEMENT_HIDING.match(line) or ELEMENT_HIDING_EXCEPTION.match(line):
                continue

            # 处理白名单规则
            if line.startswith('@@'):
                # 处理标准白名单规则
                if ADBLOCK_WHITELIST.match(line):
                    domain_match = ADBLOCK_WHITELIST.match(line)
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        rules.add(f"DOMAIN,{domain}")
                    continue
                
                # 处理其他白名单规则
                simplified = simplify_rule(line[2:])  # 移除@@前缀
                if simplified:
                    # 提取域名部分
                    domain_match = re.search(r'\|\|([\w.-]+)', simplified)
                    if domain_match:
                        domain = domain_match.group(1)
                        if is_valid_domain(domain):
                            rules.add(f"DOMAIN,{domain}")
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                domain_match = ADBLOCK_DOMAIN.match(line) or re.search(r'\|\|([\w.-]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        rules.add(f"DOMAIN-SUFFIX,{domain}")
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    rules.add(f"DOMAIN-SUFFIX,{domain}")
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
                        rules.add(f"DOMAIN-SUFFIX,{domain}")
                continue

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and is_valid_domain(line):
                rules.add(f"DOMAIN-SUFFIX,{line}")
                continue

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                # 转换为Surge兼容的通配符格式
                converted = convert_wildcard_rule(line)
                if converted:
                    rules.add(converted)
                continue

            # 处理其他规则（如果包含IP地址）
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if ip_match:
                ip = ip_match.group(0)
                if IP_ADDRESS.match(ip):
                    rules.add(f"IP-CIDR,{ip}/32")
                continue

    return rules


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


def convert_wildcard_rule(wildcard_rule):
    """转换通配符规则为Surge兼容格式"""
    # 移除开头的*
    if wildcard_rule.startswith('*'):
        wildcard_rule = wildcard_rule[1:]
    
    # 移除结尾的*
    if wildcard_rule.endswith('*'):
        wildcard_rule = wildcard_rule[:-1]
    
    # 如果中间有*，转换为DOMAIN-KEYWORD规则
    if '*' in wildcard_rule:
        keyword = wildcard_rule.replace('*', '')
        if keyword:
            return f"DOMAIN-KEYWORD,{keyword}"
    
    # 否则转换为DOMAIN-SUFFIX规则
    return f"DOMAIN-SUFFIX,{wildcard_rule}"


def simplify_rule(rule):
    """简化规则以适应Surge"""
    # 移除修饰符部分
    if '$' in rule:
        parts = rule.split('$')
        return parts[0]
    
    return rule


def write_output(rules):
    """写入输出文件，不包含头信息"""
    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('[Rule]\n')
        f.write('\n'.join(sorted(rules)) + '\n')

    print(f"生成Surge规则: {len(rules)} 条")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 处理文件
    rules = process_file()

    # 写入输出
    write_output(rules)