#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
from pathlib import Path


# 配置参数
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
TEMP_DIR = Path(GITHUB_WORKSPACE) / os.getenv('TEMP_DIR', 'tmp')
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
ALLOW_FILE = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
INPUT_FILE = TEMP_DIR / "adblock_merged.txt"

# 预编译正则表达式
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
ELEMENT_HIDING = re.compile(r'^.*##[^#]+$')
ELEMENT_HIDING_EXCEPTION = re.compile(r'^.*#@#[^#]+$')
SCRIPT_RULE = re.compile(r'.*\$script.*')
IMAGE_RULE = re.compile(r'.*\$image.*')
STYLESHEET_RULE = re.compile(r'.*\$stylesheet.*')
DOMAIN_RULE = re.compile(r'.*\$domain=.*')
THIRD_PARTY_RULE = re.compile(r'.*\$third-party.*')
POPUP_RULE = re.compile(r'.*\$popup.*')

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

# AdGuard 支持的修饰符
SUPPORTED_MODIFIERS = {
    '$script', '$image', '$stylesheet', '$domain', '$third-party', 
    '~third-party', '$popup', '$xmlhttprequest', '$object', 
    '$object-subrequest', '$subdocument', '$ping', '$websocket', 
    '$webrtc', '$other'
}


def process_file():
    """处理文件并生成AdGuard规则"""
    rules = []
    allows = []
    seen_rules = set()
    seen_allows = set()

    if not INPUT_FILE.exists():
        print(f"输入文件不存在: {INPUT_FILE}")
        return rules, allows

    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue

            # 处理白名单规则
            if line.startswith('@@'):
                # 检查是否是元素隐藏例外规则
                if ELEMENT_HIDING_EXCEPTION.match(line):
                    rule_hash = hashlib.md5(line.encode()).hexdigest()
                    if rule_hash not in seen_allows:
                        allows.append(line)
                        seen_allows.add(rule_hash)
                    continue
                
                # 处理标准白名单规则
                normalized = line[2:]
                if ADBLOCK_DOMAIN.match(normalized):
                    rule_hash = hashlib.md5(normalized.encode()).hexdigest()
                    if rule_hash not in seen_allows:
                        allows.append(normalized)
                        seen_allows.add(rule_hash)
                else:
                    # 处理带有修饰符的白名单规则
                    rule_hash = hashlib.md5(line.encode()).hexdigest()
                    if rule_hash not in seen_allows:
                        allows.append(line)
                        seen_allows.add(rule_hash)
                continue

            # 处理元素隐藏规则
            if ELEMENT_HIDING.match(line):
                rule_hash = hashlib.md5(line.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    rules.append(line)
                    seen_rules.add(rule_hash)
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    rule = f"||{domain}^"
                    rule_hash = hashlib.md5(rule.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        rules.append(rule)
                        seen_rules.add(rule_hash)
                continue

            # 处理纯域名
            if PLAIN_DOMAIN.match(line) and is_valid_domain(line):
                rule = f"||{line}^"
                rule_hash = hashlib.md5(rule.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    rules.append(rule)
                    seen_rules.add(rule_hash)
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line):
                rule_hash = hashlib.md5(line.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    rules.append(line)
                    seen_rules.add(rule_hash)
                continue

            # 处理带有修饰符的规则
            if any(modifier in line for modifier in SUPPORTED_MODIFIERS):
                rule_hash = hashlib.md5(line.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    rules.append(line)
                    seen_rules.add(rule_hash)
                continue

    return rules, allows


def is_valid_domain(domain: str) -> bool:
    """验证域名有效性"""
    if domain in DOMAIN_BLACKLIST or IP_ADDRESS.match(domain):
        return False
    if len(domain) < 4 or len(domain) > 253:
        return False
    if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    return True


def write_output(rules, allows):
    """写入输出文件"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules) + '\n')

    with open(ALLOW_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(allows) + '\n')

    print(f"已生成拦截规则: {len(rules)} 条")
    print(f"已生成白名单规则: {len(allows)} 条")


def github_actions_output():
    """GitHub Actions输出"""
    if github_output := os.getenv('GITHUB_OUTPUT'):
        with open(github_output, 'a') as f:
            f.write(f"adguard_file={OUTPUT_FILE}\n")
            f.write(f"adguard_allow_file={ALLOW_FILE}\n")


if __name__ == '__main__':
    try:
        rules, allows = process_file()
        write_output(rules, allows)
        github_actions_output()
    except Exception as e:
        print(f"处理失败: {e}")
        sys.exit(1)