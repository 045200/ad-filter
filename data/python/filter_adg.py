#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
from pathlib import Path
from urllib.parse import urlparse


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
GENERIC_RULE = re.compile(r'^\|\|.*\^$')
URL_RULE = re.compile(r'^https?://[^\s]+$')
MALWARE_RULE = re.compile(r'.*(malware|phishing|ransomware|trojan|virus|worm|spyware|adware|keylogger)\.', re.IGNORECASE)

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain', 'example',
    'test', 'invalid', 'local', 'domain', 'com', 'org', 'net'
}

# AdGuard 支持的修饰符
SUPPORTED_MODIFIERS = {
    '$script', '$image', '$stylesheet', '$domain', '$third-party', 
    '~third-party', '$popup', '$xmlhttprequest', '$object', 
    '$object-subrequest', '$subdocument', '$ping', '$websocket', 
    '$webrtc', '$other', '$document', '$font', '$media', 
    '$match-case', '$important', '$empty', '$mp4', '$redirect',
    '$csp', '$replace', '$cookie', '$network', '$app'
}

# 支持的重定向资源
SUPPORTED_REDIRECTS = {
    'nooptext', 'noopcss', 'noopjs', 'noopframe', 'noophtml',
    '1x1.gif', '2x2.png', '3x2.png', '32x32.png', 'empty',
    'redirect', 'block', 'mp4', 'self'
}

# 常见跟踪参数
TRACKING_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term',
    'utm_content', 'fbclid', 'gclid', 'dclid', 'msclkid',
    'mc_cid', 'mc_eid', '_ga', 'yclid', 'igshid'
}


def is_valid_domain(domain: str) -> bool:
    """验证域名有效性"""
    if not domain or domain in DOMAIN_BLACKLIST or IP_ADDRESS.match(domain):
        return False
    if len(domain) < 4 or len(domain) > 253:
        return False
    if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    if MALWARE_RULE.search(domain):
        return False  # 过滤掉明显是恶意软件相关的域名
    return True


def normalize_rule(rule: str) -> str:
    """规范化规则以提高匹配率"""
    # 移除不必要的通配符
    if rule.startswith('*.'):
        rule = rule[2:]
    
    # 处理包含查询参数的URL规则
    if '?' in rule and ('^' in rule or '$' in rule):
        # 提取主域名部分
        domain_part = rule.split('?')[0]
        if domain_part.endswith('^'):
            rule = domain_part + '$all'
    
    # 规范化第三方标记
    if '$third-party' in rule:
        rule = rule.replace('$third-party', '~third-party')
    elif 'third-party' in rule and not rule.startswith('~third-party'):
        rule = rule.replace('third-party', '~third-party')
    
    # 处理重定向规则
    if '$redirect' in rule and any(redirect in rule for redirect in SUPPORTED_REDIRECTS):
        # 确保重定向规则格式正确
        parts = rule.split('$')
        if len(parts) > 1 and 'redirect=' in parts[-1]:
            redirect_part = parts[-1].split('=', 1)
            if redirect_part[1] in SUPPORTED_REDIRECTS:
                rule = f"{parts[0]}$${redirect_part[1]}"
    
    return rule


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
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue

            try:
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
                if ELEMENT_HIDING.match(line) and not line.startswith('#'):
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
                        rule = normalize_rule(rule)
                        rule_hash = hashlib.md5(rule.encode()).hexdigest()
                        if rule_hash not in seen_rules:
                            rules.append(rule)
                            seen_rules.add(rule_hash)
                    continue

                # 处理纯域名
                if PLAIN_DOMAIN.match(line) and is_valid_domain(line):
                    rule = f"||{line}^"
                    rule = normalize_rule(rule)
                    rule_hash = hashlib.md5(rule.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        rules.append(rule)
                        seen_rules.add(rule_hash)
                    continue

                # 处理URL规则
                if URL_RULE.match(line):
                    parsed = urlparse(line)
                    if parsed.netloc and is_valid_domain(parsed.netloc):
                        rule = f"||{parsed.netloc}^"
                        rule = normalize_rule(rule)
                        rule_hash = hashlib.md5(rule.encode()).hexdigest()
                        if rule_hash not in seen_rules:
                            rules.append(rule)
                            seen_rules.add(rule_hash)
                    continue

                # 处理标准Adblock规则
                if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                    rule = normalize_rule(line)
                    rule_hash = hashlib.md5(rule.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        rules.append(rule)
                        seen_rules.add(rule_hash)
                    continue

                # 处理带有修饰符的规则
                if any(modifier in line for modifier in SUPPORTED_MODIFIERS):
                    rule = normalize_rule(line)
                    rule_hash = hashlib.md5(rule.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        rules.append(rule)
                        seen_rules.add(rule_hash)
                    continue

                # 处理包含跟踪参数的规则
                if any(param in line for param in TRACKING_PARAMS):
                    rule = normalize_rule(line)
                    rule_hash = hashlib.md5(rule.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        rules.append(rule)
                        seen_rules.add(rule_hash)
                    continue

            except Exception as e:
                print(f"处理第 {line_num} 行时出错: {line} - {e}")
                continue

    return rules, allows


def write_output(rules, allows):
    """写入输出文件"""
    # 直接写入规则，不添加任何头信息
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
        print("处理完成!")
    except Exception as e:
        print(f"处理失败: {e}")
        sys.exit(1)