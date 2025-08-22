#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
import glob
from pathlib import Path
from urllib.parse import urlparse


# 配置参数
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
DATA_DIR = Path(GITHUB_WORKSPACE) / "data" / "filter"
OUTPUT_FILE = DATA_DIR / "adblock_adg.txt"
ALLOW_FILE = DATA_DIR / "allow_allow.txt"

# 输入文件模式
ADBLOCK_PATTERNS = ["adblock.txt"]
ALLOW_PATTERNS = ["allow.txt"]

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

# AdGuard 特定规则识别
ADGUARD_DNSREWRITE = re.compile(r'.*\$dnsrewrite=.*')
ADGUARD_CNAME = re.compile(r'.*\$cname=.*')
ADGUARD_CLIENT = re.compile(r'.*\$client=.*')
ADGUARD_DNSTYPE = re.compile(r'.*\$dnstype=.*')
ADGUARD_DENYALLOW = re.compile(r'.*\$denyallow=.*')
ADGUARD_IMPORTANT = re.compile(r'.*\$important.*')
ADGUARD_CTAG = re.compile(r'.*\$ctag=.*')
ADGUARD_BADFILTER = re.compile(r'.*\$badfilter.*')
ADGUARD_REDIRECT = re.compile(r'.*\$redirect=.*')
ADGUARD_REMOVEHEADER = re.compile(r'.*\$removeheader=.*')
ADGUARD_REMOVEPARAM = re.compile(r'.*\$removeparam=.*')
ADGUARD_APP = re.compile(r'.*\$app=.*')

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
    '$csp', '$replace', '$cookie', '$network', '$app',
    '$dnsrewrite', '$cname', '$client', '$dnstype', '$denyallow',
    '$ctag', '$badfilter', '$removeheader', '$removeparam'
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


def is_adguard_rule(rule: str) -> bool:
    """检查是否是AdGuard特定规则"""
    return any(pattern.search(rule) for pattern in [
        ADGUARD_DNSREWRITE, ADGUARD_CNAME, ADGUARD_CLIENT, ADGUARD_DNSTYPE,
        ADGUARD_DENYALLOW, ADGUARD_IMPORTANT, ADGUARD_CTAG, ADGUARD_BADFILTER,
        ADGUARD_REDIRECT, ADGUARD_REMOVEHEADER, ADGUARD_REMOVEPARAM, ADGUARD_APP
    ])


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


def convert_adblock_to_adguard(rule: str) -> str:
    """将AdBlock规则转换为AdGuard规则"""
    # 如果是AdGuard特定规则，直接返回
    if is_adguard_rule(rule):
        return rule
    
    # 处理元素隐藏规则
    if ELEMENT_HIDING.match(rule):
        return rule
    
    # 处理白名单规则
    if rule.startswith('@@'):
        # 移除@@前缀
        clean_rule = rule[2:]
        # 如果是域名规则，确保格式正确
        if ADBLOCK_DOMAIN.match(clean_rule):
            if not clean_rule.endswith('^'):
                clean_rule += '^'
            return f"@@{clean_rule}"
        return rule
    
    # 处理标准AdBlock域名规则
    if ADBLOCK_DOMAIN.match(rule):
        if not rule.endswith('^'):
            rule += '^'
        return rule
    
    # 处理通用规则
    if GENERIC_RULE.match(rule):
        return rule
    
    # 处理Hosts规则
    hosts_match = HOSTS_RULE.match(rule)
    if hosts_match:
        domain = hosts_match.group(2)
        if is_valid_domain(domain):
            return f"||{domain}^"
    
    # 处理纯域名
    if PLAIN_DOMAIN.match(rule) and is_valid_domain(rule):
        return f"||{rule}^"
    
    # 处理URL规则
    if URL_RULE.match(rule):
        parsed = urlparse(rule)
        if parsed.netloc and is_valid_domain(parsed.netloc):
            return f"||{parsed.netloc}^"
    
    # 默认情况下返回原规则
    return rule


def read_input_files(patterns, is_allow=False):
    """读取输入文件"""
    rules = []
    for pattern in patterns:
        for file_path in glob.glob(str(DATA_DIR / pattern)):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        # 跳过空行和注释
                        if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                            continue
                        rules.append(line)
            except Exception as e:
                print(f"读取文件 {file_path} 时出错: {e}")
    return rules


def process_rules(input_rules, is_allow=False):
    """处理规则并生成AdGuard规则"""
    processed_rules = []
    seen_rules = set()

    for line in input_rules:
        try:
            # 处理白名单规则
            if is_allow:
                # 检查是否是元素隐藏例外规则
                if ELEMENT_HIDING_EXCEPTION.match(line):
                    rule_hash = hashlib.md5(line.encode()).hexdigest()
                    if rule_hash not in seen_rules:
                        processed_rules.append(line)
                        seen_rules.add(rule_hash)
                    continue

                # 处理标准白名单规则
                if line.startswith('@@'):
                    normalized = line
                else:
                    normalized = f"@@{line}" if not line.startswith('@@') else line
                
                # 转换为AdGuard格式
                adguard_rule = convert_adblock_to_adguard(normalized)
                rule_hash = hashlib.md5(adguard_rule.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    processed_rules.append(adguard_rule)
                    seen_rules.add(rule_hash)
                continue

            # 处理拦截规则
            # 检查是否是元素隐藏规则
            if ELEMENT_HIDING.match(line) and not line.startswith('#'):
                rule_hash = hashlib.md5(line.encode()).hexdigest()
                if rule_hash not in seen_rules:
                    processed_rules.append(line)
                    seen_rules.add(rule_hash)
                continue

            # 转换为AdGuard格式
            adguard_rule = convert_adblock_to_adguard(line)
            rule_hash = hashlib.md5(adguard_rule.encode()).hexdigest()
            if rule_hash not in seen_rules:
                processed_rules.append(adguard_rule)
                seen_rules.add(rule_hash)

        except Exception as e:
            print(f"处理规则时出错: {line} - {e}")
            continue

    return processed_rules


def write_output(rules, allows):
    """写入输出文件"""
    # 确保输出目录存在
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
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
        # 读取输入文件
        adblock_rules = read_input_files(ADBLOCK_PATTERNS)
        allow_rules = read_input_files(ALLOW_PATTERNS, is_allow=True)
        
        print(f"读取拦截规则: {len(adblock_rules)} 条")
        print(f"读取白名单规则: {len(allow_rules)} 条")
        
        # 处理规则
        processed_adblock = process_rules(adblock_rules)
        processed_allow = process_rules(allow_rules, is_allow=True)
        
        # 写入输出
        write_output(processed_adblock, processed_allow)
        github_actions_output()
        print("处理完成!")
    except Exception as e:
        print(f"处理失败: {e}")
        sys.exit(1)