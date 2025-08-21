#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path


# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adp.txt"
ALLOW_FILE = Path(GITHUB_WORKSPACE) / "allow_adp.txt"
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

# AdBlock Plus 支持的修饰符
SUPPORTED_MODIFIERS = {
    '$domain', '$third-party', '~third-party', '$script', 
    '$image', '$stylesheet', '$object', '$object-subrequest',
    '$subdocument', '$document', '$elemhide', '$generichide',
    '$genericblock', '$popup', '$match-case', '$collapse',
    '$badfilter', '$important'
}

# AdBlock Plus 不支持的修饰符
UNSUPPORTED_MODIFIERS = {
    '$csp', '$redirect', '$removeparam', '$removeheader',
    '$hiden', '$jsonprune', '$replace', '$cookie', '$all',
    '$app', '$network', '$ping', '$websocket', '$webrtc',
    '$xmlhttprequest'
}

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}


def process_file():
    """处理输入文件并生成AdBlock Plus规则"""
    rules = set()
    allows = set()

    if not INPUT_FILE.exists():
        print(f"错误: 输入文件不存在 {INPUT_FILE}")
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
                    allows.add(line)
                    continue
                
                # 处理标准白名单规则
                if ADBLOCK_WHITELIST.match(line):
                    # 简化白名单规则，移除不支持的修饰符
                    simplified = simplify_rule(line)
                    if simplified and is_valid_rule(simplified):
                        allows.add(simplified)
                    continue
                
                # 处理其他白名单规则
                simplified = simplify_rule(line[2:])  # 移除@@前缀
                if simplified and is_valid_rule(simplified):
                    allows.add('@@' + simplified)
                continue

            # 处理元素隐藏规则
            if ELEMENT_HIDING.match(line):
                rules.add(line)
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                # 简化规则，移除AdBlock Plus不支持的修饰符
                simplified = simplify_rule(line)
                if simplified and is_valid_rule(simplified):
                    rules.add(simplified)
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    rules.add(f"||{domain}^")
                continue

            # 处理URL规则
            if URL_RULE.match(line):
                # 提取域名部分
                domain_match = re.search(r'://([^/]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        rules.add(f"||{domain}^")
                continue

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and is_valid_domain(line):
                rules.add(f"||{line}^")
                continue

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                # 转换为AdBlock Plus兼容的通配符格式
                converted = convert_wildcard_rule(line)
                if converted and is_valid_rule(converted):
                    rules.add(converted)
                continue

            # 处理其他规则（如果包含支持的修饰符）
            if any(mod in line for mod in SUPPORTED_MODIFIERS):
                simplified = simplify_rule(line)
                if simplified and is_valid_rule(simplified):
                    rules.add(simplified)
                continue

    return rules, allows


def simplify_rule(rule):
    """简化规则以适应AdBlock Plus"""
    # 移除不支持的修饰符
    if '$' in rule:
        parts = rule.split('$')
        base_rule = parts[0]
        modifiers = parts[1:]

        # 过滤支持的修饰符
        supported_mods = []
        for mod in modifiers:
            mod_name = mod.split('=')[0] if '=' in mod else mod
            if mod_name in SUPPORTED_MODIFIERS:
                supported_mods.append(mod)

        # 重新构建规则
        if supported_mods:
            return base_rule + '$' + '$'.join(supported_mods)
        else:
            return base_rule + '^'  # 如果没有修饰符，添加默认的^

    return rule


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


def is_valid_rule(rule):
    """验证规则有效性"""
    # 基本长度检查
    if not rule or len(rule) > 200:
        return False
    
    # 检查是否包含无效字符
    if re.search(r'[^\w\.\-\*\^\|\@\$\,\=\~\/]', rule):
        return False
    
    return True


def convert_wildcard_rule(wildcard_rule):
    """转换通配符规则为AdBlock Plus兼容格式"""
    # 移除开头的*
    if wildcard_rule.startswith('*'):
        wildcard_rule = wildcard_rule[1:]
    
    # 移除结尾的*
    if wildcard_rule.endswith('*'):
        wildcard_rule = wildcard_rule[:-1]
    
    # 如果中间有*，转换为域名规则
    if '*' in wildcard_rule:
        # 将*替换为通配符
        return wildcard_rule.replace('*', '^')
    
    # 否则转换为域名规则
    return f"||{wildcard_rule}^"


def write_output(rules, allows):
    """写入输出文件，不包含头信息"""
    # 写入拦截规则文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(rules)) + '\n')
    
    # 写入白名单规则文件
    with open(ALLOW_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(allows)) + '\n')

    print(f"生成AdBlock Plus拦截规则: {len(rules)} 条")
    print(f"生成AdBlock Plus白名单规则: {len(allows)} 条")


def github_actions_output():
    """GitHub Actions输出"""
    if github_output := os.getenv('GITHUB_OUTPUT'):
        with open(github_output, 'a') as f:
            f.write(f"adblock_plus_file={OUTPUT_FILE}\n")
            f.write(f"adblock_plus_allow_file={ALLOW_FILE}\n")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 处理文件
    rules, allows = process_file()

    # 写入输出
    write_output(rules, allows)
    
    # GitHub Actions输出
    github_actions_output()