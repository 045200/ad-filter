#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path
from urllib.parse import urlparse

# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
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
MODIFIER_RULE = re.compile(r'^.+\$.+$')

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

# 支持的Mihomo规则类型
MIHOMO_RULE_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
    'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'DST-PORT', 'SRC-PORT', 
    'PROCESS-NAME', 'PROCESS-PATH', 'MATCH', 'FINAL',
    'RULE-SET', 'SCRIPT', 'SUB-RULE', 'AND', 'OR', 'NOT'
}


def process_file():
    """处理输入文件并生成Clash/Mihomo规则"""
    rules = set()
    rejected_rules = set()
    
    if not INPUT_FILE.exists():
        print(f"错误: 输入文件不存在 {INPUT_FILE}")
        return rules

    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # 跳过空行和注释
            if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                continue

            # 跳过元素隐藏规则（Clash/Mihomo不支持）
            if ELEMENT_HIDING.match(line) or ELEMENT_HIDING_EXCEPTION.match(line):
                rejected_rules.add(f"Line {line_num}: 元素隐藏规则 - {line}")
                continue

            # 处理白名单规则 (Mihomo支持更丰富的白名单语法)
            if line.startswith('@@'):
                # 处理标准白名单规则
                if ADBLOCK_WHITELIST.match(line):
                    domain_match = ADBLOCK_WHITELIST.match(line)
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        # Mihomo 支持更精确的白名单规则
                        rules.add(f"DOMAIN,{domain},DIRECT")
                    else:
                        rejected_rules.add(f"Line {line_num}: 无效白名单域名 - {line}")
                    continue

                # 处理其他白名单规则
                simplified = simplify_rule(line[2:])  # 移除@@前缀
                if simplified and is_valid_rule(simplified):
                    # 提取域名部分
                    domain_match = re.search(r'\|\|([\w.-]+)', simplified)
                    if domain_match:
                        domain = domain_match.group(1)
                        if is_valid_domain(domain):
                            rules.add(f"DOMAIN,{domain},DIRECT")
                    else:
                        # 尝试匹配其他格式的白名单
                        url_match = re.search(r'://([^/]+)', simplified)
                        if url_match:
                            domain = url_match.group(1)
                            if is_valid_domain(domain):
                                rules.add(f"DOMAIN,{domain},DIRECT")
                else:
                    rejected_rules.add(f"Line {line_num}: 无法处理的白名单规则 - {line}")
                continue

            # 处理标准Adblock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                domain_match = ADBLOCK_DOMAIN.match(line) or re.search(r'\|\|([\w.-]+)', line)
                if domain_match:
                    domain = domain_match.group(1)
                    if is_valid_domain(domain):
                        rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                    else:
                        rejected_rules.add(f"Line {line_num}: 无效域名 - {line}")
                continue

            # 处理Hosts规则
            hosts_match = HOSTS_RULE.match(line)
            if hosts_match:
                domain = hosts_match.group(2)
                if is_valid_domain(domain):
                    rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                else:
                    rejected_rules.add(f"Line {line_num}: 无效hosts域名 - {line}")
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
                        rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                    else:
                        rejected_rules.add(f"Line {line_num}: URL规则中无效域名 - {line}")
                continue

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and is_valid_domain(line):
                rules.add(f"DOMAIN-SUFFIX,{line},REJECT")
                continue

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                # 转换为Clash兼容的通配符格式
                converted = convert_wildcard_rule(line)
                if converted and is_valid_rule(converted):
                    rules.add(f"{converted},REJECT")
                else:
                    rejected_rules.add(f"Line {line_num}: 无法处理的通配符规则 - {line}")
                continue

            # 处理正则表达式规则 (Mihomo支持DOMAIN-REGEX)
            if REGEX_RULE.match(line):
                # 移除前后的斜杠
                regex_pattern = line[1:-1]
                # 简化常见正则模式
                simplified_regex = simplify_regex(regex_pattern)
                if simplified_regex:
                    rules.add(f"DOMAIN-REGEX,{simplified_regex},REJECT")
                else:
                    rejected_rules.add(f"Line {line_num}: 无法处理的正则规则 - {line}")
                continue

            # 处理修饰符规则 (包含$的规则)
            if MODIFIER_RULE.match(line):
                # 尝试提取基本规则部分
                base_rule = line.split('$')[0]
                if base_rule and is_valid_rule(base_rule):
                    # 处理基本规则
                    if base_rule.startswith('||'):
                        domain = base_rule[2:]
                        if is_valid_domain(domain):
                            rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                    elif base_rule.startswith('|http'):
                        url_match = re.search(r'://([^/]+)', base_rule)
                        if url_match:
                            domain = url_match.group(1)
                            if is_valid_domain(domain):
                                rules.add(f"DOMAIN,{domain},REJECT")
                else:
                    rejected_rules.add(f"Line {line_num}: 无法处理的修饰符规则 - {line}")
                continue

            # 处理其他规则（如果包含IP地址）
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if ip_match:
                ip = ip_match.group(0)
                if IP_ADDRESS.match(ip):
                    rules.add(f"IP-CIDR,{ip}/32,REJECT")
                continue

            # 无法识别的规则
            rejected_rules.add(f"Line {line_num}: 无法识别的规则格式 - {line}")

    # 输出被拒绝的规则信息
    if rejected_rules:
        print(f"警告: 跳过 {len(rejected_rules)} 条无法处理的规则", file=sys.stderr)
        for rule in sorted(rejected_rules):
            print(rule, file=sys.stderr)
    
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


def is_valid_rule(rule):
    """验证规则有效性"""
    # 基本长度检查
    if not rule or len(rule) > 200:
        return False

    # 检查是否包含无效字符
    if re.search(r'[^\w\.\-\*\/\,\:\$\@]', rule):
        return False

    return True


def convert_wildcard_rule(wildcard_rule):
    """转换通配符规则为Clash兼容格式"""
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
    if '.' in wildcard_rule:
        return f"DOMAIN-SUFFIX,{wildcard_rule}"
    else:
        return f"DOMAIN-KEYWORD,{wildcard_rule}"


def simplify_rule(rule):
    """简化规则以适应Clash"""
    # 移除修饰符部分
    if '$' in rule:
        parts = rule.split('$')
        return parts[0]

    return rule


def simplify_regex(regex_pattern):
    """简化正则表达式模式"""
    # 常见的Adblock正则模式简化
    simplifications = {
        r'^.*\.example\.com$': r'\.example\.com$',
        r'^example\.com.*$': r'^example\.com',
    }
    
    # 检查是否可以直接简化
    for complex_pattern, simple_pattern in simplifications.items():
        if re.match(complex_pattern, regex_pattern):
            return simple_pattern
    
    # 如果不能简化，返回原始模式（Mihomo支持正则）
    return regex_pattern


def write_output(rules):
    """写入输出文件，包含Mihomo兼容的头部信息"""
    # 将规则转换为Clash YAML格式
    clash_rules = []
    for rule in sorted(rules):
        clash_rules.append(f"  - {rule}")

    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('# Mihomo 广告规则\n')
        f.write('# 由AdBlock规则转换生成\n')
        f.write('# 更新时间: ' + str(os.path.getmtime(INPUT_FILE)) + '\n')
        f.write('payload:\n')
        f.write('\n'.join(clash_rules) + '\n')

    print(f"成功生成Mihomo规则: {len(rules)} 条")
    print(f"输出文件: {OUTPUT_FILE}")


if __name__ == '__main__':
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 处理文件
    rules = process_file()

    # 写入输出
    write_output(rules)