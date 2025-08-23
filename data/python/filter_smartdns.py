#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
from pathlib import Path
from urllib.parse import urlparse

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adh.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adh.txt"
OUTPUT_SMARTDNS = Path(GITHUB_WORKSPACE) / "smartdns.conf"

# SmartDNS 支持的规则类型
SMARTDNS_RULE_TYPES = {'domain', 'full', 'regex'}

def is_compatible(rule):
    """检查规则是否与SmartDNS兼容"""
    # 跳过注释和空行
    if not rule or rule.startswith(('!', '#')):
        return False
    
    # 跳过元素隐藏规则
    if any(element in rule for element in {'##', '#@#', '#%#', '#$#'}):
        return False
    
    # 跳过不支持的修饰符
    unsupported_modifiers = {'$important', '~third-party', '$third-party', 
                           '$domain', '$client', '$dnstype', '$ctag', 
                           '$badfilter', '$removeparam', '$removeheader', 
                           '$redirect', '$csp', '$replace'}
    if any(modifier in rule for modifier in unsupported_modifiers):
        return False
    
    return True

def convert_to_smartdns(rule):
    """将AdGuard规则转换为SmartDNS格式"""
    # 处理例外规则（允许规则）
    is_allow = rule.startswith('@@')
    if is_allow:
        rule = rule[2:]  # 移除@@前缀
    
    # 处理基本域名规则
    if rule.startswith('||') and rule.endswith('^'):
        domain = rule[2:-1]
        if '*' in domain:
            # 通配符域名规则
            return f"domain:{domain}"
        else:
            # 完整域名规则
            return f"full:{domain}"
    
    # 处理精确匹配规则
    elif rule.startswith('|') and rule.endswith('|'):
        domain = rule[1:-1]
        # 提取域名部分（去除协议等）
        if '://' in domain:
            parsed = urlparse(domain)
            domain = parsed.hostname or parsed.path
        return f"full:{domain}"
    
    # 处理正则表达式规则
    elif rule.startswith('/') and rule.endswith('/'):
        # 移除正则标记
        regex_pattern = rule[1:-1]
        return f"regex:{regex_pattern}"
    
    # 处理普通域名规则
    elif re.match(r'^[a-zA-Z0-9.*-]+$', rule):
        if '*' in rule:
            return f"domain:{rule}"
        else:
            return f"full:{rule}"
    
    # 无法识别的规则类型
    return None

def process_file(input_path, is_allow=False):
    """处理输入文件并转换为SmartDNS规则"""
    output_rules = []
    seen_hashes = set()
    
    if not input_path.exists():
        print(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not is_compatible(line):
                    continue
                
                converted_rule = convert_to_smartdns(line)
                if converted_rule is None:
                    continue
                
                # 对于允许规则，添加whitelist前缀
                if is_allow:
                    converted_rule = f"whitelist {converted_rule}"
                else:
                    converted_rule = f"block {converted_rule}"
                
                rule_hash = hashlib.md5(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    output_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    except Exception as e:
        print(f"处理文件 {input_path} 时出错: {e}")
    
    return output_rules

def main():
    # 处理拦截规则
    block_rules = process_file(INPUT_BLOCK, is_allow=False)
    
    # 处理允许规则（白名单）
    allow_rules = process_file(INPUT_ALLOW, is_allow=True)
    
    # 合并规则（白名单优先）
    all_rules = allow_rules + block_rules
    
    try:
        with open(OUTPUT_SMARTDNS, 'w', encoding='utf-8') as f:
            f.write("# SmartDNS 规则配置\n")
            f.write("# 由 AdGuard Home 规则转换生成\n\n")
            f.write('\n'.join(all_rules) + '\n')
        
        print(f"SmartDNS 规则转换完成。总规则数: {len(all_rules)}")
        print(f"输出文件: {OUTPUT_SMARTDNS}")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())