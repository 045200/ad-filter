#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
from pathlib import Path

# 配置参数
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
BLOCK_INPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
ALLOW_INPUT_FILE = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
BLOCK_OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adh.txt"
ALLOW_OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "allow_adh.txt"

# 正则表达式
DOMAIN_RULE = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^$', re.IGNORECASE)
WHITELIST_RULE = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^$', re.IGNORECASE)
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
REGEX_RULE = re.compile(r'^/.*/$')

# AdGuardHome 支持的修饰符
ADGUARD_HOME_MODIFIERS = {
    '$domain', '$client', '$important', '$dnstype', '$dnsrewrite',
    '$ctag', '$badfilter', '$redirect', '~third-party', '$third-party'
}

# AdGuardHome 不支持的修饰符
UNSUPPORTED_MODIFIERS = {
    '$script', '$image', '$stylesheet', '$popup', '$xmlhttprequest',
    '$object', '$object-subrequest', '$subdocument', '$ping', '$websocket',
    '$webrtc', '$other', '$document', '$font', '$media', '$match-case',
    '$empty', '$mp4', '$csp', '$replace', '$cookie', '$network', '$app',
    '$removeheader', '$removeparam'
}

def read_input_file(file_path):
    """读取输入文件"""
    rules = []
    if not file_path.exists():
        print(f"输入文件不存在: {file_path}")
        return rules
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 跳过空行和注释
                if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                    continue
                rules.append(line)
    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
    
    return rules

def is_adguard_home_compatible(rule: str) -> bool:
    """检查规则是否与AdGuard Home兼容"""
    # 跳过元素隐藏规则
    if '##' in rule:
        return False
    
    # 跳过正则表达式规则（AdGuard Home支持但需要特别处理）
    if REGEX_RULE.match(rule):
        return True  # AdGuard Home支持正则表达式
    
    # 检查是否包含AdGuard Home不支持的修饰符
    for modifier in UNSUPPORTED_MODIFIERS:
        if modifier in rule:
            return False
    
    return True

def extract_adguard_home_rules(rules, is_allow=False):
    """从AdGuard规则中提取AdGuardHome兼容的规则"""
    adguard_home_rules = []
    
    for rule in rules:
        try:
            # 检查规则是否兼容
            if not is_adguard_home_compatible(rule):
                continue
            
            # 处理正则表达式规则
            if REGEX_RULE.match(rule):
                adguard_home_rules.append(rule)
                continue
            
            # 处理白名单规则
            if is_allow:
                if WHITELIST_RULE.match(rule):
                    # 提取域名部分
                    domain = rule[4:-1]  # 移除 @@|| 和 ^
                    processed_rule = f"@@{domain}"
                    adguard_home_rules.append(processed_rule)
                    continue
                elif rule.startswith('@@'):
                    # 其他类型的白名单规则，尝试提取域名
                    domain_part = rule[2:]  # 移除 @@
                    if DOMAIN_RULE.match(f"||{domain_part}^"):
                        domain = domain_part[2:-1] if domain_part.startswith('||') and domain_part.endswith('^') else domain_part
                        processed_rule = f"@@{domain}"
                        adguard_home_rules.append(processed_rule)
                    else:
                        # 保留其他类型的白名单规则（如带有修饰符的）
                        adguard_home_rules.append(rule)
                    continue
            
            # 处理拦截规则
            else:
                if DOMAIN_RULE.match(rule):
                    # 提取域名部分
                    domain = rule[2:-1]  # 移除 || 和 ^
                    processed_rule = domain
                    adguard_home_rules.append(processed_rule)
                    continue
                elif rule.startswith('||') and rule.endswith('^'):
                    # 其他格式的域名规则
                    domain = rule[2:-1]
                    processed_rule = domain
                    adguard_home_rules.append(processed_rule)
                    continue
                else:
                    # 保留其他类型的拦截规则（如带有修饰符的）
                    adguard_home_rules.append(rule)
                    continue
        except Exception as e:
            print(f"处理规则时出错: {rule} - {e}")
            continue
    
    return adguard_home_rules

def write_output(rules, output_file, is_allow=False):
    """写入输出文件"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')
        print(f"已生成{'白名单' if is_allow else '拦截'}规则: {len(rules)} 条")
    except Exception as e:
        print(f"写入文件 {output_file} 时出错: {e}")

def main():
    """主函数"""
    try:
        # 读取输入文件
        block_rules = read_input_file(BLOCK_INPUT_FILE)
        allow_rules = read_input_file(ALLOW_INPUT_FILE)
        
        print(f"读取拦截规则: {len(block_rules)} 条")
        print(f"读取白名单规则: {len(allow_rules)} 条")
        
        # 处理规则
        processed_block = extract_adguard_home_rules(block_rules, is_allow=False)
        processed_allow = extract_adguard_home_rules(allow_rules, is_allow=True)
        
        # 写入输出
        write_output(processed_block, BLOCK_OUTPUT_FILE, is_allow=False)
        write_output(processed_allow, ALLOW_OUTPUT_FILE, is_allow=True)
        
        print("AdGuardHome规则提取完成!")
    except Exception as e:
        print(f"处理失败: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())