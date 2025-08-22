#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
from pathlib import Path

# 配置参数
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
BLOCK_INPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
ALLOW_INPUT_FILE = Path(GITHUB_WORKSPACE) / "allow_allow.txt"
ABP_BLOCK_OUTPUT = Path(GITHUB_WORKSPACE) / "adblock_plus.txt"
ABP_ALLOW_OUTPUT = Path(GITHUB_WORKSPACE) / "adblock_plus_allow.txt"

# AdBlock Plus 不支持的特殊修饰符 (AdGuard/AdGuard Home 特有)
ABP_UNSUPPORTED_MODIFIERS = {
    '$dnsrewrite', '$cname', '$client', '$dnstype', '$denyallow',
    '$ctag', '$badfilter', '$redirect', '$removeheader', '$removeparam',
    '$app'
}

def convert_to_abp_format(rule, is_allow=False):
    """
    将 AdGuard 规则转换为 AdBlock Plus 格式。
    参考：https://adguard-dns.io/kb/zh-CN/general/dns-filtering-syntax/[citation:1]
    """
    # 注释和空行直接保留
    if rule.strip().startswith(('!', '#')) or not rule.strip():
        return rule

    # 处理白名单规则（例外规则）
    exception_prefix = "@@"
    is_exception = rule.startswith(exception_prefix)
    clean_rule = rule[len(exception_prefix):] if is_exception else rule

    # 检查并移除 AdBlock Plus 不支持的修饰符
    for modifier in ABP_UNSUPPORTED_MODIFIERS:
        # 确保修饰符前后有适当的边界（如$或逗号）
        pattern = r'[,$]' + re.escape(modifier) + r'([=,][^,$]+)?'
        clean_rule = re.sub(pattern, '', clean_rule)
        # 处理可能是唯一修饰符的情况
        if clean_rule.endswith('$' + modifier):
            clean_rule = clean_rule[:-len('$' + modifier)]
        elif clean_rule.endswith(',' + modifier):
            clean_rule = clean_rule[:-len(',' + modifier)]

    # 清理可能因移除修饰符而残留的尾随 $ 或 ,
    clean_rule = re.sub(r'[,&]?$', '', clean_rule) # 移除尾随的逗号或$
    if clean_rule.endswith('$'):
        clean_rule = clean_rule[:-1]

    # 对于白名单规则，加回 @@ 前缀
    if is_exception or is_allow:
        final_rule = exception_prefix + clean_rule
    else:
        final_rule = clean_rule

    return final_rule

def process_rules_for_abp(input_file, is_allow=False):
    """处理规则并转换为 AdBlock Plus 格式"""
    processed_rules = []
    seen_hashes = set()

    if not input_file.exists():
        print(f"警告：输入文件 {input_file} 不存在，跳过处理。")
        return processed_rules

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    # 保留注释和空行
                    processed_rules.append(line)
                    continue

                converted_rule = convert_to_abp_format(line, is_allow)
                # 简单的去重基于哈希
                rule_hash = hashlib.md5(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    processed_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    except Exception as e:
        print(f"处理文件 {input_file} 时出错: {e}")
    return processed_rules

def main():
    """主函数"""
    # 处理拦截规则
    block_rules = process_rules_for_abp(BLOCK_INPUT_FILE, is_allow=False)
    # 处理白名单规则
    allow_rules = process_rules_for_abp(ALLOW_INPUT_FILE, is_allow=True)

    # 写入输出文件
    try:
        with open(ABP_BLOCK_OUTPUT, 'w', encoding='utf-8') as f:
            f.write('\n'.join(block_rules) + '\n')
        with open(ABP_ALLOW_OUTPUT, 'w', encoding='utf-8') as f:
            f.write('\n'.join(allow_rules) + '\n')
        print(f"AdBlock Plus 规则转换完成。拦截规则: {len(block_rules)} 条, 白名单规则: {len(allow_rules)} 条")
    except Exception as e:
        print(f"写入输出文件时出错: {e}")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())