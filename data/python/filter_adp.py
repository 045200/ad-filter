#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import hashlib
from pathlib import Path

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adp.txt"
OUTPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adp.txt"

# AdBlock Plus (ABP) 不支持的修饰符 (相比AdGuard)
ABP_UNSUPPORTED_MODIFIERS = {
    '$dnsrewrite',  # DNS重写规则
    '$cname',       # CNAME规则
    '$client',      # 客户端IP规则
    '$dnstype',     # DNS类型规则
    '$denyallow',   # 拒绝允许规则
    '$ctag',       # 内容标签规则
    '$badfilter',   # 坏规则标记
    '$redirect',    # 重定向规则
    '$removeheader', # 移除HTTP头规则
    '$removeparam',  # 移除URL参数规则
    '$app'          # 应用规则
}

def convert_to_abp_format(rule, is_allow=False):
    """将AdGuard规则转换为AdBlock Plus格式[citation:2]"""
    if rule.strip().startswith(('!', '#')) or not rule.strip():
        return rule

    exception_prefix = "@@"
    is_exception = rule.startswith(exception_prefix)
    clean_rule = rule[len(exception_prefix):] if is_exception else rule

    # 构建正则表达式模式来匹配不支持的修饰符
    modifiers_pattern = r'[,$](' + '|'.join(re.escape(mod) for mod in ABP_UNSUPPORTED_MODIFIERS) + r')([=,][^,$]+)?'
    clean_rule = re.sub(modifiers_pattern, '', clean_rule)
    
    # 清理规则末尾可能多余的逗号或&符号
    clean_rule = re.sub(r'[,&]?$', '', clean_rule)
    if clean_rule.endswith('$'):
        clean_rule = clean_rule[:-1]

    if is_exception or is_allow:
        final_rule = exception_prefix + clean_rule
    else:
        final_rule = clean_rule

    return final_rule

def process_file(input_path, is_allow=False):
    output_rules = []
    seen_hashes = set()
    if not input_path.exists() or not os.access(input_path, os.R_OK):
        print(f"警告：输入文件 {input_path} 不存在或不可读，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')) or len(line.strip()) == 0:
                    output_rules.append(line)
                    continue

                converted_rule = convert_to_abp_format(line, is_allow)
                rule_hash = hashlib.sha256(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    output_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    except FileNotFoundError:
        print(f"错误：输入文件 {input_path} 不存在。")
    except PermissionError:
        print(f"错误：输入文件 {input_path} 不可读，权限不足。")
    except Exception as e:
        print(f"处理文件 {input_path} 时发生未知错误: {e}")
    return output_rules

def main():
    block_rules = process_file(INPUT_BLOCK, is_allow=False)
    allow_rules = process_file(INPUT_ALLOW, is_allow=True)

    def write_rules_to_file(file_path, rules):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(rules) + '\n')
        except Exception as e:
            print(f"写入文件 {file_path} 时出错: {e}")
            raise

    try:
        write_rules_to_file(OUTPUT_BLOCK, block_rules)
        write_rules_to_file(OUTPUT_ALLOW, allow_rules)
        print(f"AdBlock Plus 规则转换完成。拦截: {len(block_rules)} 条, 允许: {len(allow_rules)} 条")
    except Exception:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())