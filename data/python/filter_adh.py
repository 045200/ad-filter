#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import hashlib
from pathlib import Path
import logging

# 配置日志格式
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"
INPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adg.txt"
OUTPUT_BLOCK = Path(GITHUB_WORKSPACE) / "adblock_adh.txt"
OUTPUT_ALLOW = Path(GITHUB_WORKSPACE) / "allow_adh.txt"

# AdGuard Home 支持的修饰符 (DNS过滤层面)[citation:1][citation:13][citation:14]
SUPPORTED_MODIFIERS = {
    '$important', '~third-party', '$third-party', '$domain', '$client', 
    '$dnstype', '$ctag', '$badfilter', '$subdomain', '$ip', '$all', 
    '$regexp', '$document', '$script', '$image', '$object', 
    '$stylesheet', '$font', '$media', '$denyallow'
}

# 不支持的元素 (如元素隐藏、页面脚本规则)[citation:13][citation:14]
UNSUPPORTED_ELEMENTS = {
    '##', '#@#', '#%#', '#$#', '#+js', '#+css', '#+object', 
    '#+frame', '#+xmlhttprequest', '#+websocket'
}

# 不支持的重定向和移除类修饰符[citation:13][citation:14]
UNSUPPORTED_ACTIONS = {
    '$removeparam', '$removeheader', '$redirect', '$csp', '$replace', 
    '$set-cookie', '$remove-cookie', '$inject', '$substitute'
}

def is_compatible(rule: str) -> bool:
    """检查规则是否与AdGuard Home兼容[citation:1][citation:13][citation:14]"""
    if any(element in rule for element in UNSUPPORTED_ELEMENTS):
        return False
    for action in UNSUPPORTED_ACTIONS:
        if action in rule:
            return False
    
    # 检查修饰符有效性
    modifiers_part = rule.split('$')[-1] if '$' in rule else ''
    for modifier in modifiers_part.split(','):
        if modifier and modifier not in SUPPORTED_MODIFIERS:
            return False
    return True

def convert_rule(rule: str, is_allow: bool = False) -> str | None:
    """转换单条规则（此处主要进行过滤，AdGuard Home兼容AdGuard语法[citation:1][citation:13]）"""
    if not is_compatible(rule):
        return None
    
    # 处理例外规则的特殊符号
    if is_allow and not rule.startswith('@@'):
        return f'@@{rule}'
    return rule

def process_file(input_path: Path, is_allow: bool = False) -> list[str]:
    """处理输入文件"""
    output_rules = []
    seen_hashes = set()
    if not input_path.exists():
        logging.warning(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    output_rules.append(line)
                    continue

                converted_rule = convert_rule(line, is_allow)
                if converted_rule is None:
                    continue

                # 处理正则表达式规则
                if converted_rule.startswith('/') and converted_rule.endswith('/'):
                    converted_rule = converted_rule[1:-1]  # 移除前后斜杠
                
                rule_hash = hashlib.md5(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    output_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    except UnicodeDecodeError as e:
        logging.error(f"解码错误发生在文件 {input_path}: {e}")
    except IOError as e:
        logging.error(f"读写错误发生在文件 {input_path}: {e}")
    except Exception as e:
        logging.exception(f"未预期的错误发生在文件 {input_path}: {e}")
    return output_rules

def main() -> int:
    block_rules = process_file(INPUT_BLOCK, is_allow=False)
    allow_rules = process_file(INPUT_ALLOW, is_allow=True)

    try:
        with open(OUTPUT_BLOCK, 'w', encoding='utf-8') as f_block, open(OUTPUT_ALLOW, 'w', encoding='utf-8') as f_allow:
            # 处理正则表达式规则的特殊格式
            processed_block = []
            for rule in block_rules:
                if re.match(r'^/.*?$', rule):
                    processed_block.append(f'/{rule}/')
                else:
                    processed_block.append(rule)
            
            processed_allow = []
            for rule in allow_rules:
                if re.match(r'^/.*?$', rule):
                    processed_allow.append(f'@@/{rule}/')
                else:
                    processed_allow.append(f'@@{rule}')
            
            f_block.write('\n'.join(processed_block) + '\n')
            f_allow.write('\n'.join(processed_allow) + '\n')
        logging.info(f"AdGuard Home 规则转换完成。拦截: {len(block_rules)} 条, 允许: {len(allow_rules)} 条")
    except IOError as e:
        logging.error(f"写入输出文件时出错: {e}")
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
