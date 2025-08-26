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

# 【核实来源】AdGuard Home 官方DNS过滤支持的修饰符（截至2024.5，参考AGH v0.107+文档）
# 仅保留DNS层可实现的修饰符，排除HTTP层/页面层修饰符
SUPPORTED_MODIFIERS = {
    '$important',    # 强制优先生效
    '$third-party',  # 仅匹配第三方请求
    '~third-party',  # 仅匹配第一方请求
    '$domain',       # 限制规则仅对指定域名生效（如$domain=example.com）
    '$client',       # 限制规则仅对指定客户端生效（IP/客户端名，如$client=192.168.1.100）
    '$dnstype',      # 限制规则仅对指定DNS记录类型生效（如$dnstype=A,AAAA）
    '$ctag',         # 规则分类标签（用于管理，如$ctag=ads）
    '$badfilter',    # 取消之前匹配的规则
    '$subdomain',    # 匹配子域名（如example.com$subdomain 匹配a.example.com）
    '$ip',           # 匹配目标IP（如$ip=192.168.1.0/24）
    '$all',          # 匹配所有请求类型（DNS层等效于无类型限制）
    '$regexp',       # 基于正则表达式匹配（需配合//包裹的规则）
    '$denyallow'     # 仅允许指定客户端/域名（例外逻辑）
}

# 【核实来源】AdGuard Home 不支持的规则元素（均为页面层/HTTP层功能）
UNSUPPORTED_ELEMENTS = {
    '##',            # 元素隐藏（浏览器扩展功能）
    '#@#',           # 元素隐藏例外（浏览器扩展功能）
    '#%#',           # CSS注入（浏览器扩展功能）
    '#$#',           # JS注入（浏览器扩展功能）
    '#+js',          # 脚本拦截（浏览器扩展/桌面端功能）
    '#+css',         # CSS拦截（浏览器扩展功能）
    '#+object',      # 对象拦截（浏览器扩展功能）
    '#+frame',       # 框架拦截（浏览器扩展功能）
    '#+xmlhttprequest', # XHR请求拦截（浏览器扩展功能）
    '#+websocket'    # WebSocket拦截（浏览器扩展功能）
}

# 【核实来源】AdGuard Home 不支持的操作修饰符（均为HTTP层功能）
UNSUPPORTED_ACTIONS = {
    '$removeparam',  # 移除URL参数（HTTP层功能）
    '$removeheader', # 移除HTTP头（HTTP层功能）
    '$redirect',     # 重定向请求（浏览器扩展/桌面端功能）
    '$csp',          # 设置CSP策略（HTTP层功能）
    '$replace',      # 替换页面内容（HTTP层功能）
    '$set-cookie',   # 设置Cookie（HTTP层功能）
    '$remove-cookie',# 删除Cookie（HTTP层功能）
    '$inject',       # 注入内容（HTTP层功能）
    '$substitute'    # 替换响应内容（HTTP层功能）
}

def extract_modifier_name(modifier_str: str) -> str:
    """提取修饰符名称（排除=后的参数，如$domain=example.com → $domain）"""
    if '=' in modifier_str:
        return f"${modifier_str.split('=')[0].strip()}"
    return f"${modifier_str.strip()}"

def is_compatible(rule: str) -> bool:
    """检查规则是否与AdGuard Home兼容（基于官方语法）"""
    # 1. 排除不支持的规则元素（页面层功能）
    if any(elem in rule for elem in UNSUPPORTED_ELEMENTS):
        return False
    
    # 2. 排除不支持的操作修饰符（HTTP层功能）
    if any(action in rule for action in UNSUPPORTED_ACTIONS):
        return False
    
    # 3. 验证所有修饰符是否在支持列表中（处理带参数的修饰符，如$domain=abc.com）
    if '$' in rule:
        # 分割规则主体与修饰符部分（仅处理最后一个$后的修饰符串）
        _, modifiers_part = rule.rsplit('$', 1)
        # 分割多个修饰符（如$domain=abc.com,third-party → ["domain=abc.com", "third-party"]）
        modifiers = modifiers_part.split(',')
        for mod in modifiers:
            if not mod:  # 跳过空修饰符（如规则末尾多一个逗号）
                continue
            mod_name = extract_modifier_name(mod)
            if mod_name not in SUPPORTED_MODIFIERS:
                logging.debug(f"不支持的修饰符 {mod_name}，规则 {rule} 被过滤")
                return False
    
    # 4. 验证正则规则格式（AGH要求正则规则必须用//包裹，且无嵌套）
    if rule.startswith('/') and not rule.endswith('/'):
        logging.debug(f"正则规则格式错误（缺少闭合/），规则 {rule} 被过滤")
        return False
    
    return True

def convert_rule(rule: str, is_allow: bool = False) -> str | None:
    """转换单条规则（仅保留AGH兼容规则，不修改语法结构）"""
    if not is_compatible(rule):
        return None
    
    # 处理允许规则：AGH要求例外规则必须以@@开头（避免重复添加）
    if is_allow:
        return rule if rule.startswith('@@') else f'@@{rule}'
    
    # 处理正则规则：确保无多余空格（如"/example\.com/" → 保留原格式）
    return rule.strip()

def process_file(input_path: Path, is_allow: bool = False) -> list[str]:
    """处理输入文件（保留注释/空行，去重，过滤不兼容规则）"""
    output_rules = []
    seen_hashes = set()
    
    if not input_path.exists():
        logging.warning(f"警告：输入文件 {input_path} 不存在，跳过处理。")
        return output_rules

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                original_line = line.strip()
                current_line = original_line

                # 1. 保留注释（!开头）、空行、配置指令（#开头，如# Title）
                if not current_line or current_line.startswith(('!', '#')):
                    output_rules.append(original_line)
                    continue

                # 2. 转换并检查兼容性
                converted_rule = convert_rule(current_line, is_allow)
                if converted_rule is None:
                    logging.debug(f"文件 {input_path} 第{line_num}行规则不兼容：{original_line}")
                    continue

                # 3. 去重（基于规则内容的MD5哈希）
                rule_hash = hashlib.md5(converted_rule.encode('utf-8')).hexdigest()
                if rule_hash not in seen_hashes:
                    output_rules.append(converted_rule)
                    seen_hashes.add(rule_hash)
    
    except UnicodeDecodeError as e:
        logging.error(f"文件 {input_path} 解码错误（编码非UTF-8）：{e}")
    except IOError as e:
        logging.error(f"文件 {input_path} 读写错误：{e}")
    except Exception as e:
        logging.exception(f"文件 {input_path} 处理异常（第{line_num}行）：{e}")
    
    return output_rules

def main() -> int:
    # 处理拦截规则和允许规则
    block_rules = process_file(INPUT_BLOCK, is_allow=False)
    allow_rules = process_file(INPUT_ALLOW, is_allow=True)

    try:
        # 写入输出文件（保留原始换行格式）
        with open(OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f_block, \
             open(OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f_allow:
            f_block.write('\n'.join(block_rules))
            f_allow.write('\n'.join(allow_rules))
        
        logging.info(f"AdGuard Home 规则转换完成：")
        logging.info(f"  - 拦截规则：{len(block_rules)} 条（输出至 {OUTPUT_BLOCK}）")
        logging.info(f"  - 允许规则：{len(allow_rules)} 条（输出至 {OUTPUT_ALLOW}）")
    
    except IOError as e:
        logging.error(f"输出文件写入错误：{e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
