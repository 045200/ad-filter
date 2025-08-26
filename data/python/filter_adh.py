#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
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
SYNTAX_DB_PATH = Path(GITHUB_WORKSPACE) / "data" / "python" / "adblock_syntax_db.json"

# 加载语法库
def load_syntax_db():
    """加载语法库JSON文件"""
    if not SYNTAX_DB_PATH.exists():
        logging.warning(f"语法库文件 {SYNTAX_DB_PATH} 不存在，使用内置默认值")
        return None
    
    try:
        with open(SYNTAX_DB_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"加载语法库失败: {e}")
        return None

# 预编译正则表达式模式
def compile_patterns(syntax_db):
    """预编译语法库中的正则表达式模式"""
    patterns = {}
    
    if syntax_db and "syntax_patterns" in syntax_db:
        for pattern_name, pattern_str in syntax_db["syntax_patterns"].items():
            try:
                patterns[pattern_name] = re.compile(pattern_str)
            except re.error as e:
                logging.warning(f"无法编译模式 {pattern_name}: {pattern_str}, 错误: {e}")
    
    return patterns

# 加载语法库和预编译模式
SYNTAX_DB = load_syntax_db()
COMPILED_PATTERNS = compile_patterns(SYNTAX_DB)

# 从语法库获取支持的修饰符
def get_supported_modifiers():
    """从语法库获取AdGuard Home支持的修饰符"""
    if SYNTAX_DB and "adguard_home_specific" in SYNTAX_DB:
        home_specific = SYNTAX_DB["adguard_home_specific"]
        if "special_modifiers" in home_specific:
            # 添加$前缀
            return {'$' + mod for mod in home_specific["special_modifiers"]}
    
    # 默认值（如果语法库不可用）
    return {
        '$important', '$third-party', '~third-party', '$domain', '$client',
        '$dnstype', '$ctag', '$badfilter', '$subdomain', '$ip', '$all',
        '$regexp', '$denyallow'
    }

# 从语法库获取不支持的规则元素
def get_unsupported_elements():
    """从语法库获取AdGuard Home不支持的规则元素"""
    if SYNTAX_DB and "adguard_home_specific" in SYNTAX_DB:
        home_specific = SYNTAX_DB["adguard_home_specific"]
        if "unsupported_rule_types" in home_specific:
            # 转换为对应的语法元素
            unsupported = set()
            type_to_element = {
                "element_hiding_basic": "##",
                "element_hiding_exception": "#@#",
                "extended_css": "#?#",
                "adguard_scriptlet": "#%#",
                "adguard_redirect_rule": "$redirect=",
                "adguard_removeparam_rule": "$removeparam=",
                "adguard_csp_rule": "$csp=",
                "adguard_replace_rule": "$replace=",
                "adguard_cookie_rule": "$cookie="
            }
            
            for rule_type in home_specific["unsupported_rule_types"]:
                if rule_type in type_to_element:
                    unsupported.add(type_to_element[rule_type])
            
            return unsupported
    
    # 默认值（如果语法库不可用）
    return {
        '##', '#@#', '#%#', '#$#', '#+js', '#+css', '#+object', '#+frame',
        '#+xmlhttprequest', '#+websocket'
    }

# 从语法库获取不支持的操作修饰符
def get_unsupported_actions():
    """从语法库获取AdGuard Home不支持的操作修饰符"""
    if SYNTAX_DB and "adguard_home_specific" in SYNTAX_DB:
        home_specific = SYNTAX_DB["adguard_home_specific"]
        if "unsupported_rule_types" in home_specific:
            # 转换为对应的操作修饰符
            unsupported = set()
            type_to_action = {
                "adguard_redirect_rule": "$redirect=",
                "adguard_removeparam_rule": "$removeparam=",
                "adguard_csp_rule": "$csp=",
                "adguard_replace_rule": "$replace=",
                "adguard_cookie_rule": "$cookie="
            }
            
            for rule_type in home_specific["unsupported_rule_types"]:
                if rule_type in type_to_action:
                    unsupported.add(type_to_action[rule_type])
            
            return unsupported
    
    # 默认值（如果语法库不可用）
    return {
        '$removeparam', '$removeheader', '$redirect', '$csp', '$replace',
        '$set-cookie', '$remove-cookie', '$inject', '$substitute'
    }

# 使用语法库中的值
SUPPORTED_MODIFIERS = get_supported_modifiers()
UNSUPPORTED_ELEMENTS = get_unsupported_elements()
UNSUPPORTED_ACTIONS = get_unsupported_actions()

def extract_modifier_name(modifier_str: str) -> str:
    """提取修饰符名称（排除=后的参数，如$domain=example.com → $domain）"""
    if '=' in modifier_str:
        return f"${modifier_str.split('=')[0].strip()}"
    return f"${modifier_str.strip()}"

def is_compatible(rule: str) -> bool:
    """检查规则是否与AdGuard Home兼容（优先使用语法库）"""
    # 1. 使用语法库模式匹配（如果可用）
    if COMPILED_PATTERNS:
        for pattern_name, pattern in COMPILED_PATTERNS.items():
            if pattern.search(rule):
                # 检查此模式是否被AdGuard Home支持
                if (SYNTAX_DB and "adguard_home_specific" in SYNTAX_DB and 
                    "unsupported_rule_types" in SYNTAX_DB["adguard_home_specific"] and
                    pattern_name in SYNTAX_DB["adguard_home_specific"]["unsupported_rule_types"]):
                    logging.debug(f"规则类型 {pattern_name} 不被AdGuard Home支持: {rule}")
                    return False
    
    # 2. 排除不支持的规则元素（页面层功能）
    if any(elem in rule for elem in UNSUPPORTED_ELEMENTS):
        return False

    # 3. 排除不支持的操作修饰符（HTTP层功能）
    if any(action in rule for action in UNSUPPORTED_ACTIONS):
        return False

    # 4. 验证所有修饰符是否在支持列表中（处理带参数的修饰符，如$domain=abc.com）
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

    # 5. 验证正则规则格式（AGH要求正则规则必须用//包裹，且无嵌套）
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
    # 记录使用的语法库信息
    if SYNTAX_DB:
        logging.info(f"使用语法库: {SYNTAX_DB.get('version', '未知版本')}")
        logging.info(f"语法库描述: {SYNTAX_DB.get('description', '无描述')}")
    else:
        logging.info("使用内置默认语法规则")

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