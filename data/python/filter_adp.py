#!/usr/bin/env python3
"""
AdBlock Plus 规则转换器
输入: adblock_intermediate.txt (黑名单) 和 allow_intermediate.txt (白名单)
输出: adblock_abp.txt (黑名单规则) 和 allow_abp.txt (白名单规则)
处理包括: 语法转换、去重、黑白名单分离
"""

import os
import re
import logging
from pathlib import Path

# 配置
INPUT_FILE = "adblock_intermediate.txt"
ALLOW_INPUT_FILE = "allow_intermediate.txt"
OUTPUT_FILE = "adblock_abp.txt"
ALLOW_OUTPUT_FILE = "allow_abp.txt"

# 日志配置
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ABP支持的修饰符列表
SUPPORTED_MODIFIERS = [
    'domain', 'third-party', 'script', 'image', 'stylesheet', 'object',
    'xmlhttprequest', 'subdocument', 'ping', 'websocket', 'webrtc', 'document',
    'elemhide', 'genericblock', 'generichide', 'important', 'popup', 'csp',
    'redirect', 'removeparam', 'badfilter', 'all', 'match-case'
]

# ABP不支持的修饰符（这些将被移除）
UNSUPPORTED_MODIFIERS = [
    'dnsrewrite', 'dnstype', 'ctag', 'hls', 'jsonprune', 'app', 'extension',
    'redirect-rule', 'replace', 'cname', 'denyallow', 'header', 'redirect='
]

# ABP不支持的规则类型
UNSUPPORTED_RULE_TYPES = [
    '##^script:has', '##^script:has-text', '##:has', '##:has-text',
    '##^meta:has', '##^meta:has-text', '##+js', '##:style'
]

def convert_to_abp(line: str) -> str:
    """转换规则为ABP格式，移除不支持的语法"""
    # 保留空行
    if not line:
        return ""
    
    # 去除头信息标记
    if line.startswith(('[Adblock', '! Title:', '! Version:', '! Last modified:', '! Expires:', '! Homepage:', '! License:')):
        return ""
    
    # 保留普通注释
    if line.startswith('!'):
        return line
    
    # 处理带有修饰符的规则
    if '$' in line:
        base_rule, modifiers = line.split('$', 1)
        base_rule = base_rule.strip()
        modifiers = modifiers.strip()
        
        # 过滤不支持的修饰符
        valid_modifiers = []
        for mod in modifiers.split(','):
            mod = mod.strip()
            if not mod:
                continue
                
            # 处理带值的修饰符
            if '=' in mod:
                mod_name, mod_value = mod.split('=', 1)
                mod_name = mod_name.strip()
                
                # 只支持特定带值修饰符
                if mod_name in ['csp', 'redirect', 'removeparam']:
                    # 注意：ABP的redirect只支持预定义的资源名称
                    if mod_name == 'redirect' and not re.match(r'^[\w-]+$', mod_value):
                        continue
                    valid_modifiers.append(f"{mod_name}={mod_value}")
            else:
                # 检查修饰符是否支持
                if mod in SUPPORTED_MODIFIERS:
                    valid_modifiers.append(mod)
        
        # 重新组装规则
        if valid_modifiers:
            return f"{base_rule}${','.join(valid_modifiers)}"
        else:
            return base_rule
    
    # 检查是否为不支持的规则类型
    for pattern in UNSUPPORTED_RULE_TYPES:
        if line.startswith(pattern):
            return ""
    
    # 处理基础规则
    return line

def is_valid_abp_rule(rule: str) -> bool:
    """验证规则是否适用于ABP"""
    if not rule:
        return False
    
    # 保留注释
    if rule.startswith('!'):
        return True
    
    # 检查不支持的修饰符
    if any(unsupported in rule for unsupported in UNSUPPORTED_MODIFIERS):
        return False
    
    # 检查不支持的规则类型
    if any(pattern in rule for pattern in UNSUPPORTED_RULE_TYPES):
        return False
    
    # 检查规则格式
    if rule.startswith(('||', '|', '@@', '##', '#@#', '/')):
        return True
    
    # 检查域名规则
    if re.match(r'^[\w.-]+$', rule):
        return True
    
    return False

def process_file(input_path: Path, output_path: Path, is_whitelist: bool = False):
    """处理输入文件并输出转换后的规则（包含去重）"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return 0, 0, 0
    
    total_count = 0
    valid_count = 0
    duplicate_count = 0
    
    try:
        # 使用集合存储已出现的规则，实现去重
        seen_rules = set()
        
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:
            
            for line in infile:
                total_count += 1
                line = line.strip()
                
                # 转换规则
                converted = convert_to_abp(line)
                
                # 跳过空行
                if not converted:
                    continue
                    
                # 检查规则类型
                is_whitelist_rule = converted.startswith('@@')
                if is_whitelist and not is_whitelist_rule:
                    continue
                elif not is_whitelist and is_whitelist_rule:
                    continue
                
                # 验证规则
                if not is_valid_abp_rule(converted):
                    continue
                
                # 去重处理
                if converted in seen_rules:
                    duplicate_count += 1
                    continue
                
                # 写入唯一规则
                outfile.write(converted + '\n')
                seen_rules.add(converted)
                valid_count += 1
    
    except Exception as e:
        logger.error(f"处理文件 {input_path} 失败: {str(e)}")
    
    return total_count, valid_count, duplicate_count

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 处理黑名单
    input_path = repo_root / INPUT_FILE
    output_path = repo_root / OUTPUT_FILE
    total, valid, duplicates = process_file(input_path, output_path)
    logger.info(f"处理黑名单: 输入 {total} 条, 输出 {valid} 条有效规则, 跳过 {duplicates} 条重复规则")
    
    # 处理白名单
    allow_input_path = repo_root / ALLOW_INPUT_FILE
    allow_output_path = repo_root / ALLOW_OUTPUT_FILE
    allow_total, allow_valid, allow_duplicates = process_file(allow_input_path, allow_output_path, is_whitelist=True)
    logger.info(f"处理白名单: 输入 {allow_total} 条, 输出 {allow_valid} 条有效规则, 跳过 {allow_duplicates} 条重复规则")

if __name__ == "__main__":
    main()
