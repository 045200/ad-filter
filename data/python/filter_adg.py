#!/usr/bin/env python3
"""
AdGuard 规则转换器 - 混合语法处理 (方案一)
黑名单存在白名单则提取到白名单
白名单存在黑名单则跳过
输入: 
  - adblock_intermediate.txt (黑名单)
  - allow_intermediate.txt (白名单)
输出:
  - adblock_adg.txt (纯净黑名单)
  - allow_adg.txt (纯净白名单)
"""

import os
import re
import logging
from pathlib import Path

# 配置
BLOCK_INPUT = "adblock_intermediate.txt"
ALLOW_INPUT = "allow_intermediate.txt"
BLOCK_OUTPUT = "adblock_adg.txt"
ALLOW_OUTPUT = "allow_adg.txt"

# 日志配置
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# AdGuard支持的修饰符列表
SUPPORTED_MODIFIERS = [
    'domain', 'third-party', 'script', 'image', 'stylesheet', 'object',
    'xmlhttprequest', 'subdocument', 'ping', 'websocket', 'webrtc', 'document',
    'elemhide', 'genericblock', 'generichide', 'important', 'popup',
    'csp', 'redirect', 'removeparam', 'badfilter', 'all', 'inline-script',
    'removeheader', 'hls', 'jsonprune', 'app', 'network', 'dnsrewrite',
    'replace', 'cname', 'dnstype', 'dns'
]

def is_allow_rule(line: str) -> bool:
    """判断是否为白名单规则"""
    # 注释行不算规则
    if not line or line.startswith(('!', '#', '[Adblock')):
        return False
    
    # 明确的白名单标记
    if line.startswith(('@@', '#@#')):
        return True
    
    # 包含白名单修饰符
    if '$badfilter' in line or '$generichide' in line:
        return True
    
    return False

def convert_rule(line: str) -> str:
    """转换规则为AdGuard格式，过滤不支持的修饰符"""
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
                if mod_name in SUPPORTED_MODIFIERS:
                    valid_modifiers.append(f"{mod_name}={mod_value}")
            else:
                if mod in SUPPORTED_MODIFIERS:
                    valid_modifiers.append(mod)

        # 重新组装规则
        if valid_modifiers:
            return f"{base_rule}${','.join(valid_modifiers)}"
    
    return line

def process_files(block_input: Path, allow_input: Path, block_output: Path, allow_output: Path):
    """处理所有文件，按照方案一处理混合语法"""
    # 存储从黑名单中提取的白名单规则
    extracted_allow_rules = []
    
    # 处理黑名单文件
    block_count = 0
    extracted_count = 0
    try:
        with block_input.open('r', encoding='utf-8') as fin_block, \
             block_output.open('w', encoding='utf-8') as fout_block:
            
            for line in fin_block:
                line = line.strip()
                if not line:
                    fout_block.write('\n')
                    continue
                    
                # 注释行直接写入
                if line.startswith(('!', '#', '[Adblock')):
                    fout_block.write(line + '\n')
                    continue
                
                # 转换规则
                converted = convert_rule(line)
                
                # 如果是白名单规则，提取到白名单列表
                if is_allow_rule(converted):
                    extracted_allow_rules.append(converted)
                    extracted_count += 1
                    continue
                
                # 写入黑名单规则
                fout_block.write(converted + '\n')
                block_count += 1
                
    except Exception as e:
        logger.error(f"处理黑名单文件失败: {str(e)}")
        return 0, 0
    
    # 处理白名单文件
    allow_count = 0
    skipped_count = 0
    try:
        with allow_input.open('r', encoding='utf-8') as fin_allow, \
             allow_output.open('w', encoding='utf-8') as fout_allow:
            
            for line in fin_allow:
                line = line.strip()
                if not line:
                    fout_allow.write('\n')
                    continue
                    
                # 注释行直接写入
                if line.startswith(('!', '#', '[Adblock')):
                    fout_allow.write(line + '\n')
                    continue
                
                # 转换规则
                converted = convert_rule(line)
                
                # 如果不是白名单规则，跳过
                if not is_allow_rule(converted):
                    skipped_count += 1
                    continue
                
                # 写入白名单规则
                fout_allow.write(converted + '\n')
                allow_count += 1
            
            # 写入从黑名单中提取的白名单规则
            for rule in extracted_allow_rules:
                fout_allow.write(rule + '\n')
                allow_count += 1
                
    except Exception as e:
        logger.error(f"处理白名单文件失败: {str(e)}")
        return block_count, 0
    
    logger.info(f"黑名单处理: 保留 {block_count} 条规则, 提取 {extracted_count} 条白名单规则")
    logger.info(f"白名单处理: 保留 {allow_count - extracted_count} 条规则, 跳过 {skipped_count} 条非白名单规则")
    
    return block_count, allow_count

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 处理文件
    block_count, allow_count = process_files(
        repo_root / BLOCK_INPUT,
        repo_root / ALLOW_INPUT,
        repo_root / BLOCK_OUTPUT,
        repo_root / ALLOW_OUTPUT
    )
    
    logger.info(f"生成 {BLOCK_OUTPUT}: {block_count} 条黑名单规则")
    logger.info(f"生成 {ALLOW_OUTPUT}: {allow_count} 条白名单规则")

if __name__ == "__main__":
    main()
