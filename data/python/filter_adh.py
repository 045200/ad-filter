#!/usr/bin/env python3
"""
AdGuard Home 规则转换器
输入: 
  - adblock_intermediate.txt (黑名单)
  - allow_intermediate.txt (白名单)
输出: 
  - adblock_adh.txt (黑名单规则)
  - allow_adh.txt (白名单规则)
功能:
  1. 分别处理黑白名单文件
  2. 严格过滤对应语法的规则
  3. 自动去重处理
  4. 支持DNS重写和hosts规则转换
"""

import os
import re
import logging
from pathlib import Path

# 文件配置
BLACK_INPUT = "adblock_intermediate.txt"
WHITE_INPUT = "allow_intermediate.txt"
BLACK_OUTPUT = "adblock_adh.txt"
WHITE_OUTPUT = "allow_adh.txt"

def setup_logger():
    """配置日志记录器"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

def convert_black_rule(line: str) -> str:
    """转换黑名单规则为AdGuard Home格式"""
    # DNS重写规则 (||example.com^)
    if line.startswith('||') and line.endswith('^'):
        return f"{line}$important"
    
    # Hosts规则 (0.0.0.0 example.com)
    if re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$', line):
        parts = line.split()
        return f"||{parts[1]}^$dnsrewrite=NOERROR;A;{parts[0]}"
    
    # 标准规则 (example.com)
    if re.match(r'^[\w.-]+$', line):
        return f"||{line}^"
    
    return None

def convert_white_rule(line: str) -> str:
    """转换白名单规则为AdGuard Home格式"""
    # 标准白名单规则 (@@||example.com^)
    if line.startswith('@@||') and line.endswith('^'):
        return line
    
    # 简化白名单规则 (example.com)
    if re.match(r'^[\w.-]+$', line):
        return f"@@||{line}^"
    
    return None

def process_file(input_path: Path, is_blacklist: bool):
    """处理输入文件并返回转换后的规则集合"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return set()
    
    converter = convert_black_rule if is_blacklist else convert_white_rule
    rule_type = "黑名单" if is_blacklist else "白名单"
    unique_rules = set()
    skipped_count = 0
    
    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
                
            # 转换规则
            converted = converter(line)
            if converted:
                unique_rules.add(converted)
            else:
                skipped_count += 1
    
    logger.info(f"处理{rule_type}规则: 输入 {len(unique_rules)+skipped_count} 条, "
                f"有效 {len(unique_rules)} 条, 跳过 {skipped_count} 条")
    return unique_rules

def write_output(rules: set, output_path: Path):
    """将规则写入输出文件"""
    with output_path.open('w', encoding='utf-8') as f:
        for rule in sorted(rules):  # 排序保证输出一致性
            f.write(rule + '\n')
    logger.info(f"生成 {output_path.name}: {len(rules)} 条规则")

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 处理黑名单
    black_rules = process_file(repo_root / BLACK_INPUT, is_blacklist=True)
    write_output(black_rules, repo_root / BLACK_OUTPUT)
    
    # 处理白名单
    white_rules = process_file(repo_root / WHITE_INPUT, is_blacklist=False)
    write_output(white_rules, repo_root / WHITE_OUTPUT)
    
    # 交叉检查重复规则
    duplicates = black_rules & white_rules
    if duplicates:
        logger.warning(f"发现 {len(duplicates)} 条重复规则存在于黑白名单中")
        for rule in sorted(duplicates):
            logger.warning(f"重复规则: {rule}")

if __name__ == "__main__":
    main()