#!/usr/bin/env python3
"""
Clash 规则转换器增强版
输入: 
  - adblock_intermediate.txt (黑名单)
  - allow_intermediate.txt (白名单)
输出: 
  - adblock_clash.yaml (合并后的规则集)
功能:
  1. 分别处理黑白名单文件
  2. 严格过滤对应语法的规则
  3. 自动去重处理
  4. 白名单规则使用DIRECT策略，黑名单使用REJECT策略
  5. 合并规则时白名单优先
"""

import os
import re
import logging
from pathlib import Path
import yaml

# 文件配置
BLACK_INPUT = "adblock_intermediate.txt"
WHITE_INPUT = "allow_intermediate.txt"
OUTPUT_FILE = "adblock_clash.yaml"

def setup_logger():
    """配置日志记录器"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

def convert_black_rule(line: str) -> dict:
    """转换黑名单规则为Clash格式"""
    rule = {}
    
    # DNS重写规则 (||example.com^)
    if line.startswith('||') and line.endswith('^'):
        rule['type'] = 'DOMAIN-SUFFIX'
        rule['value'] = line[2:-1]
        rule['policy'] = 'REJECT'
        return rule
    
    # Hosts规则 (0.0.0.0 example.com)
    if re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$', line):
        parts = line.split()
        rule['type'] = 'IP-CIDR'
        rule['value'] = f"{parts[0]}/32"
        rule['policy'] = 'REJECT'
        return rule
    
    # 标准域名规则 (example.com)
    if re.match(r'^[\w.-]+$', line):
        rule['type'] = 'DOMAIN-SUFFIX'
        rule['value'] = line
        rule['policy'] = 'REJECT'
        return rule
    
    return None

def convert_white_rule(line: str) -> dict:
    """转换白名单规则为Clash格式"""
    rule = {}
    
    # 标准白名单规则 (@@||example.com^)
    if line.startswith('@@||') and line.endswith('^'):
        rule['type'] = 'DOMAIN-SUFFIX'
        rule['value'] = line[4:-1]
        rule['policy'] = 'DIRECT'
        return rule
    
    # 简化白名单规则 (example.com)
    if re.match(r'^[\w.-]+$', line):
        rule['type'] = 'DOMAIN-SUFFIX'
        rule['value'] = line
        rule['policy'] = 'DIRECT'
        return rule
    
    return None

def process_file(input_path: Path, is_blacklist: bool) -> list:
    """处理输入文件并返回转换后的规则列表"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return []
    
    converter = convert_black_rule if is_blacklist else convert_white_rule
    rule_type = "黑名单" if is_blacklist else "白名单"
    rules = []
    seen_rules = set()
    skipped_count = 0
    
    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
                
            # 转换规则
            rule = converter(line)
            if rule:
                # 创建唯一标识符 (类型+值+策略)
                rule_key = f"{rule['type']}:{rule['value']}:{rule['policy']}"
                if rule_key not in seen_rules:
                    rules.append(rule)
                    seen_rules.add(rule_key)
                else:
                    skipped_count += 1
            else:
                skipped_count += 1
    
    logger.info(f"处理{rule_type}规则: 输入 {len(rules)+skipped_count} 条, "
                f"有效 {len(rules)} 条, 跳过 {skipped_count} 条")
    return rules

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 处理白名单 (优先处理，确保白名单规则在前)
    white_rules = process_file(repo_root / WHITE_INPUT, is_blacklist=False)
    
    # 处理黑名单
    black_rules = process_file(repo_root / BLACK_INPUT, is_blacklist=True)
    
    # 合并规则集 (白名单在前，黑名单在后)
    all_rules = white_rules + black_rules
    total_rules = len(all_rules)
    
    # 构建Clash规则集
    clash_ruleset = {'payload': all_rules}
    
    # 写入输出文件
    output_path = repo_root / OUTPUT_FILE
    with output_path.open('w', encoding='utf-8') as outfile:
        yaml.dump(clash_ruleset, outfile, allow_unicode=True, sort_keys=False)
    
    logger.info(f"生成 {OUTPUT_FILE}: {total_rules} 条规则 (白名单: {len(white_rules)}, 黑名单: {len(black_rules)})")

if __name__ == "__main__":
    main()