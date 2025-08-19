#!/usr/bin/env python3
"""
Hosts规则提取转换器（无头部信息版）
输入: adblock_intermediate.txt (中间规则文件)
输出: hosts.txt (纯Hosts规则，无头部注释)
处理包括: 提取可转换规则、转换为Hosts格式、去重、过滤无效条目
"""

import os
import re
import logging
from pathlib import Path

# 配置
INPUT_FILE = "adblock_intermediate.txt"
OUTPUT_FILE = "hosts.txt"
# Hosts规则目标IP（通常指向本地或黑洞IP）
TARGET_IP = "0.0.0.0"

# 日志配置
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# 无效域名模式（排除本地/内网地址）
INVALID_DOMAIN_PATTERNS = [
    r'^localhost$',
    r'^127\.0\.0\.1$',
    r'^::1$',
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # 排除IP地址
    r'^(\w+\.)?local$',  # 本地域名
    r'^(\w+\.)?lan$'     # 局域网域名
]

def is_valid_domain(domain: str) -> bool:
    """验证域名是否有效（适合Hosts规则）"""
    # 检查无效模式
    for pattern in INVALID_DOMAIN_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            return False
    
    # 验证域名格式（简化版）
    domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, domain) is not None

def extract_hosts_rules(line: str) -> list:
    """从规则中提取可转换为Hosts的域名"""
    # 跳过注释和空行
    if not line or line.startswith('!'):
        return []
    
    # 跳过白名单规则
    if line.startswith('@@'):
        return []
    
    # 跳过元素隐藏规则
    if '##' in line:
        return []
    
    # 提取域名的模式
    domain_patterns = [
        # 匹配 ||example.com 或 |example.com 格式
        r'\|{1,2}([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        # 匹配 domain=example.com 或 domain=*.example.com
        r'domain=(\*?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
    ]
    
    domains = []
    for pattern in domain_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            # 处理通配符（仅保留 *.example.com 中的 example.com）
            if match.startswith('*.'):
                domain = match[2:]
            else:
                domain = match
            
            # 清理域名中的特殊字符
            domain = domain.split('^')[0].split('/')[0].strip()
            
            if is_valid_domain(domain):
                domains.append(domain)
    
    # 去重并返回
    return list(set(domains))

def process_hosts_file(input_path: Path, output_path: Path):
    """处理输入文件并生成Hosts规则（无头部信息）"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return 0, 0, 0

    total_count = 0
    valid_count = 0
    duplicate_count = 0
    seen_domains = set()

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            # 不写入头部注释，仅保留纯规则
            for line in infile:
                total_count += 1
                line = line.strip()

                # 提取可转换的域名
                domains = extract_hosts_rules(line)
                for domain in domains:
                    # 去重处理
                    if domain in seen_domains:
                        duplicate_count += 1
                        continue
                    
                    # 写入Hosts规则（仅IP + 域名，无注释）
                    outfile.write(f"{TARGET_IP} {domain}\n")
                    seen_domains.add(domain)
                    valid_count += 1

    except Exception as e:
        logger.error(f"处理文件 {input_path} 失败: {str(e)}")

    return total_count, valid_count, duplicate_count

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))

    # 处理Hosts规则
    input_path = repo_root / INPUT_FILE
    output_path = repo_root / OUTPUT_FILE
    total, valid, duplicates = process_hosts_file(input_path, output_path)
    logger.info(f"处理Hosts规则: 输入 {total} 条规则, 输出 {valid} 条有效Hosts条目, 跳过 {duplicates} 条重复域名")

if __name__ == "__main__":
    main()
