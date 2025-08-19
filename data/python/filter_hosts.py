#!/usr/bin/env python3
"""
Hosts规则提取与转换器（增强版）
功能：1. 提取中间文件中的原始Hosts规则 2. 转换其他拦截器规则为Hosts格式
输入: adblock_intermediate.txt
输出: hosts.txt（纯规则，无头部）
"""

import os
import re
import logging
from pathlib import Path

# 配置
INPUT_FILE = "adblock_intermediate.txt"
OUTPUT_FILE = "hosts.txt"
TARGET_IP = "0.0.0.0"  # 默认黑洞IP，原始Hosts中的IP会被保留

# 日志配置
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# 无效域名/IP模式
INVALID_DOMAIN_PATTERNS = [
    r'^localhost$', r'^127\.0\.0\.1$', r'^::1$',
    r'^(\w+\.)?local$', r'^(\w+\.)?lan$',
    r'^[\*]+$',  # 纯通配符
]

# 有效IP地址正则（用于匹配原始Hosts中的IP）
IP_PATTERN = r'^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$'  # IPv4/IPv6

def is_valid_domain(domain: str) -> bool:
    """验证域名有效性"""
    for pattern in INVALID_DOMAIN_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            return False
    # 基础域名格式（支持多级域名）
    return re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', domain) is not None

def is_valid_ip(ip: str) -> bool:
    """验证IP地址有效性（用于原始Hosts规则）"""
    return re.match(IP_PATTERN, ip) is not None

def extract_raw_hosts(line: str) -> tuple:
    """提取原始Hosts格式规则（IP 域名）"""
    line = line.strip()
    # 跳过注释（#开头）和空行
    if not line or line.startswith('#'):
        return None
    # 匹配 Hosts 格式：IP + 空格 + 域名（支持多空格）
    match = re.match(r'^(\S+)\s+(\S+)$', line)
    if not match:
        return None
    ip, domain = match.groups()
    # 验证IP和域名
    if is_valid_ip(ip) and is_valid_domain(domain):
        return (ip, domain)
    return None

def convert_to_hosts(line: str) -> list:
    """将其他拦截器规则转换为Hosts兼容的域名列表"""
    # 跳过白名单、元素隐藏、注释
    if not line or line.startswith(('!', '@@')) or '##' in line or '#@#' in line or '+js' in line:
        return []
    
    # 补充更多可转换的规则格式
    domain_patterns = [
        # AdBlock系列：||example.com、|example.com、*.example.com
        r'\|{1,2}([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        r'\*\.([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        
        # 修饰符中的域名：domain=example.com、domain=*.example.com
        r'domain=(\*?[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        
        # Clash/Surge/Pi-hole：直接域名或通配符域名
        r'^([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$',
        r'^@?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$',  # 含@前缀的规则
        
        # URL中的域名：http://example.com/... 或 https://...
        r'https?://([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        
        # 路径中的域名：/example.com/...
        r'/([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/'
    ]
    
    domains = []
    for pattern in domain_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            # 清理通配符和特殊字符
            domain = match.lstrip('*.@').split('/')[0].split('^')[0].strip()
            if is_valid_domain(domain) and domain not in domains:
                domains.append(domain)
    return domains

def process_hosts_file(input_path: Path, output_path: Path):
    """处理文件：提取原始Hosts + 转换其他规则"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return 0, 0, 0, 0

    total_lines = 0
    raw_hosts_count = 0  # 提取的原始Hosts数量
    converted_count = 0  # 转换的规则数量
    duplicates = 0
    seen_entries = set()  # 去重：存储 "IP 域名" 字符串

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            for line in infile:
                total_lines += 1
                line = line.strip()

                # 第一步：尝试提取原始Hosts规则
                raw_hosts = extract_raw_hosts(line)
                if raw_hosts:
                    ip, domain = raw_hosts
                    entry = f"{ip} {domain}"
                    if entry in seen_entries:
                        duplicates += 1
                        continue
                    outfile.write(f"{entry}\n")
                    seen_entries.add(entry)
                    raw_hosts_count += 1
                    continue  # 提取到原始Hosts后跳过转换

                # 第二步：转换其他拦截器规则为Hosts
                domains = convert_to_hosts(line)
                for domain in domains:
                    # 转换的规则使用默认TARGET_IP
                    entry = f"{TARGET_IP} {domain}"
                    if entry in seen_entries:
                        duplicates += 1
                        continue
                    outfile.write(f"{entry}\n")
                    seen_entries.add(entry)
                    converted_count += 1

    except Exception as e:
        logger.error(f"处理文件失败: {str(e)}")

    return total_lines, raw_hosts_count, converted_count, duplicates

def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    input_path = repo_root / INPUT_FILE
    output_path = repo_root / OUTPUT_FILE

    total, raw, converted, duplicates = process_hosts_file(input_path, output_path)
    logger.info(
        f"处理完成: 总规则 {total} 条, "
        f"提取原始Hosts {raw} 条, "
        f"转换规则 {converted} 条, "
        f"跳过重复 {duplicates} 条"
    )

if __name__ == "__main__":
    main()
