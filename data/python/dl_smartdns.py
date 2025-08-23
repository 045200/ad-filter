#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SmartDNS规则下载器
下载并处理专门的SmartDNS规则源
"""

import os
import re
import requests
import time
from pathlib import Path
from urllib.parse import urlparse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SmartDNSRuleDownloader')

# 配置
class Config:
    BASE_DIR = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    SOURCES_FILE = BASE_DIR / "data" / "smartdns_sources.txt"
    OUTPUT_DIR = BASE_DIR / "data" / "sources"
    CACHE_DIR = BASE_DIR / "data" / "cache"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# SmartDNS规则源列表
DEFAULT_SMARTDNS_SOURCES = [
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-smartdns.conf",
    "https://raw.githubusercontent.com/Olixn/china_list_for_smartdns/refs/heads/main/chinalist.domain.smartdns.conf",
    "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/smartdns.conf",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

def load_custom_sources():
    """加载自定义规则源"""
    custom_sources = []
    if Config.SOURCES_FILE.exists():
        try:
            with open(Config.SOURCES_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom_sources.append(line)
            logger.info(f"从 {Config.SOURCES_FILE} 加载了 {len(custom_sources)} 个自定义规则源")
        except Exception as e:
            logger.error(f"加载自定义规则源失败: {e}")
    
    return custom_sources

def download_file(url, output_path):
    """下载文件"""
    try:
        headers = {'User-Agent': Config.USER_AGENT}
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        logger.info(f"成功下载: {url} -> {output_path}")
        return True
    except Exception as e:
        logger.error(f"下载失败 {url}: {e}")
        return False

def extract_domain_from_smartdns_rule(rule):
    """从SmartDNS规则中提取域名"""
    rule = rule.strip()
    
    # 跳过注释和空行
    if not rule or rule.startswith(('#', '!', '/')):
        return None
    
    # 匹配SmartDNS规则格式: address /domain/0.0.0.0
    smartdns_pattern = re.compile(r'^address\s+/([^/]+)/')
    match = smartdns_pattern.match(rule)
    if match:
        return match.group(1)
    
    # 匹配hosts格式: 0.0.0.0 domain
    hosts_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+\s+([\w.-]+)')
    match = hosts_pattern.match(rule)
    if match:
        return match.group(1)
    
    # 匹配Adblock格式: ||domain.com^
    adblock_pattern = re.compile(r'^\|\|([\w.-]+)\^')
    match = adblock_pattern.match(rule)
    if match:
        return match.group(1)
    
    return None

def process_smartdns_rules(input_file, output_file):
    """处理SmartDNS规则文件，提取域名"""
    domains = set()
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                domain = extract_domain_from_smartdns_rule(line)
                if domain:
                    domains.add(domain)
        
        # 保存提取的域名
        with open(output_file, 'w', encoding='utf-8') as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")
        
        logger.info(f"从 {input_file} 提取了 {len(domains)} 个域名到 {output_file}")
        return True
    except Exception as e:
        logger.error(f"处理文件 {input_file} 失败: {e}")
        return False

def main():
    """主函数"""
    logger.info("开始下载SmartDNS规则")
    
    # 确保输出目录存在
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 获取所有规则源
    all_sources = DEFAULT_SMARTDNS_SOURCES + load_custom_sources()
    logger.info(f"总共 {len(all_sources)} 个规则源需要处理")
    
    # 下载并处理每个规则源
    successful_downloads = 0
    for i, url in enumerate(all_sources):
        try:
            # 生成文件名
            parsed_url = urlparse(url)
            filename = f"smartdns_source_{i}_{parsed_url.netloc}_{parsed_url.path.split('/')[-1]}"
            filename = filename.replace('/', '_').replace('.', '_')
            
            # 下载文件
            raw_file = Config.OUTPUT_DIR / f"{filename}_raw.txt"
            processed_file = Config.OUTPUT_DIR / f"{filename}_processed.txt"
            
            if download_file(url, raw_file):
                # 处理文件
                if process_smartdns_rules(raw_file, processed_file):
                    successful_downloads += 1
            
            # 避免请求过于频繁
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"处理规则源 {url} 时出错: {e}")
    
    logger.info(f"SmartDNS规则下载完成，成功处理 {successful_downloads}/{len(all_sources)} 个规则源")

if __name__ == '__main__':
    main()