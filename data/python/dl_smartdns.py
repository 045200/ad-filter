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
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# 配置日志 - 使用GitHub Actions友好的格式
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('SmartDNSRuleDownloader')

# 配置
class Config:
    BASE_DIR = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    SOURCES_FILE = BASE_DIR / "data" / "smartdns_sources.txt"
    OUTPUT_DIR = BASE_DIR / "data" / "sources"
    CACHE_DIR = BASE_DIR / "data" / "cache"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    MAX_RETRIES = 3  # 最大重试次数
    BACKOFF_FACTOR = 0.5  # 退避因子

# SmartDNS规则源列表
DEFAULT_SMARTDNS_SOURCES = [
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-smartdns.conf",
    "https://raw.githubusercontent.com/Olixn/china_list_for_smartdns/refs/heads/main/chinalist.domain.smartdns.conf",
    "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/smartdns.conf",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

# 预编译正则表达式以提高性能
SMARTDNS_PATTERN = re.compile(r'^address\s+/([^/]+)/')
HOSTS_PATTERN = re.compile(r'^\d+\.\d+\.\d+\.\d+\s+([\w.-]+)')
ADVERTISING_BLOCK_PATTERN = re.compile(r'^\|\|([\w.-]+)\^')

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
            logger.info(f"Loaded {len(custom_sources)} custom sources from {Config.SOURCES_FILE}")
        except Exception as e:
            logger.error(f"Failed to load custom sources: {e}")
    return custom_sources

def create_session():
    """创建带有重试机制的会话对象"""
    session = requests.Session()
    retry = Retry(
        total=Config.MAX_RETRIES,
        backoff_factor=Config.BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({'User-Agent': Config.USER_AGENT})
    return session

def download_file(url, output_path, session):
    """下载文件"""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download {url}: {e}")
        return False

def extract_domain_from_smartdns_rule(rule):
    """从SmartDNS规则中提取域名"""
    rule = rule.strip()

    # 跳过注释和空行
    if not rule or rule.startswith(('#', '!', '/')):
        return None

    # 匹配SmartDNS规则格式: address /domain/0.0.0.0
    match = SMARTDNS_PATTERN.match(rule)
    if match:
        return match.group(1)

    # 匹配hosts格式: 0.0.0.0 domain
    match = HOSTS_PATTERN.match(rule)
    if match:
        return match.group(1)

    # 匹配Adblock格式: ||domain.com^
    match = ADVERTISING_BLOCK_PATTERN.match(rule)
    if match:
        return match.group(1)

    return None

def process_smartdns_rules(input_file, output_file):
    """处理SmartDNS规则文件，提取域名"""
    domains = set()

    try:
        with open(input_file, 'r', encoding='utf-8') as fin:
            for line in fin:
                domain = extract_domain_from_smartdns_rule(line)
                if domain:
                    domains.add(domain)

        # 保存提取的域名
        with open(output_file, 'w', encoding='utf-8') as fout:
            for domain in sorted(domains):
                fout.write(f"{domain}\n")

        return len(domains)
    except Exception as e:
        logger.error(f"Failed to process file {input_file}: {e}")
        return 0

def sanitize_filename(text):
    """清理文本中的非法文件名字符"""
    # 替换Windows/Linux文件名中的非法字符
    return re.sub(r'[\\/*?:"<>|]', '_', text)

def main():
    """主函数"""
    logger.info("Starting SmartDNS rules download")

    # 确保输出目录存在
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 获取所有规则源
    all_sources = DEFAULT_SMARTDNS_SOURCES + load_custom_sources()
    logger.info(f"Total sources to process: {len(all_sources)}")

    # 创建带重试机制的会话
    session = create_session()

    # 下载并处理每个规则源
    successful_downloads = 0
    source_stats = {}  # 存储每个源的规则数量
    
    for i, url in enumerate(all_sources):
        try:
            # 生成安全的文件名
            parsed_url = urlparse(url)
            safe_netloc = sanitize_filename(parsed_url.netloc)
            safe_path = sanitize_filename(parsed_url.path.split('/')[-1])
            filename = f"smartdns_source_{i}_{safe_netloc}_{safe_path}"

            # 下载文件
            raw_file = Config.OUTPUT_DIR / f"{filename}_raw.txt"
            processed_file = Config.OUTPUT_DIR / f"{filename}_processed.txt"

            if download_file(url, raw_file, session):
                # 处理文件并获取规则数量
                rule_count = process_smartdns_rules(raw_file, processed_file)
                if rule_count > 0:
                    successful_downloads += 1
                    source_stats[url] = rule_count
                    logger.debug(f"Processed {url}: {rule_count} rules")

            # 根据响应时间动态调整睡眠间隔
            time.sleep(min(1, max(0.1, 1 / (i + 1))))

        except Exception as e:
            logger.error(f"Error processing source {url}: {e}")

    # 输出统计结果
    total_rules = sum(source_stats.values())
    
    print(f"::set-output name=downloaded_sources::{successful_downloads}")
    print(f"::set-output name=total_sources::{len(all_sources)}")
    print(f"::set-output name=total_rules::{total_rules}")
    
    logger.info("=" * 50)
    logger.info("DOWNLOAD SUMMARY:")
    logger.info(f"Downloaded sources: {successful_downloads}/{len(all_sources)}")
    logger.info(f"Total rules: {total_rules}")
    
    # 输出每个源的规则数量
    for url, count in source_stats.items():
        logger.info(f"  {url}: {count} rules")

if __name__ == '__main__':
    main()