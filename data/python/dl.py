#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载处理脚本 - GitHub CI优化版
专注高效下载，保留规则注释与GitHub CI适配
"""

import os
import sys
import time
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============== GitHub环境变量配置 ==============
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
DATA_DIR = os.getenv('DATA_DIR', 'data')
TEMP_DIR = os.getenv('TEMP_DIR', 'tmp')

# ============== 下载优化配置 ==============
# 基于GitHub CI 4核CPU优化的线程数
MAX_WORKERS = 8  # 4核CPU推荐线程数（核心数×2）
REQUEST_TIMEOUT = 20  # 略微延长超时应对可能的CDN节点差异
MAX_RETRIES = 3  # 保持重试次数平衡效率与可靠性
RETRY_BACKOFF = 1.5  # 指数退避策略（1s, 1.5s, 2.25s）
HTTP_POOL_SIZE = 16  # 连接池大小，提升并发效率

# ============== 路径配置 ==============
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_PATH = BASE_DIR / TEMP_DIR

# ============== 日志配置 ==============
def setup_logger():
    """配置适应GitHub CI的日志系统"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # GitHub Actions环境使用分组兼容格式
    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('[%(levelname)s] %(message)s')

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ============== GitHub Actions支持 ==============
def gh_group(name):
    """GitHub Actions分组输出"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")

# ============== 环境准备 ==============
def prepare_environment():
    """准备下载所需的基础环境"""
    gh_group("准备下载环境")
    try:
        # 确保临时目录存在
        TEMP_PATH.mkdir(exist_ok=True, parents=True)
        logger.info(f"临时目录: {TEMP_PATH.relative_to(BASE_DIR)}")
        logger.info("环境准备完成")
        return True
    except Exception as e:
        logger.error(f"环境初始化失败: {str(e)[:100]}")
        sys.exit(1)
    finally:
        gh_endgroup()

# ============== 下载核心优化 ==============
def create_optimized_session():
    """创建优化的请求会话，提升下载性能"""
    session = requests.Session()
    
    # 配置重试策略：连接错误、超时、5xx状态码自动重试
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    
    # 配置连接池，复用TCP连接
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=HTTP_POOL_SIZE,
        pool_maxsize=HTTP_POOL_SIZE
    )
    
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # 优化请求头，模拟浏览器行为提升兼容性
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    })
    
    return session

def download_with_optimization(url, session):
    """优化的下载函数，支持自动编码检测和高效传输"""
    try:
        with session.get(url, timeout=REQUEST_TIMEOUT, stream=True) as resp:
            resp.raise_for_status()
            
            # 自动检测编码（优先从响应头获取）
            encoding = resp.encoding or resp.apparent_encoding or 'utf-8'
            
            # 流式读取提升大文件处理效率
            content = resp.content.decode(encoding, errors='replace')
            return content
    except Exception as e:
        raise Exception(f"下载失败: {str(e)[:100]}")

def process_single_url(url, prefix, index, session):
    """处理单个URL下载与保存"""
    try:
        content = download_with_optimization(url, session)
        filename = TEMP_PATH / f"{prefix}{index:02d}.txt"
        
        # 保留源URL注释并写入内容
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# 源地址: {url}\n")
            f.write(content)
        
        logger.info(f"✓ 成功: {url.split('/')[-1]}")  # 仅显示文件名简化日志
        return True
    except Exception as e:
        logger.error(f"✗ 失败: {url} - {str(e)}")
        return False

def batch_download(urls, prefix, start_index=1):
    """批量下载URL列表，跳过注释行"""
    # 筛选有效URL（跳过注释和空行）
    valid_urls = [
        url.strip() for url in urls 
        if url.strip() and not url.strip().startswith('#')
    ]
    
    if not valid_urls:
        logger.warning(f"没有有效的{prefix}规则URL")
        return 0, 0
    
    logger.info(f"开始下载{len(valid_urls)}个{prefix}规则...")
    session = create_optimized_session()
    success_count = 0
    
    try:
        # 并发处理下载任务
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(process_single_url, url, prefix, i, session): url
                for i, url in enumerate(valid_urls, start_index)
            }
            
            for future in as_completed(futures):
                if future.result():
                    success_count += 1
        return success_count, len(valid_urls)
    finally:
        session.close()

# ============== 规则列表（CDN加速优化）==============
# 拦截规则列表（优先使用CDN加速地址）
ADBLOCK_URLS = [
    # 大萌主-接口广告规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/damengzhu/banad@main/jiekouAD.txt",
    # DD-AD去广告规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/afwfv/DD-AD@main/rule/DD-AD.txt",
    # GitHub加速hosts（CDN加速）
    "https://cdn.jsdelivr.net/gh/hellogithub/hosts@main/hosts",
    # 晴雅去广告规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/790953214/qy-Ads-Rule@main/black.txt",
    # 海哥广告规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/2771936993/HG@main/hg1.txt",
    # FCM hosts规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/entr0pia/fcm-hosts@fcm/fcm-hosts",
    # 秋风广告规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/AWAvenue-Ads-Rule.txt",
    # 茯苓拦截规则（CDN加速）
    "https://cdn.jsdelivr.net/gh/Kuroba-Sayuki/FuLing-AdRules@main/FuLingRules/FuLingBlockList.txt"
]

# 白名单规则列表（优先使用CDN加速地址）
ALLOW_URLS = [
    # 那个谁520广告白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/qq5460168/EasyAds@refs/heads/main/allow.txt",
    # AdGuardHome通用白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/mphin/AdGuardHomeRules@main/Allowlist.txt",
    # 冷漠域名白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",
    # jhsvip白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/jhsvip/ADRuls@main/white.txt",
    # liwenjie119白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/liwenjie119/adg-rules@master/white.txt",
    # 喵二白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/miaoermua/AdguardFilter@main/whitelist.txt",
    # 茯苓白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/Kuroba-Sayuki/FuLing-AdRules@main/FuLingRules/FuLingAllowList.txt",
    # Cats-Team白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/Cats-Team/AdRules@script/script/allowlist.txt",
    # 浅笑白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/user001235/112@main/white.txt",
    # 酷安cocieto白名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/urkbio/adguardhomefilter@main/whitelist.txt",
    # anti-ad混合名单（CDN加速）
    "https://cdn.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/easylist.txt"
]

# ============== 主流程 ==============
def main():
    """主执行流程"""
    start_time = time.time()
    
    # 准备环境
    prepare_environment()
    
    # 下载规则
    gh_group("下载拦截规则")
    ad_success, ad_total = batch_download(ADBLOCK_URLS, "adblock")
    gh_endgroup()
    
    gh_group("下载白名单规则")
    allow_success, allow_total = batch_download(ALLOW_URLS, "allow")
    gh_endgroup()
    
    # 输出汇总信息
    total_time = time.time() - start_time
    gh_group("下载汇总")
    logger.info(f"总耗时: {total_time:.2f}秒")
    logger.info(f"拦截规则: 成功{ad_success}/{ad_total}")
    logger.info(f"白名单规则: 成功{allow_success}/{allow_total}")
    logger.info(f"总成功率: {(ad_success + allow_success) / (ad_total + allow_total) * 100:.1f}%")
    gh_endgroup()

if __name__ == "__main__":
    main()
