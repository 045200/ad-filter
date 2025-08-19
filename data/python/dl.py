#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载处理脚本 - 恢复注释版
保留所有原始注释远程源，同时新增CDN加速地址
"""

import os
import sys
import time
import shutil
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============== 环境变量与配置 ==============
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
MOD_PATH = DATA_DIR / 'mod'

# 4核16G环境优化参数
MAX_WORKERS = 4
REQUEST_TIMEOUT = 8
MAX_RETRIES = 2
RETRY_DELAY = 0.5
HTTP_CONN_POOL = 10

# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(levelname)s] %(message)s'
    handler.setFormatter(logging.Formatter(fmt))
    logger.handlers = [handler]
    return logger

logger = setup_logger()

# ============== GitHub Actions支持 ==============
def gh_group(name):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")

# ============== 环境准备 ==============
def clean_target_files():
    gh_group("清理文件")
    patterns = ['*.txt', '*.mrs', '*.yaml', '*.conf']
    deleted = 0
    for p in patterns:
        for f in BASE_DIR.glob(p):
            if f.is_file():
                f.unlink(missing_ok=True)
                deleted += 1
    logger.info(f"清理完成: {deleted}个文件")
    gh_endgroup()
    return deleted

def prepare_environment():
    gh_group("环境准备")
    for dir in [TEMP_DIR, DATA_DIR, MOD_PATH]:
        dir.mkdir(exist_ok=True, parents=True)
    
    local_files = {
        MOD_PATH / "adblock.txt": TEMP_DIR / "adblock01.txt",
        MOD_PATH / "whitelist.txt": TEMP_DIR / "allow01.txt"
    }
    copied = 0
    for src, dst in local_files.items():
        if src.exists():
            shutil.copyfile(src, dst)
            copied += 1
    logger.info(f"环境就绪: 复制{copied}个本地规则")
    gh_endgroup()

# ============== 高效下载逻辑 ==============
def create_session():
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=HTTP_CONN_POOL,
        pool_maxsize=MAX_WORKERS,
        pool_block=False
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    })
    session.max_redirects = 2
    return session

def download_with_retry(url, session):
    for attempt in range(MAX_RETRIES):
        try:
            with session.get(url, timeout=REQUEST_TIMEOUT, stream=False) as resp:
                resp.raise_for_status()
                if resp.encoding is None:
                    resp.encoding = 'utf-8'
                return resp.text
        except (requests.exceptions.RequestException, UnicodeDecodeError):
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(RETRY_DELAY)

def process_url(args):
    url, prefix, index, session = args
    try:
        content = download_with_retry(url, session)
        with open(TEMP_DIR / f"{prefix}{index:02d}.txt", 'w', encoding='utf-8', newline='\n') as f:
            f.write(f"# Source: {url}\n{content}")
        return True
    except Exception:
        return False

def download_all(urls, prefix, start_index=2):
    active_urls = [u.strip() for u in urls if u.strip() and not u.strip().startswith('#')]
    total = len(active_urls)
    if total == 0:
        return 0, 0

    session = create_session()
    success = 0
    tasks = [(url, prefix, i, session) for i, url in enumerate(active_urls, start_index)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_url, task) for task in tasks]
        for future in as_completed(futures):
            if future.result():
                success += 1

    session.close()
    return success, total

# ============== 规则列表（恢复注释版）==============
ADBLOCK_URLS = [
    # 大萌主-接口广告规则（CDN加速）
    "https://ghproxy.com/https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    # DD-AD去广告规则（CDN加速）
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # GitHub加速hosts（官方CDN）
    "https://raw.hellogithub.com/hosts",
    # Anti-AD通用规则（注释保留）
    #"https://anti-ad.net/easylist.txt",
    # Cats-Team广告规则（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
    # 那个谁520广告hosts规则（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
    # 10007自动规则（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/lingeringsound/10007_auto/adb.txt",
    # 晴雅去广告规则（CDN加速）
    "https://gh.flyinbug.top/https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    # 海哥广告规则（CDN加速）
    "https://ghproxy.net/https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    # FCM hosts规则（CDN加速）
    "https://proxy.zyglz.com/https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
    # 秋风广告规则（CDN加速）
    "https://ghps.cc/https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    # SMAdHosts规则（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    # 茯苓拦截规则（CDN加速）
    "https://raw.fastgit.org/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
]

ALLOW_URLS = [
    # 那个谁520广告白名单（CDN加速）
    "https://ghproxy.com/https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/allow.txt",
    # AdGuardHome通用白名单（CDN加速）
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    # 冷漠域名白名单（原地址）
    "https://file-git.trli.club/file-hosts/allow/Domains",
    # jhsvip白名单（CDN加速）
    "https://gh.flyinbug.top/https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
    # liwenjie119白名单（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    # 喵二白名单（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    # 茯苓白名单（CDN加速）
    "https://raw.fastgit.org/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
    # Cats-Team白名单（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
    # 浅笑白名单（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/user001235/112/main/white.txt",
    # 酷安cocieto白名单（注释保留）
    #"https://ghproxy.com/https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
    # anti-ad混合名单（官方CDN）
    "https://anti-ad.net/easylist.txt"
]

# ============== 主流程 ==============
def main():
    start_time = time.time()
    
    clean_target_files()
    prepare_environment()
    
    gh_group("下载规则")
    with ThreadPoolExecutor(max_workers=2) as executor:
        ad_future = executor.submit(download_all, ADBLOCK_URLS, "adblock")
        allow_future = executor.submit(download_all, ALLOW_URLS, "allow")
        
        success_ad, total_ad = ad_future.result()
        success_allow, total_allow = allow_future.result()
    
    elapsed = time.time() - start_time
    logger.info(f"\n下载完成 | 耗时: {elapsed:.2f}s")
    logger.info(f"拦截规则: {success_ad}/{total_ad} 成功")
    logger.info(f"白名单规则: {success_allow}/{total_allow} 成功")
    gh_endgroup()

if __name__ == "__main__":
    main()
