#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载处理脚本 - GitHub CI优化版
保留规则列表中的注释，优化GitHub Actions资源使用
"""

import os
import sys
import time
import shutil
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============== GitHub Actions 环境变量 ==============
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
SCRIPTS_DIR = os.getenv('SCRIPTS_DIR', 'data/python')
DATA_DIR = os.getenv('DATA_DIR', 'data')
TEMP_DIR = os.getenv('TEMP_DIR', 'tmp')

# ============== 配置参数 ==============
# GitHub免费版资源优化配置
MAX_WORKERS = 6                # 降低线程数避免资源限制
REQUEST_TIMEOUT = 15           # 缩短超时时间适应CI环境
MAX_RETRIES = 3                # 减少重试次数
RETRY_DELAY = 1.0              # 缩短重试间隔
CLEAN_PATTERNS = ['*.txt', '*.mrs', '*.yaml', '*.conf']  # 清理文件模式

# ============== 路径配置 ==============
# 使用环境变量设置路径
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_PATH = BASE_DIR / TEMP_DIR
DATA_PATH = BASE_DIR / DATA_DIR
MOD_PATH = DATA_PATH / 'mod'
SCRIPTS_PATH = BASE_DIR / SCRIPTS_DIR

# ============== 日志配置 ==============
def setup_logger():
    """配置日志系统 - GitHub CI优化版"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # GitHub CI环境使用分组日志
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

# ============== 文件处理 ==============
def clean_target_files():
    """安全清理目标文件"""
    gh_group("清理目标文件")
    logger.info(f"工作区路径: {BASE_DIR}")
    
    deleted_count = 0
    for pattern in CLEAN_PATTERNS:
        for file in BASE_DIR.glob(pattern):
            try:
                if file.is_file():
                    file.unlink()
                    deleted_count += 1
                    if os.getenv('GITHUB_ACTIONS') != 'true':  # 非CI环境显示详情
                        logger.info(f"已删除: {file.relative_to(BASE_DIR)}")
            except Exception as e:
                logger.error(f"删除失败 {file}: {str(e)[:100]}")
    
    logger.info(f"清理完成: 删除 {deleted_count} 个文件")
    gh_endgroup()
    return deleted_count

def prepare_environment():
    """准备运行环境 - 使用环境变量路径"""
    gh_group("准备环境")
    try:
        # 确保临时目录存在
        TEMP_PATH.mkdir(exist_ok=True, parents=True)
        logger.info(f"临时目录: {TEMP_PATH.relative_to(BASE_DIR)}")
        
        # 确保数据目录存在
        DATA_PATH.mkdir(exist_ok=True, parents=True)
        MOD_PATH.mkdir(exist_ok=True, parents=True)
        
        # 复制本地规则文件
        local_files = {
            MOD_PATH / "adblock.txt": TEMP_PATH / "adblock01.txt",
            MOD_PATH / "whitelist.txt": TEMP_PATH / "allow01.txt"
        }

        copied_count = 0
        for src, dst in local_files.items():
            try:
                if src.exists():
                    shutil.copy(src, dst)
                    copied_count += 1
                    if os.getenv('GITHUB_ACTIONS') != 'true':  # 非CI环境显示详情
                        logger.info(f"已复制: {src.relative_to(BASE_DIR)} → {dst.relative_to(BASE_DIR)}")
                else:
                    logger.warning(f"本地规则不存在: {src.relative_to(BASE_DIR)}")
            except Exception as e:
                logger.error(f"复制失败 {src}: {str(e)[:100]}")
        
        logger.info(f"环境准备完成: 复制 {copied_count} 个本地规则")
        return copied_count
    except Exception as e:
        logger.error(f"环境初始化失败: {str(e)[:100]}")
        sys.exit(1)
    finally:
        gh_endgroup()

# ============== 下载处理 ==============
def download_with_retry(url, session=None):
    """带重试机制的下载器 - GitHub CI优化"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept-Encoding': 'gzip, deflate'
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = (session or requests).get(
                url, 
                headers=headers, 
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            
            # 自动检测编码
            if resp.encoding is None:
                resp.encoding = 'utf-8'
                
            return resp.text
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise Exception(f"下载失败 {url}: {str(e)[:100]}")
        except Exception as e:
            raise Exception(f"处理失败 {url}: {str(e)[:100]}")

def process_url(url, prefix, index, session=None):
    """处理单个URL下载 - 增强错误处理"""
    try:
        content = download_with_retry(url, session)
        filename = TEMP_PATH / f"{prefix}{index:02d}.txt"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Source: {url}\n{content}")

        logger.info(f"✓ 下载成功: {url}")
        return True
    except Exception as e:
        logger.error(f"✗ 下载失败: {url} - {str(e)[:100]}")
        return False

def download_all(urls, prefix, start_index=2):
    """并发下载所有规则 - 跳过注释行"""
    session = requests.Session()
    session.max_redirects = 3  # 限制重定向次数
    
    results = []
    success_count = 0
    active_urls = []

    # 筛选出非注释URL
    for url in urls:
        if isinstance(url, str) and not url.strip().startswith('#'):
            active_urls.append(url)
    
    logger.info(f"准备下载 {len(active_urls)}/{len(urls)} 个规则 (跳过 {len(urls)-len(active_urls)} 个注释)")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for i, url in enumerate(active_urls, start_index):
            futures.append(executor.submit(process_url, url, prefix, i, session))
        
        for future in as_completed(futures):
            try:
                if future.result():
                    success_count += 1
                results.append(future.result())
            except Exception as e:
                logger.error(f"任务执行异常: {str(e)[:100]}")
                results.append(False)

    session.close()
    return success_count, len(active_urls)

# ============== 完整规则列表（保留注释）==============
# 拦截规则列表 - 注释行以#开头
ADBLOCK_URLS = [
    # 大萌主-接口广告规则
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    # DD-AD去广告规则
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # GitHub加速hosts
    "https://raw.hellogithub.com/hosts",
    # Anti-AD通用规则（注释保留）
    #"https://anti-ad.net/easylist.txt",
    # Cats-Team广告规则（注释保留）
    #"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
    # 那个谁520广告hosts规则（注释保留）
    #"https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
    # 10007自动规则（注释保留）
    #"https://lingeringsound.github.io/10007_auto/adb.txt",
    # 晴雅去广告规则
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    # 海哥广告规则
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    # FCM hosts规则
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
    # 秋风广告规则
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    # SMAdHosts规则（注释保留）
    #"https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    # 茯苓拦截规则
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
]

# 白名单规则列表 - 注释行以#开头
ALLOW_URLS = [
    # 那个谁520广告白名单
    "https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/allow.txt",
    # AdGuardHome通用白名单
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    # 冷漠域名白名单
    "https://file-git.trli.club/file-hosts/allow/Domains",
    # jhsvip白名单
    "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
    # liwenjie119白名单
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    # 喵二白名单
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    # 茯苓白名单
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
    # Cats-Team白名单
    "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
    # 浅笑白名单
    "https://raw.githubusercontent.com/user001235/112/main/white.txt",
    # 酷安cocieto白名单
    "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
    # anti-ad混合名单
    "https://anti-ad.net/easylist.txt" 
]

# ============== 主流程 ==============
def main():
    """主执行流程 - GitHub CI优化"""
    # 初始化环境
    clean_target_files()
    prepare_environment()

    # 下载规则
    gh_group("下载规则列表")
    start_time = time.time()
    
    # 并发下载拦截规则和白名单规则
    with ThreadPoolExecutor(max_workers=2) as executor:
        ad_future = executor.submit(download_all, ADBLOCK_URLS, "adblock")
        allow_future = executor.submit(download_all, ALLOW_URLS, "allow")
        
        success_ad, total_ad = ad_future.result()
        success_allow, total_allow = allow_future.result()
    
    elapsed = time.time() - start_time
    logger.info(f"\n✅ 下载完成 | 耗时: {elapsed:.2f}s")
    logger.info(f"拦截规则: 成功 {success_ad}/{total_ad} (共 {len(ADBLOCK_URLS)} 项)")
    logger.info(f"白名单规则: 成功 {success_allow}/{total_allow} (共 {len(ALLOW_URLS)} 项)")
    
    # 显示被跳过的注释规则数量
    skipped_ad = len(ADBLOCK_URLS) - total_ad
    skipped_allow = len(ALLOW_URLS) - total_allow
    if skipped_ad > 0 or skipped_allow > 0:
        logger.info(f"跳过规则: {skipped_ad} 个拦截规则 + {skipped_allow} 个白名单规则 (注释)")
    
    gh_endgroup()

if __name__ == "__main__":
    main()