#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载处理脚本 - 精简优化版
功能：从远程URL下载广告规则和白名单，保存到临时目录，为后续处理提供输入
"""

import os
import sys
import time
import shutil
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============== 配置集中管理（还原原始远程源列表） ==============
class Config:
    """下载脚本配置参数（集中管理，便于维护）"""
    # 路径配置
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    MOD_PATH = DATA_DIR / 'mod'  # 本地规则目录

    # 下载参数（4核16G环境优化）
    MAX_WORKERS = 4  # 最大并行下载数
    TIMEOUT = 8  # 请求超时时间（秒）
    MAX_RETRIES = 2  # 下载重试次数
    RETRY_DELAY = 0.5  # 重试间隔（秒）
    HTTP_POOL_SIZE = 10  # HTTP连接池大小

    # ============== 规则列表（官方GitHub CDN版）==============
    ADBLOCK_URLS = [
        # 大萌主-接口广告规则（官方CDN）
        "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
        # DD-AD去广告规则（官方CDN）
        "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
        # GitHub加速hosts（官方CDN）
        "https://raw.hellogithub.com/hosts",
        # Anti-AD通用规则（注释保留）
        #"https://anti-ad.net/easylist.txt",
        # Cats-Team广告规则（注释保留）
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        # 那个谁520广告hosts规则（注释保留）
        #"https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
        # 10007自动规则（注释保留）
        #"https://raw.githubusercontent.com/lingeringsound/10007_auto/adb.txt",
        # 晴雅去广告规则（官方CDN）
        "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
        # 海哥广告规则（官方CDN）
        "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
        # FCM hosts规则（官方CDN）
        "https://raw.githubusercontent.com/entr0pia/fcm-hosts/fcm/fcm-hosts",
        # 秋风广告规则（官方CDN）
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        # SMAdHosts规则（注释保留）
        #"https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
        # 茯苓拦截规则（官方CDN）
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
    ]

    ALLOW_URLS = [
        # 那个谁520广告白名单（官方CDN）
        "https://raw.githubusercontent.com/qq5460168/EasyAds/main/allow.txt",
        # AdGuardHome通用白名单（官方CDN）
        "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
        # 冷漠域名白名单（原地址）
        "https://file-git.trli.club/file-hosts/allow/Domains",
        # jhsvip白名单（官方CDN）
        "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
        # liwenjie119白名单（注释保留）
        #"https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
        # 喵二白名单（注释保留）
        #"https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
        # 茯苓白名单（官方CDN）
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
        # Cats-Team白名单（注释保留）
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
        # 浅笑白名单（注释保留）
        #"https://raw.githubusercontent.com/user001235/112/main/white.txt",
        # 酷安cocieto白名单（注释保留）
        #"https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
        # anti-ad混合名单（官方CDN）
        "https://anti-ad.net/easylist.txt"
    ]

    # 本地规则文件映射（源路径 -> 临时目录路径）
    LOCAL_RULES = {
        MOD_PATH / "adblock.txt": TEMP_DIR / "adblock01.txt",
        MOD_PATH / "whitelist.txt": TEMP_DIR / "allow01.txt"
    }


# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger('RuleDownloader')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    
    # 适配GitHub Actions日志格式（与步骤2脚本统一）
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(asctime)s] %(levelname)s: %(message)s'
    handler.setFormatter(logging.Formatter(fmt, datefmt='%H:%M:%S'))
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ============== GitHub Actions工具 ==============
def gh_group(name: str):
    """GitHub Actions分组显示（与步骤2脚本统一）"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    """结束GitHub Actions分组"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


# ============== 下载核心逻辑 ==============
class RuleDownloader:
    def __init__(self):
        self.config = Config()
        self.session = self._init_session()
        # 确保临时目录存在
        self.config.TEMP_DIR.mkdir(parents=True, exist_ok=True)

    def _init_session(self):
        """初始化带连接池的requests会话"""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.config.HTTP_POOL_SIZE,
            pool_maxsize=self.config.HTTP_POOL_SIZE
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def download_with_retry(self, url: str, save_path: Path) -> bool:
        """带重试机制的下载函数"""
        for attempt in range(self.config.MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=self.config.TIMEOUT)
                response.raise_for_status()  # 触发HTTP错误
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                logger.info(f"✅ 成功下载: {url}")
                return True
            except Exception as e:
                if attempt < self.config.MAX_RETRIES:
                    logger.warning(f"⚠️ 下载失败（第{attempt+1}次重试）: {url}，错误: {str(e)}")
                    time.sleep(self.config.RETRY_DELAY)
                else:
                    logger.error(f"❌ 下载失败（已达最大重试次数）: {url}，错误: {str(e)}")
        return False

    def copy_local_rules(self):
        """复制本地规则到临时目录"""
        gh_group("复制本地规则")
        for src, dest in self.config.LOCAL_RULES.items():
            if src.exists():
                shutil.copy2(src, dest)
                logger.info(f"📋 复制本地规则: {src.name} -> {dest.name}")
            else:
                logger.warning(f"⚠️ 本地规则不存在，跳过: {src}")
        gh_endgroup()

    def download_remote_rules(self):
        """并行下载远程规则"""
        # 下载广告拦截规则
        gh_group("下载广告拦截规则")
        adblock_tasks = []
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            for i, url in enumerate(self.config.ADBLOCK_URLS, 1):
                if url.startswith('#'):  # 跳过注释的URL
                    logger.info(f"📝 跳过注释规则: {url.strip('# ')}")
                    continue
                save_path = self.config.TEMP_DIR / f"adblock{i:02d}.txt"
                adblock_tasks.append(executor.submit(self.download_with_retry, url, save_path))
            
            # 等待任务完成
            for future in as_completed(adblock_tasks):
                pass  # 结果已在子函数中日志输出
        gh_endgroup()

        # 下载白名单规则
        gh_group("下载白名单规则")
        allow_tasks = []
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            for i, url in enumerate(self.config.ALLOW_URLS, 1):
                if url.startswith('#'):  # 跳过注释的URL
                    logger.info(f"📝 跳过注释规则: {url.strip('# ')}")
                    continue
                save_path = self.config.TEMP_DIR / f"allow{i:02d}.txt"
                allow_tasks.append(executor.submit(self.download_with_retry, url, save_path))
            
            # 等待任务完成
            for future in as_completed(allow_tasks):
                pass  # 结果已在子函数中日志输出
        gh_endgroup()

    def run(self):
        """执行完整下载流程"""
        gh_group("开始规则下载流程")
        self.copy_local_rules()
        self.download_remote_rules()
        logger.info("📌 所有下载任务处理完毕")
        gh_endgroup()


if __name__ == "__main__":
    try:
        downloader = RuleDownloader()
        downloader.run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"💥 脚本执行失败: {str(e)}")
        sys.exit(1)
