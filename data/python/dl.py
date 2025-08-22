#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import logging
import chardet
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
FILTER_DIR = DATA_DIR / 'filter'
MOD_PATH = DATA_DIR / 'mod'

# 下载配置
MAX_WORKERS = 6
TIMEOUT = 25
MAX_RETRIES = 4
RETRY_DELAY = 2
HTTP_POOL_SIZE = 15

# 额外下载文件配置
EXTRA_DOWNLOADS = {
    "china_ip_ranges.txt": {
        "url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
    },
    "GeoLite2-Country.mmdb": {
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    }
}

# HTTP请求头
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'DNT': '1',
    'Pragma': 'no-cache'
}

# 规则URL列表（输出文件名：adblockXX.txt/allowXX.txt）
ADBLOCK_URLS = [
    # 大萌主-接口广告规则（官方CDN）
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    # DD-AD去广告规则（官方CDN）
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # GitHub加速hosts（官方CDN）
    "https://raw.hellogithub.com/hosts",
    # Anti-AD通用规则（注释保留）
    # "https://anti-ad.net/easylist.txt",
    # Cats-Team广告规则（注释保留）
    # "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
    # 那个谁520广告hosts规则（注释保留）
    # "https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
    # 10007自动规则（注释保留）
    # "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt",
    # 晴雅去广告规则（官方CDN）
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
    # 海哥广告规则（官方CDN）
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
    # FCM hosts规则（官方CDN）
    "https://raw.githubusercontent.com/entr0pia/fcm-hosts/fcm/fcm-hosts",
    # 秋风广告规则（官方CDN）
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    # SMAdHosts规则（注释保留）
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
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
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
    # 喵二白名单（注释保留）
    "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
    # 茯苓白名单（官方CDN）
    "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
    # Cats-Team白名单（注释保留）
    # "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
    # 浅笑白名单（注释保留）
    "https://raw.githubusercontent.com/user001235/112/main/white.txt",
    # 酷安cocieto白名单（注释保留）
    "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
    # anti-ad混合名单（官方CDN）
    # "https://anti-ad.net/easylist.txt"
]

# 本地规则映射
LOCAL_RULES = {
    MOD_PATH / "adblock.txt": FILTER_DIR / "adblock00.txt",
    MOD_PATH / "whitelist.txt": FILTER_DIR / "allow00.txt"
}

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(levelname)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('RuleDownloader')


def gh_group(name):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


class RuleDownloader:
    def __init__(self):
        FILTER_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.session = self._init_session()
        self._clean_filter_dir()
        self.stats = {
            'adblock': {'success': 0, 'fail': 0},
            'allow': {'success': 0, 'fail': 0},
            'local': {'copied': 0, 'missing': 0},
            'extra': {'success': 0, 'fail': 0}
        }

    def _init_session(self):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=HTTP_POOL_SIZE,
            pool_maxsize=HTTP_POOL_SIZE,
            max_retries=0
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update(HEADERS)
        return session

    def _clean_filter_dir(self):
        if FILTER_DIR.exists():
            for item in FILTER_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
                    except Exception:
                        pass

    def _convert_to_utf8(self, content):
        detected = chardet.detect(content)
        encoding = detected.get('encoding', 'utf-8')
        confidence = detected.get('confidence', 0)

        if encoding.lower() in ['utf-8', 'ascii'] and confidence > 0.7:
            try:
                return content.decode('utf-8'), 'utf-8'
            except UnicodeDecodeError:
                pass

        encodings_to_try = ['gbk', 'gb2312', 'gb18030', 'latin-1', 'iso-8859-1', 'cp1252']
        for enc in encodings_to_try:
            try:
                text = content.decode(enc)
                return text, enc
            except UnicodeDecodeError:
                continue

        try:
            text = content.decode('utf-8', errors='replace')
            return text, 'utf-8'
        except Exception:
            return content.decode('latin-1', errors='replace'), 'latin-1'

    def download_with_retry(self, url, save_path, is_binary=False):
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=TIMEOUT, verify=True)
                response.raise_for_status()

                if is_binary:
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                else:
                    content = response.content
                    text, _ = self._convert_to_utf8(content)
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(text)

                return True

            except Exception:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * (attempt + 1))
        return False

    def copy_local_rules(self):
        for src, dest in LOCAL_RULES.items():
            try:
                if src.exists():
                    with open(src, 'rb') as f:
                        content = f.read()
                    text, _ = self._convert_to_utf8(content)
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.stats['local']['copied'] += 1
                else:
                    self.stats['local']['missing'] += 1
            except Exception:
                self.stats['local']['missing'] += 1

    def download_remote_rules(self):
        # 下载广告拦截规则
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ADBLOCK_URLS, 1):
                save_path = FILTER_DIR / f"adblock{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path))

            for future in as_completed(futures):
                if future.result():
                    self.stats['adblock']['success'] += 1
                else:
                    self.stats['adblock']['fail'] += 1

        # 下载白名单规则
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ALLOW_URLS, 1):
                save_path = FILTER_DIR / f"allow{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path))

            for future in as_completed(futures):
                if future.result():
                    self.stats['allow']['success'] += 1
                else:
                    self.stats['allow']['fail'] += 1

    def download_extra_files(self):
        for filename, file_info in EXTRA_DOWNLOADS.items():
            url = file_info["url"]
            save_path = DATA_DIR / filename
            is_binary = filename.endswith('.mmdb')

            try:
                if self.download_with_retry(url, save_path, is_binary=is_binary):
                    self.stats['extra']['success'] += 1
                else:
                    self.stats['extra']['fail'] += 1
            except Exception:
                self.stats['extra']['fail'] += 1

    def run(self):
        start_time = time.time()

        self.copy_local_rules()
        self.download_remote_rules()
        self.download_extra_files()

        elapsed = time.time() - start_time
        
        # 单行输出结果
        logger.info(f"耗时:{elapsed:.1f}s 拦截:{self.stats['adblock']['success']}/{len(ADBLOCK_URLS)} "
                   f"放行:{self.stats['allow']['success']}/{len(ALLOW_URLS)} "
                   f"额外:{self.stats['extra']['success']}/{len(EXTRA_DOWNLOADS)}")


if __name__ == "__main__":
    try:
        RuleDownloader().run()
        sys.exit(0)
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)