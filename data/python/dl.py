#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import shutil
import requests
import logging
import chardet
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
MOD_PATH = DATA_DIR / 'mod'

# 下载配置
MAX_WORKERS = 6
TIMEOUT = 25
MAX_RETRIES = 4
RETRY_DELAY = 2
HTTP_POOL_SIZE = 15

# 额外下载文件配置（包含MD5验证信息）
EXTRA_DOWNLOADS = {
    "china_ip_ranges.txt": {
        "url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
        "md5": None  # 文本文件不需要MD5验证
    },
    "GeoLite2-Country.mmdb": {
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
        "md5": None  # 由于文件可能更新，不进行MD5验证
    }
}

# 使用您提供的真实浏览器UA和完整的HTTP请求头
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
    'DNT': '1',  # 不要跟踪
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
        #"https://anti-ad.net/easylist.txt",
        # Cats-Team广告规则（注释保留）
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        # 那个谁520广告hosts规则（注释保留）
        #"https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
        # 10007自动规则（注释保留）
        #"https://raw.githubusercontent.com/lingeringsound/10007_auto/master/adb.txt",
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
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
        # 浅笑白名单（注释保留）
        "https://raw.githubusercontent.com/user001235/112/main/white.txt",
        # 酷安cocieto白名单（注释保留）
        "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
        # anti-ad混合名单（官方CDN）
        #"https://anti-ad.net/easylist.txt"
    ]

# 本地规则映射（源 -> 临时文件）
LOCAL_RULES = {
    MOD_PATH / "adblock.txt": TEMP_DIR / "adblock00.txt",  # 本地规则固定为00序号
    MOD_PATH / "whitelist.txt": TEMP_DIR / "allow00.txt"
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
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.session = self._init_session()
        self._clean_temp_dir()
        self.stats = {
            'adblock': {'success': 0, 'fail': 0},
            'allow': {'success': 0, 'fail': 0},
            'local': {'copied': 0, 'missing': 0},
            'extra': {'success': 0, 'fail': 0, 'md5_mismatch': 0}
        }
        self.failed_urls = []  # 记录失败的URL

    def _init_session(self):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=HTTP_POOL_SIZE,
            pool_maxsize=HTTP_POOL_SIZE,
            max_retries=0  # 禁用默认重试，使用自定义重试逻辑
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update(HEADERS)
        return session

    def _clean_temp_dir(self):
        gh_group("清理临时目录")
        if TEMP_DIR.exists():
            for item in TEMP_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
                        logger.info(f"清理旧规则: {item.name}")
                    except Exception as e:
                        logger.warning(f"清理失败 {item.name}: {e}")
        logger.info("临时目录清理完成")
        gh_endgroup()

    def _calculate_md5(self, file_path):
        """计算文件的MD5哈希值"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"计算MD5失败 {file_path}: {e}")
            return None

    def _convert_to_utf8(self, content):
        """将内容转换为UTF-8编码"""
        # 检测编码
        detected = chardet.detect(content)
        encoding = detected.get('encoding', 'utf-8')
        confidence = detected.get('confidence', 0)
        
        # 优先尝试UTF-8
        if encoding.lower() in ['utf-8', 'ascii'] and confidence > 0.7:
            try:
                return content.decode('utf-8'), 'utf-8'
            except UnicodeDecodeError:
                pass
        
        # 尝试其他常见编码
        encodings_to_try = ['gbk', 'gb2312', 'gb18030', 'latin-1', 'iso-8859-1', 'cp1252']
        for enc in encodings_to_try:
            try:
                text = content.decode(enc)
                logger.info(f"成功使用编码 {enc} 解码内容")
                return text, enc
            except UnicodeDecodeError:
                continue
        
        # 如果所有编码都失败，使用replace错误处理
        try:
            text = content.decode('utf-8', errors='replace')
            logger.warning("使用UTF-8 with errors='replace' 解码内容")
            return text, 'utf-8'
        except Exception as e:
            logger.error(f"所有编码尝试都失败: {e}")
            # 返回原始内容作为字符串
            return content.decode('latin-1', errors='replace'), 'latin-1'

    def download_with_retry(self, url, save_path, is_binary=False, expected_md5=None):
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(
                    url, 
                    timeout=TIMEOUT,
                    verify=True
                )
                response.raise_for_status()

                if is_binary:
                    # 二进制文件直接保存
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                    
                    # 验证MD5（如果提供了期望的MD5）
                    if expected_md5:
                        actual_md5 = self._calculate_md5(save_path)
                        if actual_md5 and actual_md5 != expected_md5:
                            logger.error(f"MD5验证失败: {url} (期望: {expected_md5}, 实际: {actual_md5})")
                            save_path.unlink()
                            return False
                        elif actual_md5:
                            logger.info(f"MD5验证成功: {url}")
                else:
                    # 文本文件 - 转换为UTF-8
                    content = response.content
                    text, detected_encoding = self._convert_to_utf8(content)
                    
                    # 保存为UTF-8编码
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(text)
                    
                    logger.info(f"已转换为UTF-8: {url} (检测编码: {detected_encoding})")

                logger.info(f"成功下载: {url.split('/')[-1]}")
                return True

            except Exception as e:
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * (attempt + 1))  # 指数退避策略
                else:
                    logger.warning(f"下载失败 {url}: {str(e)}")
                    self.failed_urls.append(url)
        return False

    def copy_local_rules(self):
        gh_group("复制本地规则")
        for src, dest in LOCAL_RULES.items():
            try:
                if src.exists():
                    # 读取本地文件并转换为UTF-8
                    with open(src, 'rb') as f:
                        content = f.read()
                    
                    text, detected_encoding = self._convert_to_utf8(content)
                    
                    # 保存为UTF-8编码
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(text)
                    
                    self.stats['local']['copied'] += 1
                    logger.info(f"复制并转换为UTF-8: {src.name} -> {dest.name} (检测编码: {detected_encoding})")
                else:
                    self.stats['local']['missing'] += 1
                    logger.warning(f"本地规则不存在: {src}")
            except Exception as e:
                self.stats['local']['missing'] += 1
                logger.warning(f"复制失败 {src.name}: {e}")
        gh_endgroup()

    def download_remote_rules(self):
        # 下载广告拦截规则（adblockXX.txt）
        gh_group("下载广告拦截规则")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ADBLOCK_URLS, 1):
                save_path = TEMP_DIR / f"adblock{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path))

            for future in as_completed(futures):
                if future.result():
                    self.stats['adblock']['success'] += 1
                else:
                    self.stats['adblock']['fail'] += 1
        logger.info(f"广告规则统计: 成功{self.stats['adblock']['success']}，失败{self.stats['adblock']['fail']}")
        gh_endgroup()

        # 下载白名单规则（allowXX.txt）
        gh_group("下载白名单规则")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ALLOW_URLS, 1):
                save_path = TEMP_DIR / f"allow{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path))

            for future in as_completed(futures):
                if future.result():
                    self.stats['allow']['success'] += 1
                else:
                    self.stats['allow']['fail'] += 1
        logger.info(f"白名单统计: 成功{self.stats['allow']['success']}，失败{self.stats['allow']['fail']}")
        gh_endgroup()

    def download_extra_files(self):
        """下载额外的文件"""
        gh_group("下载额外文件")
        for filename, file_info in EXTRA_DOWNLOADS.items():
            url = file_info["url"]
            expected_md5 = file_info.get("md5")
            save_path = DATA_DIR / filename
            is_binary = filename.endswith('.mmdb')  # mmdb文件是二进制格式

            try:
                if self.download_with_retry(url, save_path, is_binary=is_binary, expected_md5=expected_md5):
                    self.stats['extra']['success'] += 1
                    logger.info(f"成功下载额外文件: {filename}")
                else:
                    self.stats['extra']['fail'] += 1
                    logger.warning(f"下载额外文件失败: {filename}")
            except Exception as e:
                self.stats['extra']['fail'] += 1
                logger.warning(f"下载额外文件异常 {filename}: {e}")
        gh_endgroup()

    def run(self):
        start_time = time.time()
        gh_group("规则下载流程")

        self.copy_local_rules()
        self.download_remote_rules()
        self.download_extra_files()

        # 输出结果
        elapsed = time.time() - start_time
        logger.info(f"\n总耗时: {elapsed:.2f}秒")
        logger.info(f"本地规则: 成功{self.stats['local']['copied']}，缺失{self.stats['local']['missing']}")
        logger.info(f"广告规则: 成功{self.stats['adblock']['success']}，失败{self.stats['adblock']['fail']}")
        logger.info(f"白名单: 成功{self.stats['allow']['success']}，失败{self.stats['allow']['fail']}")
        logger.info(f"额外文件: 成功{self.stats['extra']['success']}，失败{self.stats['extra']['fail']}")
        
        if self.stats['extra']['md5_mismatch'] > 0:
            logger.info(f"MD5验证失败: {self.stats['extra']['md5_mismatch']}")
        
        # 输出失败的URL
        if self.failed_urls:
            logger.info("\n失败的URL列表:")
            for url in self.failed_urls:
                logger.info(f"  - {url}")

        logger.info("临时目录准备就绪，所有文本文件已转换为UTF-8编码")

        # GitHub Actions输出
        if github_output := os.getenv('GITHUB_OUTPUT'):
            with open(github_output, 'a') as f:
                f.write(f"temp_dir={TEMP_DIR}\n")
                f.write(f"failed_count={len(self.failed_urls)}\n")

        gh_endgroup()


if __name__ == "__main__":
    try:
        RuleDownloader().run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"执行失败: {e}")
        sys.exit(1)