#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import shutil
import requests
import logging
import chardet
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 与合并脚本共享临时目录
MOD_PATH = DATA_DIR / 'mod'

# 下载配置
MAX_WORKERS = 4
TIMEOUT = 10  # 增加超时时间
MAX_RETRIES = 3  # 增加重试次数
RETRY_DELAY = 1.0  # 增加重试延迟
HTTP_POOL_SIZE = 10
MIN_FILE_SIZE = 1024  # 最小文件大小（字节）

# 额外下载文件配置
EXTRA_DOWNLOADS = {
    "china_ip_ranges.txt": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
    "GeoLite2-Country.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
}

# 请求头 - 添加更多浏览器特征
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0'
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
        "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        # 那个谁520广告hosts规则（注释保留）
        "https://raw.githubusercontent.com/qq5460168/EasyAds/refs/heads/main/adblock.txt",
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
        "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
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
        DATA_DIR.mkdir(parents=True, exist_ok=True)  # 确保data目录存在
        self.session = self._init_session()
        self._clean_temp_dir()
        self.stats = {
            'adblock': {'success': 0, 'fail': 0, 'failed_urls': []},
            'allow': {'success': 0, 'fail': 0, 'failed_urls': []},
            'local': {'copied': 0, 'missing': 0},
            'extra': {'success': 0, 'fail': 0, 'failed_urls': []}
        }

    def _init_session(self):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=HTTP_POOL_SIZE,
            pool_maxsize=HTTP_POOL_SIZE,
            max_retries=3  # 添加重试配置
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

    def _detect_encoding(self, content):
        result = chardet.detect(content)
        encoding = result['encoding'] or 'utf-8'
        return 'gb18030' if encoding.lower() in ['gb2312', 'gbk'] else encoding

    def download_with_retry(self, url, save_path, is_binary=False, rule_type="unknown"):
        for attempt in range(MAX_RETRIES + 1):
            try:
                logger.info(f"尝试下载 ({attempt+1}/{MAX_RETRIES+1}): {url}")
                response = self.session.get(url, timeout=TIMEOUT)
                response.raise_for_status()

                if is_binary:
                    # 二进制文件直接保存
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                else:
                    # 文本文件需要处理编码
                    content = response.content
                    encoding = self._detect_encoding(content)
                    text = content.decode(encoding, errors='replace')
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(text)

                file_size = save_path.stat().st_size
                if file_size < MIN_FILE_SIZE:
                    save_path.unlink()
                    logger.warning(f"文件太小({file_size}字节)，已删除: {url}")
                    return False

                logger.info(f"成功下载: {url} -> {save_path.name} ({file_size}字节)")
                return True

            except requests.exceptions.RequestException as e:
                if attempt < MAX_RETRIES:
                    logger.warning(f"下载失败，{RETRY_DELAY}秒后重试: {url} - {str(e)}")
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error(f"最终下载失败: {url} - {str(e)}")
                    if rule_type in self.stats:
                        self.stats[rule_type]['failed_urls'].append(url)
                    return False
            except Exception as e:
                logger.error(f"下载过程中发生未知错误: {url} - {str(e)}")
                if rule_type in self.stats:
                    self.stats[rule_type]['failed_urls'].append(url)
                return False
        return False

    def copy_local_rules(self):
        gh_group("复制本地规则")
        for src, dest in LOCAL_RULES.items():
            try:
                if src.exists() and src.stat().st_size >= MIN_FILE_SIZE:
                    shutil.copy2(src, dest)
                    self.stats['local']['copied'] += 1
                    logger.info(f"复制本地规则: {src.name} -> {dest.name}")
                else:
                    self.stats['local']['missing'] += 1
                    logger.warning(f"本地规则无效或不存在: {src}")
            except Exception as e:
                self.stats['local']['missing'] += 1
                logger.warning(f"复制失败 {src.name}: {e}")
        gh_endgroup()

    def download_remote_rules(self):
        # 下载广告拦截规则（adblockXX.txt）
        gh_group("下载广告拦截规则")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ADBLOCK_URLS, 1):  # 从1开始编号，00留给本地规则
                save_path = TEMP_DIR / f"adblock{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path, False, 'adblock'))

            for future in as_completed(futures):
                if future.result():
                    self.stats['adblock']['success'] += 1
                else:
                    self.stats['adblock']['fail'] += 1
                    
        # 输出失败的URL
        if self.stats['adblock']['failed_urls']:
            logger.warning("以下广告规则下载失败:")
            for url in self.stats['adblock']['failed_urls']:
                logger.warning(f"  - {url}")
                
        logger.info(f"广告规则统计: 成功{self.stats['adblock']['success']}，失败{self.stats['adblock']['fail']}")
        gh_endgroup()

        # 下载白名单规则（allowXX.txt）
        gh_group("下载白名单规则")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i, url in enumerate(ALLOW_URLS, 1):  # 从1开始编号，00留给本地规则
                save_path = TEMP_DIR / f"allow{i:02d}.txt"
                futures.append(executor.submit(self.download_with_retry, url, save_path, False, 'allow'))

            for future in as_completed(futures):
                if future.result():
                    self.stats['allow']['success'] += 1
                else:
                    self.stats['allow']['fail'] += 1
                    
        # 输出失败的URL
        if self.stats['allow']['failed_urls']:
            logger.warning("以下白名单规则下载失败:")
            for url in self.stats['allow']['failed_urls']:
                logger.warning(f"  - {url}")
                
        logger.info(f"白名单统计: 成功{self.stats['allow']['success']}，失败{self.stats['allow']['fail']}")
        gh_endgroup()

    def download_extra_files(self):
        """下载额外的文件（中国IP范围和GeoIP数据库）"""
        gh_group("下载额外文件")
        for filename, url in EXTRA_DOWNLOADS.items():
            save_path = DATA_DIR / filename
            is_binary = filename.endswith('.mmdb')  # mmdb文件是二进制格式

            try:
                if self.download_with_retry(url, save_path, is_binary=is_binary, rule_type='extra'):
                    self.stats['extra']['success'] += 1
                    logger.info(f"成功下载额外文件: {filename}")
                else:
                    self.stats['extra']['fail'] += 1
                    self.stats['extra']['failed_urls'].append(url)
                    logger.warning(f"下载额外文件失败: {filename}")
            except Exception as e:
                self.stats['extra']['fail'] += 1
                self.stats['extra']['failed_urls'].append(url)
                logger.warning(f"下载额外文件异常 {filename}: {e}")
                
        # 输出失败的URL
        if self.stats['extra']['failed_urls']:
            logger.warning("以下额外文件下载失败:")
            for url in self.stats['extra']['failed_urls']:
                logger.warning(f"  - {url}")
                
        gh_endgroup()

    def run(self):
        start_time = time.time()
        gh_group("规则下载流程")

        self.copy_local_rules()
        self.download_remote_rules()
        self.download_extra_files()  # 新增：下载额外文件

        # 输出结果
        elapsed = time.time() - start_time
        logger.info(f"\n总耗时: {elapsed:.2f}秒")
        logger.info(f"本地规则: 成功{self.stats['local']['copied']}，缺失{self.stats['local']['missing']}")
        logger.info(f"广告规则: 成功{self.stats['adblock']['success']}，失败{self.stats['adblock']['fail']}")
        logger.info(f"白名单规则: 成功{self.stats['allow']['success']}，失败{self.stats['allow']['fail']}")
        logger.info(f"额外文件: 成功{self.stats['extra']['success']}，失败{self.stats['extra']['fail']}")
        
        # 如果有失败的下载，列出所有失败的URL
        failed_urls = (self.stats['adblock']['failed_urls'] + 
                      self.stats['allow']['failed_urls'] + 
                      self.stats['extra']['failed_urls'])
        
        if failed_urls:
            logger.warning("\n以下URL下载失败，请检查网络连接或URL有效性:")
            for url in failed_urls:
                logger.warning(f"  - {url}")
                
        logger.info("临时目录准备就绪，规则文件格式: adblockXX.txt / allowXX.txt")

        # GitHub Actions输出
        if github_output := os.getenv('GITHUB_OUTPUT'):
            with open(github_output, 'a') as f:
                f.write(f"temp_dir={TEMP_DIR}\n")

        gh_endgroup()


if __name__ == "__main__":
    # 确保chardet存在
    try:
        import chardet
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])

    try:
        RuleDownloader().run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"执行失败: {e}")
        sys.exit(1)