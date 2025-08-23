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
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
FILTER_DIR = DATA_DIR / 'filter'
MOD_PATH = DATA_DIR / 'mod'
RULES_CONFIG = BASE_DIR / 'data' / 'rules.txt'

# 从环境变量获取配置，提供默认值
config = {
    'MAX_WORKERS': int(os.getenv('MAX_WORKERS', 6)),
    'TIMEOUT': int(os.getenv('TIMEOUT', 25)),
    'MAX_RETRIES': int(os.getenv('MAX_RETRIES', 4)),
    'RETRY_DELAY': int(os.getenv('RETRY_DELAY', 2)),
    'HTTP_POOL_SIZE': int(os.getenv('HTTP_POOL_SIZE', 15)),
    'CACHE_TTL': int(os.getenv('CACHE_TTL', 86400))  # 24小时缓存
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


def validate_url(url: str) -> bool:
    """验证URL的合法性"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False


def secure_path_join(base_path: Path, filename: str) -> Path:
    """安全地拼接文件路径"""
    return base_path / filename.strip('/')


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
        self.adblock_urls, self.allow_urls = self._load_rules_config()
        self.stats = {
            'adblock': {'success': 0, 'fail': 0},
            'allow': {'success': 0, 'fail': 0},
            'local': {'copied': 0, 'missing': 0}
        }

    def _init_session(self) -> requests.Session:
        """初始化HTTP会话"""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=config['HTTP_POOL_SIZE'],
            pool_maxsize=config['HTTP_POOL_SIZE'],
            max_retries=0
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update(HEADERS)
        return session

    def _clean_filter_dir(self):
        """清理过滤器目录"""
        if FILTER_DIR.exists():
            for item in FILTER_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
                    except IOError as e:
                        logger.warning(f"删除文件失败 {item}: {e}")

    def _load_rules_config(self) -> Tuple[List[str], List[str]]:
        """从配置文件加载规则URL"""
        adblock_urls = []
        allow_urls = []
        
        if not RULES_CONFIG.exists():
            logger.error(f"配置文件不存在: {RULES_CONFIG}")
            return adblock_urls, allow_urls
            
        try:
            with open(RULES_CONFIG, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            current_section = None
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if line.lower() == '[adblock]':
                    current_section = 'adblock'
                    continue
                elif line.lower() == '[allow]':
                    current_section = 'allow'
                    continue
                    
                if current_section == 'adblock' and validate_url(line):
                    adblock_urls.append(line)
                elif current_section == 'allow' and validate_url(line):
                    allow_urls.append(line)
                    
            logger.info(f"从配置加载: {len(adblock_urls)}个拦截规则, {len(allow_urls)}个放行规则")
            
        except IOError as e:
            logger.error(f"读取配置文件失败: {e}")
            
        return adblock_urls, allow_urls

    def _convert_to_utf8(self, content: bytes) -> Tuple[str, str]:
        """将内容转换为UTF-8编码"""
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

    def download_with_cache(self, url: str, save_path: Path) -> bool:
        """带缓存机制的文件下载"""
        if save_path.exists():
            mtime = save_path.stat().st_mtime
            if time.time() - mtime < config['CACHE_TTL']:
                return True
        return self.download_with_retry(url, save_path)

    def download_with_retry(self, url: str, save_path: Path) -> bool:
        """带重试机制的文件下载"""
        for attempt in range(config['MAX_RETRIES'] + 1):
            try:
                response = self.session.get(url, timeout=config['TIMEOUT'], verify=True)
                response.raise_for_status()

                # 使用流式处理大文件
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                # 转换编码
                with open(save_path, 'rb') as f:
                    content = f.read()
                text, _ = self._convert_to_utf8(content)
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(text)

                return True

            except requests.exceptions.RequestException as e:
                if attempt < config['MAX_RETRIES']:
                    time.sleep(config['RETRY_DELAY'] * (attempt + 1))
                else:
                    logger.error(f"网络请求失败 {url}: {e}")
            except UnicodeDecodeError as e:
                logger.error(f"编码转换失败 {url}: {e}")
                return False
            except IOError as e:
                logger.error(f"文件操作失败 {save_path}: {e}")
                return False
        return False

    def copy_local_rules(self):
        """复制本地规则文件"""
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
            except IOError as e:
                logger.error(f"复制本地规则失败 {src}: {e}")
                self.stats['local']['missing'] += 1

    def download_remote_rules(self):
        """下载远程规则"""
        # 下载广告拦截规则
        if self.adblock_urls:
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.adblock_urls, 1):
                    save_path = secure_path_join(FILTER_DIR, f"adblock{i:02d}.txt")
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

                for future in as_completed(futures):
                    if future.result():
                        self.stats['adblock']['success'] += 1
                    else:
                        self.stats['adblock']['fail'] += 1
        else:
            logger.warning("未配置广告拦截规则URL")

        # 下载白名单规则
        if self.allow_urls:
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.allow_urls, 1):
                    save_path = secure_path_join(FILTER_DIR, f"allow{i:02d}.txt")
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

                for future in as_completed(futures):
                    if future.result():
                        self.stats['allow']['success'] += 1
                    else:
                        self.stats['allow']['fail'] += 1
        else:
            logger.warning("未配置白名单规则URL")

    def run(self):
        """运行下载器"""
        start_time = time.time()

        self.copy_local_rules()
        self.download_remote_rules()

        elapsed = time.time() - start_time

        # 输出结果
        logger.info(f"耗时:{elapsed:.1f}s 拦截:{self.stats['adblock']['success']}/{len(self.adblock_urls)} "
                   f"放行:{self.stats['allow']['success']}/{len(self.allow_urls)} "
                   f"本地:{self.stats['local']['copied']}/{len(LOCAL_RULES)}")


if __name__ == "__main__":
    try:
        RuleDownloader().run()
        sys.exit(0)
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)
