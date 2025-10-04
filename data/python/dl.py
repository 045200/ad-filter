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
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Tuple

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
FILTER_DIR = DATA_DIR / 'filter'
MOD_PATH = DATA_DIR / 'mod'
RULES_CONFIG = BASE_DIR / 'data' / 'python' / 'rules.txt'

# 从环境变量获取配置
config = {
    'MAX_WORKERS': int(os.getenv('MAX_WORKERS', 6)),
    'TIMEOUT': int(os.getenv('TIMEOUT', 45)),  # 增加超时
    'MAX_RETRIES': int(os.getenv('MAX_RETRIES', 6)),  # 增加重试次数
    'RETRY_DELAY': int(os.getenv('RETRY_DELAY', 2)),
    'HTTP_POOL_SIZE': int(os.getenv('HTTP_POOL_SIZE', 15)),
    'CACHE_TTL': int(os.getenv('CACHE_TTL', 86400)),
}

# HTTP请求头（添加Referer以模拟浏览器）
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Referer': 'https://www.google.com/',  # 添加Referer
}

# 本地规则映射
LOCAL_RULES = {
    MOD_PATH / "adblock.txt": FILTER_DIR / "adblock00.txt",
    MOD_PATH / "whitelist.txt": FILTER_DIR / "allow00.txt"
}

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
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


def normalize_api_url(url: str) -> str:
    """标准化API URL"""
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        sorted_query = urlencode(query_params, doseq=True)
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            sorted_query,
            parsed.fragment
        ))
        return normalized
    except:
        return url


def is_http_url(url: str) -> bool:
    """检查是否为HTTP URL（非HTTPS）"""
    try:
        return urlparse(url).scheme == 'http'
    except:
        return False


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
        """初始化HTTP会话，支持代理"""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=config['HTTP_POOL_SIZE'],
            pool_maxsize=config['HTTP_POOL_SIZE']
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update(HEADERS)
        
        # 添加代理支持
        http_proxy = os.getenv('HTTP_PROXY')
        https_proxy = os.getenv('HTTPS_PROXY')
        if http_proxy:
            session.proxies['http'] = http_proxy
        if https_proxy:
            session.proxies['https'] = https_proxy
        if http_proxy or https_proxy:
            logger.info("使用代理: HTTP=%s, HTTPS=%s" % (http_proxy, https_proxy))
        
        return session

    def _clean_filter_dir(self):
        """清理过滤器目录"""
        if FILTER_DIR.exists():
            for item in FILTER_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
                    except:
                        pass

    def _load_rules_config(self) -> Tuple[List[str], List[str]]:
        """从配置文件加载规则URL"""
        adblock_urls = []
        allow_urls = []

        if not RULES_CONFIG.exists():
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
                elif line.lower() == '[allow]':
                    current_section = 'allow'
                elif current_section == 'adblock' and validate_url(line):
                    adblock_urls.append(normalize_api_url(line))
                elif current_section == 'allow' and validate_url(line):
                    allow_urls.append(normalize_api_url(line))

        except:
            pass

        return adblock_urls, allow_urls

    def _convert_to_utf8(self, content: bytes) -> str:
        """将内容转换为UTF-8编码"""
        try:
            return content.decode('utf-8')
        except UnicodeDecodeError:
            pass
        
        try:
            detected = chardet.detect(content)
            encoding = detected.get('encoding')
            if encoding:
                return content.decode(encoding)
        except:
            pass
        
        for enc in ['gbk', 'gb2312', 'latin-1']:
            try:
                return content.decode(enc)
            except UnicodeDecodeError:
                continue
        
        return content.decode('utf-8', errors='replace')

    def download_with_cache(self, url: str, save_path: Path) -> bool:
        """带缓存机制的文件下载"""
        if save_path.exists():
            mtime = save_path.stat().st_mtime
            if time.time() - mtime < config['CACHE_TTL']:
                return True
        return self.download_with_retry(url, save_path)

    def download_with_retry(self, url: str, save_path: Path) -> bool:
        """带重试机制的文件下载，并添加HTTPS fallback"""
        success = False
        for attempt in range(config['MAX_RETRIES'] + 1):
            try:
                timeout = config['TIMEOUT'] * 2 if is_http_url(url) and os.getenv('GITHUB_ACTIONS') else config['TIMEOUT']
                verify_ssl = not is_http_url(url)
                
                response = self.session.get(
                    url, 
                    timeout=timeout, 
                    verify=verify_ssl,
                    allow_redirects=True
                )
                response.raise_for_status()

                content = response.content
                text = self._convert_to_utf8(content)

                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(text)

                success = True
                break

            except requests.exceptions.SSLError as e:
                logger.warning(f"SSL错误 {url}: {e}")
                try:
                    response = self.session.get(url, timeout=config['TIMEOUT'], verify=False)
                    response.raise_for_status()
                    content = response.content
                    text = self._convert_to_utf8(content)
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(text)
                    success = True
                    break
                except Exception as retry_e:
                    pass
            except Exception as e:
                logger.warning(f"尝试 {attempt+1} 失败 {url}: {e}")
            
            if attempt < config['MAX_RETRIES']:
                time.sleep(config['RETRY_DELAY'])

        # HTTPS fallback
        if not success and is_http_url(url):
            https_url = url.replace('http://', 'https://')
            logger.info(f"HTTP失败，尝试HTTPS: {https_url}")
            success = self.download_with_retry(https_url, save_path)

        if not success:
            logger.error(f"最终下载失败 {url}，跳过此文件")
        
        return success

    def copy_local_rules(self):
        """复制本地规则文件"""
        for src, dest in LOCAL_RULES.items():
            try:
                if src.exists():
                    with open(src, 'rb') as f:
                        content = f.read()
                    text = self._convert_to_utf8(content)
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.stats['local']['copied'] += 1
                else:
                    self.stats['local']['missing'] += 1
            except:
                self.stats['local']['missing'] += 1

    def download_remote_rules(self):
        """下载远程规则"""
        # 下载广告拦截规则
        if self.adblock_urls:
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.adblock_urls, 1):
                    save_path = FILTER_DIR / f"adblock{i:02d}.txt"
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

                for future in as_completed(futures):
                    if future.result():
                        self.stats['adblock']['success'] += 1
                    else:
                        self.stats['adblock']['fail'] += 1

        # 下载白名单规则
        if self.allow_urls:
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.allow_urls, 1):
                    save_path = FILTER_DIR / f"allow{i:02d}.txt"
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

                for future in as_completed(futures):
                    if future.result():
                        self.stats['allow']['success'] += 1
                    else:
                        self.stats['allow']['fail'] += 1

    def run(self):
        """运行下载器"""
        start_time = time.time()

        self.copy_local_rules()
        self.download_remote_rules()

        elapsed = time.time() - start_time

        logger.info(f"耗时:{elapsed:.1f}s 拦截:{self.stats['adblock']['success']}/{len(self.adblock_urls)} "
                   f"放行:{self.stats['allow']['success']}/{len(self.allow_urls)} "
                   f"本地:{self.stats['local']['copied']}/{len(LOCAL_RULES)}")
        
        if self.stats['adblock']['fail'] > 0 or self.stats['allow']['fail'] > 0:
            logger.warning("有下载失败，但脚本继续执行。建议检查rules.txt移除失效URL。")


if __name__ == "__main__":
    try:
        RuleDownloader().run()
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)