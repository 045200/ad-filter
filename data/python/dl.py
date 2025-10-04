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
<<<<<<< HEAD
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Tuple
=======
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
>>>>>>> 8eb951a (改进下载脚本)

# 配置参数（新增SSL验证开关，默认开启）
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
FILTER_DIR = DATA_DIR / 'filter'
MOD_PATH = DATA_DIR / 'mod'
RULES_CONFIG = BASE_DIR / 'data' / 'python' / 'rules.txt'

<<<<<<< HEAD
# 从环境变量获取配置
=======
# 从环境变量获取配置（新增VERIFY_SSL控制）
>>>>>>> 8eb951a (改进下载脚本)
config = {
    'MAX_WORKERS': int(os.getenv('MAX_WORKERS', 6)),
    'TIMEOUT': int(os.getenv('TIMEOUT', 45)),  # 增加超时
    'MAX_RETRIES': int(os.getenv('MAX_RETRIES', 6)),  # 增加重试次数
    'RETRY_DELAY': int(os.getenv('RETRY_DELAY', 2)),
    'HTTP_POOL_SIZE': int(os.getenv('HTTP_POOL_SIZE', 15)),
<<<<<<< HEAD
    'CACHE_TTL': int(os.getenv('CACHE_TTL', 86400)),
}

# HTTP请求头（添加Referer以模拟浏览器）
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Referer': 'https://www.google.com/',  # 添加Referer
=======
    'CACHE_TTL': int(os.getenv('CACHE_TTL', 86400)),  # 24小时缓存
    'VERIFY_SSL': os.getenv('VERIFY_SSL', 'true').lower() == 'true'  # 新增：控制SSL验证
}

# HTTP请求头（保持原配置，确保兼容性）
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
    'DNT': '1',
    'Pragma': 'no-cache'
>>>>>>> 8eb951a (改进下载脚本)
}

# 本地规则映射（保持原配置）
LOCAL_RULES = {
    MOD_PATH / "adblock.txt": FILTER_DIR / "adblock00.txt",
    MOD_PATH / "whitelist.txt": FILTER_DIR / "allow00.txt"
}

# 日志配置（简化：仅保留关键级别+消息，移除GitHub Actions特殊格式）
logging.basicConfig(
    level=logging.INFO,
<<<<<<< HEAD
    format='%(message)s',
=======
    format='%(levelname)s: %(message)s',
>>>>>>> 8eb951a (改进下载脚本)
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


<<<<<<< HEAD
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
=======
def secure_path_join(base_path: Path, filename: str) -> Path:
    """安全地拼接文件路径"""
    return base_path / filename.strip('/')


def count_rules_in_file(file_path: Path) -> int:
    """统计文件中的规则数量（忽略空行和注释行）"""
    try:
        if not file_path.exists():
            return 0
        count = 0
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    count += 1
        return count
    except Exception as e:
        logger.error(f"统计规则失败 {file_path}: {str(e)[:50]}")  # 简化错误信息长度
        return 0
>>>>>>> 8eb951a (改进下载脚本)


class RuleDownloader:
    def __init__(self):
        # 初始化目录（保持原逻辑）
        FILTER_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.session = self._init_session()
        self._clean_filter_dir()
        self.adblock_urls, self.allow_urls = self._load_rules_config()
        # 统计信息（简化：仅保留核心计数）
        self.stats = {
<<<<<<< HEAD
            'adblock': {'success': 0, 'fail': 0},
            'allow': {'success': 0, 'fail': 0},
            'local': {'copied': 0, 'missing': 0}
        }

    def _init_session(self) -> requests.Session:
        """初始化HTTP会话，支持代理"""
=======
            'adblock': {'success': 0, 'fail': 0, 'total_rules': 0},
            'allow': {'success': 0, 'fail': 0, 'total_rules': 0},
            'local': {'copied': 0, 'missing': 0, 'total_rules': 0}
        }

    def _init_session(self) -> requests.Session:
        """初始化HTTP会话（保持原逻辑）"""
>>>>>>> 8eb951a (改进下载脚本)
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
        """清理过滤器目录（保持原逻辑，简化日志）"""
        if FILTER_DIR.exists():
            for item in FILTER_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
<<<<<<< HEAD
                    except:
                        pass
=======
                    except IOError as e:
                        logger.warning(f"删除旧文件失败 {item.name}: {str(e)[:30]}")
>>>>>>> 8eb951a (改进下载脚本)

    def _load_rules_config(self) -> Tuple[List[str], List[str]]:
        """从配置文件加载规则URL（简化日志输出）"""
        adblock_urls = []
        allow_urls = []
        if not RULES_CONFIG.exists():
            return adblock_urls, allow_urls

        try:
            with open(RULES_CONFIG, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith('#')]

            current_section = None
            for line in lines:
                if line.lower() == '[adblock]':
                    current_section = 'adblock'
                elif line.lower() == '[allow]':
                    current_section = 'allow'
<<<<<<< HEAD
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
=======
                elif current_section and validate_url(line):
                    if current_section == 'adblock':
                        adblock_urls.append(line)
                    else:
                        allow_urls.append(line)
            logger.info(f"加载规则配置: 拦截URL({len(adblock_urls)}个)，放行URL({len(allow_urls)}个)")
        except IOError as e:
            logger.error(f"读取配置失败: {str(e)[:50]}")
        return adblock_urls, allow_urls

    def _convert_to_utf8(self, content: bytes) -> Tuple[str, str]:
        """将内容转换为UTF-8编码（保持原逻辑）"""
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
                return content.decode(enc), enc
            except UnicodeDecodeError:
                continue

        return content.decode('utf-8', errors='replace'), 'utf-8'
>>>>>>> 8eb951a (改进下载脚本)

    def download_with_cache(self, url: str, save_path: Path) -> bool:
        """带缓存机制的文件下载（保持原逻辑）"""
        if save_path.exists():
            mtime = save_path.stat().st_mtime
            if time.time() - mtime < config['CACHE_TTL']:
<<<<<<< HEAD
=======
                logger.debug(f"使用缓存: {save_path.name}")  # 调试级别，不主动输出
>>>>>>> 8eb951a (改进下载脚本)
                return True
        return self.download_with_retry(url, save_path)

    def download_with_retry(self, url: str, save_path: Path) -> bool:
<<<<<<< HEAD
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
=======
        """带重试机制的文件下载（核心优化：使用SSL验证开关）"""
        for attempt in range(config['MAX_RETRIES'] + 1):
            try:
                # 关键修改：verify参数使用配置的VERIFY_SSL（GitHub环境可关闭）
                response = self.session.get(
                    url, 
                    timeout=config['TIMEOUT'], 
                    verify=config['VERIFY_SSL']
                )
                response.raise_for_status()

                # 流式写入文件（保持原逻辑）
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                # 编码转换（保持原逻辑）
                with open(save_path, 'rb') as f:
                    content = f.read()
                text, _ = self._convert_to_utf8(content)
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(text)

                # 统计规则数量（简化：直接累加总数，不记录单个文件）
                rule_count = count_rules_in_file(save_path)
                if save_path.name.startswith('adblock'):
                    self.stats['adblock']['total_rules'] += rule_count
                else:
                    self.stats['allow']['total_rules'] += rule_count
                logger.info(f"下载成功: {save_path.name}（{rule_count}条规则）")
                return True

            except requests.exceptions.RequestException as e:
                if attempt < config['MAX_RETRIES']:
                    time.sleep(config['RETRY_DELAY'] * (attempt + 1))
                else:
                    logger.error(f"下载失败[{url}]: {str(e)[:60]}")  # 简化错误信息
            except (UnicodeDecodeError, IOError) as e:
                logger.error(f"处理文件失败[{save_path.name}]: {str(e)[:40]}")
                return False
        return False
>>>>>>> 8eb951a (改进下载脚本)

    def copy_local_rules(self):
        """复制本地规则文件（简化日志和统计）"""
        for src, dest in LOCAL_RULES.items():
            try:
                if src.exists():
                    with open(src, 'rb') as f:
                        content = f.read()
<<<<<<< HEAD
                    text = self._convert_to_utf8(content)
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(text)
                    self.stats['local']['copied'] += 1
                else:
                    self.stats['local']['missing'] += 1
            except:
=======
                    text, _ = self._convert_to_utf8(content)
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(text)
                    # 统计本地规则
                    rule_count = count_rules_in_file(dest)
                    self.stats['local']['total_rules'] += rule_count
                    self.stats['local']['copied'] += 1
                    logger.info(f"复制本地规则: {src.name} → {dest.name}（{rule_count}条）")
                else:
                    self.stats['local']['missing'] += 1
                    logger.warning(f"本地规则缺失: {src}")
            except IOError as e:
>>>>>>> 8eb951a (改进下载脚本)
                self.stats['local']['missing'] += 1
                logger.error(f"复制失败[{src.name}]: {str(e)[:30]}")

    def download_remote_rules(self):
        """下载远程规则（保持线程池逻辑，简化日志）"""
        # 下载拦截规则
        if self.adblock_urls:
<<<<<<< HEAD
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.adblock_urls, 1):
                    save_path = FILTER_DIR / f"adblock{i:02d}.txt"
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

=======
            logger.info(f"开始下载拦截规则（{len(self.adblock_urls)}个链接）")
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = {
                    executor.submit(self.download_with_cache, url, secure_path_join(FILTER_DIR, f"adblock{i:02d}.txt")): url
                    for i, url in enumerate(self.adblock_urls, 1)
                }
>>>>>>> 8eb951a (改进下载脚本)
                for future in as_completed(futures):
                    if future.result():
                        self.stats['adblock']['success'] += 1
                    else:
                        self.stats['adblock']['fail'] += 1
<<<<<<< HEAD
=======
        else:
            logger.warning("无拦截规则URL配置")
>>>>>>> 8eb951a (改进下载脚本)

        # 下载放行规则
        if self.allow_urls:
<<<<<<< HEAD
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = []
                for i, url in enumerate(self.allow_urls, 1):
                    save_path = FILTER_DIR / f"allow{i:02d}.txt"
                    futures.append(executor.submit(self.download_with_cache, url, save_path))

=======
            logger.info(f"开始下载放行规则（{len(self.allow_urls)}个链接）")
            with ThreadPoolExecutor(max_workers=config['MAX_WORKERS']) as executor:
                futures = {
                    executor.submit(self.download_with_cache, url, secure_path_join(FILTER_DIR, f"allow{i:02d}.txt")): url
                    for i, url in enumerate(self.allow_urls, 1)
                }
>>>>>>> 8eb951a (改进下载脚本)
                for future in as_completed(futures):
                    if future.result():
                        self.stats['allow']['success'] += 1
                    else:
                        self.stats['allow']['fail'] += 1
<<<<<<< HEAD
=======
        else:
            logger.warning("无放行规则URL配置")

    def print_statistics(self):
        """打印统计信息（大幅简化：仅输出总计）"""
        logger.info("\n=== 规则下载总计 ===")
        logger.info(f"拦截规则: 成功{self.stats['adblock']['success']}/总{len(self.adblock_urls)}，共{self.stats['adblock']['total_rules']}条")
        logger.info(f"放行规则: 成功{self.stats['allow']['success']}/总{len(self.allow_urls)}，共{self.stats['allow']['total_rules']}条")
        logger.info(f"本地规则: 复制{self.stats['local']['copied']}/总{len(LOCAL_RULES)}，共{self.stats['local']['total_rules']}条")
        logger.info(f"总规则数: {self.stats['adblock']['total_rules'] + self.stats['allow']['total_rules'] + self.stats['local']['total_rules']}条")
>>>>>>> 8eb951a (改进下载脚本)

    def run(self):
        """运行下载器（保持原流程，简化耗时输出）"""
        start_time = time.time()
<<<<<<< HEAD
=======
        logger.info("开始执行规则下载器")
>>>>>>> 8eb951a (改进下载脚本)

        self.copy_local_rules()
        self.download_remote_rules()

        elapsed = time.time() - start_time
<<<<<<< HEAD

        logger.info(f"耗时:{elapsed:.1f}s 拦截:{self.stats['adblock']['success']}/{len(self.adblock_urls)} "
                   f"放行:{self.stats['allow']['success']}/{len(self.allow_urls)} "
                   f"本地:{self.stats['local']['copied']}/{len(LOCAL_RULES)}")
        
        if self.stats['adblock']['fail'] > 0 or self.stats['allow']['fail'] > 0:
            logger.warning("有下载失败，但脚本继续执行。建议检查rules.txt移除失效URL。")
=======
        logger.info(f"\n执行完成，总耗时: {elapsed:.1f}秒")
        self.print_statistics()
>>>>>>> 8eb951a (改进下载脚本)


if __name__ == "__main__":
    try:
        RuleDownloader().run()
<<<<<<< HEAD
=======
        sys.exit(0)
>>>>>>> 8eb951a (改进下载脚本)
    except Exception as e:
        logger.error(f"执行崩溃: {str(e)[:80]}")
        sys.exit(1)
