#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
广告规则下载处理脚本 - 增强优化版
功能：从远程URL下载广告规则和白名单，处理本地规则，清理旧文件，为后续合并提供纯净输入
"""

import os
import sys
import time
import shutil
import requests
import logging
import chardet  # 新增：用于自动检测编码
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============== 配置集中管理 ==============
class Config:
    """下载脚本配置参数（集中管理，便于维护）"""
    # 路径配置
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 与合并脚本使用相同的临时目录
    MOD_PATH = DATA_DIR / 'mod'  # 本地规则目录

    # 下载参数（4核16G环境优化）
    MAX_WORKERS = 4  # 最大并行下载数
    TIMEOUT = 8  # 请求超时时间（秒）
    MAX_RETRIES = 2  # 下载重试次数
    RETRY_DELAY = 0.5  # 重试间隔（秒）
    HTTP_POOL_SIZE = 10  # HTTP连接池大小
    MIN_FILE_SIZE = 1024  # 最小文件大小（字节），过滤空文件

    # 请求头（模拟浏览器，避免403）
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }

    # 规则列表（官方GitHub CDN版）
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

    # 适配GitHub Actions日志格式
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(asctime)s] %(levelname)s: %(message)s'
    handler.setFormatter(logging.Formatter(fmt, datefmt='%H:%M:%S'))
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ============== GitHub Actions工具 ==============
def gh_group(name: str):
    """GitHub Actions分组显示"""
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
        # 初始化临时目录（清空旧文件）
        self._clean_temp_dir()
        self.config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        # 下载统计
        self.stats = {
            'adblock': {'success': 0, 'fail': 0},
            'allow': {'success': 0, 'fail': 0},
            'local': {'copied': 0, 'missing': 0}
        }

    def _init_session(self):
        """初始化带连接池和请求头的会话"""
        session = requests.Session()
        # 设置连接池
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.config.HTTP_POOL_SIZE,
            pool_maxsize=self.config.HTTP_POOL_SIZE
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        # 设置请求头（避免被服务器拒绝）
        session.headers.update(self.config.HEADERS)
        return session

    def _clean_temp_dir(self):
        """清空临时目录，避免旧文件干扰"""
        gh_group("清理临时目录")
        if self.config.TEMP_DIR.exists():
            for item in self.config.TEMP_DIR.iterdir():
                try:
                    if item.is_file():
                        item.unlink()
                        logger.info(f"清理旧文件: {item.name}")
                    elif item.is_dir():
                        shutil.rmtree(item)
                        logger.info(f"清理旧目录: {item.name}")
                except Exception as e:
                    logger.warning(f"清理{item.name}失败: {str(e)}")
        logger.info("临时目录清理完成")
        gh_endgroup()

    def _detect_encoding(self, content: bytes) -> str:
        """自动检测内容编码（处理非UTF-8规则文件）"""
        result = chardet.detect(content)
        encoding = result['encoding'] or 'utf-8'
        # 修复常见编码错误
        if encoding.lower() in ['gb2312', 'gbk']:
            encoding = 'gb18030'  # 更全面的中文编码
        return encoding

    def download_with_retry(self, url: str, save_path: Path) -> bool:
        """带重试机制的下载函数（支持编码自适应）"""
        for attempt in range(self.config.MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=self.config.TIMEOUT, stream=True)
                response.raise_for_status()  # 触发HTTP错误（4xx/5xx）

                # 读取内容并检测编码
                content = response.content
                encoding = self._detect_encoding(content)
                text = content.decode(encoding, errors='replace')  # 容错解码

                # 写入文件
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(text)

                # 检查文件大小
                if save_path.stat().st_size < self.config.MIN_FILE_SIZE:
                    logger.warning(f"⚠️ 文件过小（{save_path.stat().st_size}字节）: {url}")
                    save_path.unlink()  # 删除空文件/过小文件
                    return False

                logger.info(f"✅ 成功下载: {url}")
                return True

            except requests.exceptions.HTTPError as e:
                # 特定状态码处理
                status_code = response.status_code if 'response' in locals() else 'Unknown'
                error_msg = f"HTTP错误 {status_code}"
                if status_code == 404:
                    error_msg += "（链接不存在，建议更新URL）"
                elif status_code == 403:
                    error_msg += "（访问被拒绝，可能需要更新User-Agent）"
            except Exception as e:
                error_msg = str(e)

            # 重试或失败处理
            if attempt < self.config.MAX_RETRIES:
                logger.warning(f"⚠️ 下载失败（第{attempt+1}次重试）: {url}，错误: {error_msg}")
                time.sleep(self.config.RETRY_DELAY)
            else:
                logger.error(f"❌ 下载失败（已达最大重试次数）: {url}，错误: {error_msg}")
        return False

    def copy_local_rules(self):
        """复制本地规则到临时目录（带异常处理）"""
        gh_group("复制本地规则")
        for src, dest in self.config.LOCAL_RULES.items():
            try:
                if src.exists() and src.stat().st_size >= self.config.MIN_FILE_SIZE:
                    shutil.copy2(src, dest)
                    self.stats['local']['copied'] += 1
                    logger.info(f"📋 复制本地规则: {src.name} -> {dest.name}（{src.stat().st_size}字节）")
                else:
                    self.stats['local']['missing'] += 1
                    if not src.exists():
                        logger.warning(f"⚠️ 本地规则不存在: {src}")
                    else:
                        logger.warning(f"⚠️ 本地规则文件过小: {src}（{src.stat().st_size}字节）")
            except Exception as e:
                self.stats['local']['missing'] += 1
                logger.error(f"❌ 复制本地规则失败 {src.name}: {str(e)}")
        gh_endgroup()

    def download_remote_rules(self):
        """并行下载远程规则（带统计）"""
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

            # 统计结果
            for future in as_completed(adblock_tasks):
                result = future.result()
                if result:
                    self.stats['adblock']['success'] += 1
                else:
                    self.stats['adblock']['fail'] += 1
        logger.info(f"广告拦截规则下载统计: 成功{self.stats['adblock']['success']}个，失败{self.stats['adblock']['fail']}个")
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

            # 统计结果
            for future in as_completed(allow_tasks):
                result = future.result()
                if result:
                    self.stats['allow']['success'] += 1
                else:
                    self.stats['allow']['fail'] += 1
        logger.info(f"白名单规则下载统计: 成功{self.stats['allow']['success']}个，失败{self.stats['allow']['fail']}个")
        gh_endgroup()

    def run(self):
        """执行完整下载流程（含最终统计）"""
        gh_group("开始规则下载流程")
        start_time = time.time()

        self.copy_local_rules()
        self.download_remote_rules()

        # 输出最终统计
        elapsed = time.time() - start_time
        logger.info("\n📊 下载流程汇总:")
        logger.info(f"本地规则: 成功复制{self.stats['local']['copied']}个，缺失/失败{self.stats['local']['missing']}个")
        logger.info(f"远程广告规则: 成功{self.stats['adblock']['success']}个，失败{self.stats['adblock']['fail']}个")
        logger.info(f"远程白名单规则: 成功{self.stats['allow']['success']}个，失败{self.stats['allow']['fail']}个")
        logger.info(f"总耗时: {elapsed:.2f}秒")
        logger.info("📌 所有下载任务处理完毕，临时目录已准备就绪")
        
        # 在GitHub Actions中输出临时目录路径，供后续步骤使用
        if os.getenv('GITHUB_ACTIONS') == 'true':
            github_output = os.getenv('GITHUB_OUTPUT')
            if github_output:
                with open(github_output, 'a') as f:
                    f.write(f"temp_dir={self.config.TEMP_DIR}\n")
        
        gh_endgroup()


if __name__ == "__main__":
    # 确保chardet库存在（如果缺失则安装）
    try:
        import chardet
    except ImportError:
        logger.warning("检测到缺失chardet库，正在安装...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "chardet"])

    try:
        downloader = RuleDownloader()
        downloader.run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"💥 脚本执行失败: {str(e)}", exc_info=True)
        sys.exit(1)