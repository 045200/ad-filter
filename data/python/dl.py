#!/usr/bin/env python3

import os
import sys
import time
import requests
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# 配置参数
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
DATA_DIR = BASE_DIR / 'data'
FILTER_DIR = DATA_DIR / 'filter'
MOD_PATH = DATA_DIR / 'mod'
RULES_CONFIG = BASE_DIR / 'data' / 'python' / 'rules.txt'

# 环境变量配置
config = {
    'MAX_WORKERS': int(os.getenv('MAX_WORKERS', 8)),
    'TIMEOUT': int(os.getenv('TIMEOUT', 15)),
}

# Git API 优化请求头
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; RuleDownloader/1.0)',
    'Accept': 'application/vnd.github.v3.raw, text/plain, */*',
}

# 本地规则映射
LOCAL_RULES = {
    MOD_PATH / "adblock.txt": FILTER_DIR / "adblock0.txt",
    MOD_PATH / "whitelist.txt": FILTER_DIR / "allow0.txt"
}

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    stream=sys.stdout
)
logger = logging.getLogger('RuleDownloader')


def validate_url(url: str) -> bool:
    """快速URL验证"""
    try:
        result = urlparse(url)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def count_rules_in_file(file_path: Path) -> int:
    """快速统计规则数量"""
    try:
        if not file_path.exists():
            return 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for line in f if line.strip() and not line.startswith('!'))
    except Exception:
        return 0


class RuleDownloader:
    def __init__(self):
        FILTER_DIR.mkdir(parents=True, exist_ok=True)
        self.session = self._init_session()
        self._clean_filter_dir()
        self.adblock_urls, self.allow_urls = self._load_rules_config()
        self.stats = {
            'adblock': {'success': 0, 'fail': 0, 'total_rules': 0},
            'allow': {'success': 0, 'fail': 0, 'total_rules': 0},
            'local': {'copied': 0, 'total_rules': 0}
        }

    def _init_session(self) -> requests.Session:
        """初始化高效会话"""
        session = requests.Session()
        session.headers.update(HEADERS)
        session.trust_env = False
        
        # 优化连接池
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=config['MAX_WORKERS'],
            pool_maxsize=config['MAX_WORKERS']
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        return session

    def _clean_filter_dir(self):
        """快速清理目录"""
        if FILTER_DIR.exists():
            for item in FILTER_DIR.iterdir():
                if item.is_file() and (item.name.startswith('adblock') or item.name.startswith('allow')):
                    try:
                        item.unlink()
                    except OSError:
                        pass

    def _load_rules_config(self):
        """加载配置并保留注释处理逻辑"""
        adblock_urls = []
        allow_urls = []
        
        if not RULES_CONFIG.exists():
            logger.error(f"配置文件不存在: {RULES_CONFIG}")
            return adblock_urls, allow_urls

        try:
            with open(RULES_CONFIG, 'r', encoding='utf-8') as f:
                current_section = None
                for line in f:
                    line = line.strip()
                    
                    # 跳过空行和注释行
                    if not line or line.startswith('#'):
                        continue
                    
                    # 检测章节标记
                    if line == '[adblock]':
                        current_section = 'adblock'
                        continue
                    elif line == '[allow]':
                        current_section = 'allow'
                        continue
                    
                    # 处理行内注释
                    url = line.split('#')[0].strip()
                    if not url or not validate_url(url):
                        continue
                    
                    # 根据当前章节添加到对应列表
                    if current_section == 'adblock':
                        adblock_urls.append(url)
                    elif current_section == 'allow':
                        allow_urls.append(url)
                        
        except Exception as e:
            logger.error(f"读取配置失败: {e}")
            
        return adblock_urls, allow_urls

    def copy_local_rules(self):
        """快速复制本地规则"""
        import shutil
        for src, dest in LOCAL_RULES.items():
            if src.exists():
                shutil.copy2(src, dest)
                rule_count = count_rules_in_file(dest)
                self.stats['local']['total_rules'] += rule_count
                self.stats['local']['copied'] += 1
                logger.info(f"本地: {src.name} → {rule_count}条")
            else:
                logger.warning(f"本地文件缺失: {src}")

    def download_single_rule(self, url: str, save_path: Path, rule_type: str) -> bool:
        """单次下载，无重试"""
        try:
            response = self.session.get(url, timeout=config['TIMEOUT'])
            response.raise_for_status()
            
            # 直接写入文件
            with open(save_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(response.text)
            
            # 快速统计
            rule_count = count_rules_in_file(save_path)
            self.stats[rule_type]['total_rules'] += rule_count
            logger.info(f"成功: {save_path.name} ({rule_count}条)")
            return True
            
        except Exception as e:
            logger.error(f"失败: {save_path.name} - {type(e).__name__}")
            return False

    def download_rules_parallel(self, urls: list, prefix: str, rule_type: str):
        """并行下载"""
        if not urls:
            return
            
        with ThreadPoolExecutor(max_workers=min(config['MAX_WORKERS'], len(urls))) as executor:
            futures = {
                executor.submit(
                    self.download_single_rule, 
                    url, 
                    FILTER_DIR / f"{prefix}{i+1}.txt", 
                    rule_type
                ): url for i, url in enumerate(urls)
            }
            
            for future in as_completed(futures):
                if future.result():
                    self.stats[rule_type]['success'] += 1
                else:
                    self.stats[rule_type]['fail'] += 1

    def run(self):
        """主执行流程"""
        start_time = time.time()
        logger.info("开始下载规则...")
        
        # 并行执行所有下载任务
        self.copy_local_rules()
        
        if self.adblock_urls:
            logger.info(f"下载拦截规则 ({len(self.adblock_urls)}个)")
            self.download_rules_parallel(self.adblock_urls, 'adblock', 'adblock')
        
        if self.allow_urls:
            logger.info(f"下载放行规则 ({len(self.allow_urls)}个)")
            self.download_rules_parallel(self.allow_urls, 'allow', 'allow')
        
        # 快速统计
        elapsed = time.time() - start_time
        total_success = (self.stats['adblock']['success'] + 
                        self.stats['allow']['success'] + 
                        self.stats['local']['copied'])
        total_rules = (self.stats['adblock']['total_rules'] + 
                      self.stats['allow']['total_rules'] + 
                      self.stats['local']['total_rules'])
        
        logger.info(f"\n完成! 耗时: {elapsed:.1f}s")
        logger.info(f"成功: {total_success}个源, 规则: {total_rules}条")
        
        if self.stats['adblock']['fail'] > 0 or self.stats['allow']['fail'] > 0:
            logger.info(f"失败: {self.stats['adblock']['fail']}拦截 + {self.stats['allow']['fail']}放行")
            return 1
        return 0


if __name__ == "__main__":
    try:
        exit_code = RuleDownloader().run()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("用户中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"错误: {e}")
        sys.exit(1)