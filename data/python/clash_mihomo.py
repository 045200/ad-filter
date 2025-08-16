#!/usr/bin/env python3
"""
广告规则转换终极完整版-Github CI优化版
包含Mihomo工具链管理和CI环境特别优化
"""

import os
import re
import sys
import json
import gzip
import shutil
import hashlib
import urllib.request
import time
import sqlite3
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess
from typing import List, Dict, Optional, Any
from hashlib import md5

# 配置常量
REPO_ROOT = Path(__file__).parent.parent.parent
STRICT_MODE = False  # 广告规则严格模式开关
CACHE_DB = REPO_ROOT / "rule_cache.db"  # 规则缓存数据库
BLOOM_FILTER_SIZE = 1000000  # Bloom filter大小
PROGRESS_INTERVAL = 300  # 进度报告间隔(秒)
MAX_PROCESS_TIME = 10800  # 最大处理时间3小时(CI环境)
CI_MODE = os.getenv('CI') is not None  # 是否在CI环境中

# CI环境特定设置
if CI_MODE:
    print("检测到CI环境，启用优化配置")
    os.environ['PYTHONUNBUFFERED'] = '1'  # 确保实时输出

class BloomFilter:
    """优化的Bloom filter实现"""
    def __init__(self, size: int, hash_count: int = 3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bytearray((size + 7) // 8)

    def _hashes(self, item: str) -> List[int]:
        h = md5(item.encode()).hexdigest()
        return [int(h[i*8:i*8+8], 16) % self.size for i in range(self.hash_count)]

    def add(self, item: str) -> None:
        for idx in self._hashes(item):
            byte_idx, bit_idx = divmod(idx, 8)
            self.bit_array[byte_idx] |= 1 << bit_idx

    def __contains__(self, item: str) -> bool:
        for idx in self._hashes(item):
            byte_idx, bit_idx = divmod(idx, 8)
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

class CacheManager:
    """进程安全的缓存管理器"""
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.db_path = CACHE_DB
        self._init_db()
        self.bloom = None  # 延迟初始化

    def _init_db(self):
        """初始化数据库结构"""
        conn = self._get_connection()
        try:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS rule_cache (
                domain TEXT PRIMARY KEY,
                rule_type TEXT,
                converted_rule TEXT,
                file_hash TEXT,
                last_modified REAL
            )""")
            conn.execute("""
            CREATE TABLE IF NOT EXISTS file_meta (
                path TEXT PRIMARY KEY,
                last_hash TEXT,
                last_modified REAL
            )""")
            conn.commit()
        finally:
            conn.close()

    def _init_bloom_filter(self):
        """初始化Bloom filter"""
        if self.bloom is None:
            self.bloom = BloomFilter(BLOOM_FILTER_SIZE)
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT domain FROM rule_cache")
                for (domain,) in cursor.fetchall():
                    self.bloom.add(domain)
            finally:
                conn.close()

    def _get_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def get_cached_rule(self, domain: str) -> Optional[str]:
        """获取缓存的规则"""
        if self.bloom is None:
            self._init_bloom_filter()
            
        if domain not in self.bloom:
            return None

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT converted_rule FROM rule_cache WHERE domain = ?",
                (domain,))
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def cache_rule(self, domain: str, rule_type: str, converted_rule: str) -> None:
        """缓存规则"""
        if self.bloom is None:
            self._init_bloom_filter()
            
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO rule_cache VALUES (?, ?, ?, NULL, NULL)",
                (domain, rule_type, converted_rule))
            conn.commit()
            
            if domain not in self.bloom:
                self.bloom.add(domain)
        finally:
            conn.close()

class MihomoManager:
    """Mihomo工具链管理器"""
    def __init__(self):
        self.tool_dir = REPO_ROOT / "mihomo_tools"
        self.binary_path = None
        self.latest_version = None
        self.download_progress = 0

    def _get_latest_version(self) -> Optional[str]:
        """获取最新版本号(带重试机制)"""
        retries = 3
        for attempt in range(retries):
            try:
                print(f"获取Mihomo最新版本(尝试 {attempt + 1}/{retries})...")
                with urllib.request.urlopen(
                    "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
                    timeout=15
                ) as response:
                    data = json.loads(response.read())
                    version = data['tag_name']
                    print(f"最新版本: {version}")
                    return version
            except Exception as e:
                print(f"获取版本失败: {str(e)}")
                if attempt == retries - 1:
                    return None
                time.sleep(5)

    def _download_with_progress(self, url: str, save_path: Path) -> bool:
        """带进度显示的下载函数"""
        def progress_hook(count, block_size, total_size):
            percent = int(count * block_size * 100 / total_size)
            if percent > self.download_progress and percent % 10 == 0:
                self.download_progress = percent
                print(f"下载进度: {percent}%")

        try:
            print(f"开始下载: {url}")
            self.download_progress = 0
            urllib.request.urlretrieve(url, save_path, reporthook=progress_hook)
            return True
        except Exception as e:
            print(f"下载失败: {str(e)}")
            if save_path.exists():
                save_path.unlink()
            return False

    def prepare(self) -> bool:
        """准备工具链"""
        # 1. 获取最新版本
        self.latest_version = self._get_latest_version()
        if not self.latest_version:
            print("错误: 无法获取Mihomo版本", file=sys.stderr)
            return False

        # 2. 设置平台和路径
        platform = "linux-amd64" if CI_MODE else self._detect_platform()
        self.binary_path = self.tool_dir / f"mihomo-{self.latest_version}"
        
        # 3. 检查是否已存在
        if self.binary_path.exists():
            print(f"使用缓存工具: {self.latest_version}")
            return True

        # 4. 下载和解压
        self.tool_dir.mkdir(parents=True, exist_ok=True)
        gz_url = f"https://github.com/MetaCubeX/mihomo/releases/download/{self.latest_version}/mihomo-{platform}-{self.latest_version}.gz"
        gz_path = self.tool_dir / f"mihomo-{self.latest_version}.gz"

        if not self._download_with_progress(gz_url, gz_path):
            return False

        # 5. 解压文件
        print("解压文件中...")
        try:
            with gzip.open(gz_path, 'rb') as f_in:
                with open(self.binary_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            self.binary_path.chmod(0o755)
            print(f"工具已安装: {self.binary_path}")
            return True
        except Exception as e:
            print(f"解压失败: {str(e)}", file=sys.stderr)
            if self.binary_path.exists():
                self.binary_path.unlink()
            return False
        finally:
            if gz_path.exists():
                gz_path.unlink()

    def _detect_platform(self) -> str:
        """检测平台类型"""
        if sys.platform.startswith('linux'):
            return 'linux-amd64'
        elif sys.platform == 'darwin':
            return 'darwin-amd64'
        elif sys.platform == 'win32':
            return 'windows-amd64'
        else:
            print("警告: 未知平台，默认使用linux-amd64", file=sys.stderr)
            return 'linux-amd64'

class CIProgressTracker:
    """CI环境进度跟踪器"""
    def __init__(self, file_name: str):
        self.file_name = file_name
        self.start_time = time.time()
        self.last_report = self.start_time
        
    def log(self, processed: int, converted: int):
        current_time = time.time()
        if current_time - self.last_report >= PROGRESS_INTERVAL:
            elapsed = current_time - self.start_time
            print(
                f"[进度] {self.file_name} - "
                f"已处理: {processed} | "
                f"生成规则: {converted} | "
                f"耗时: {elapsed:.1f}s"
            )
            self.last_report = current_time

class AdRuleConverter:
    """广告规则转换引擎"""
    
    AD_KEYWORDS = {
        'ad', 'ads', 'advert', 'analytics', 'track', 
        'counter', 'metric', 'pixel', 'beacon'
    }

    def __init__(self):
        self.stats = {
            'block': 0, 
            'allow': 0, 
            'cached': 0,
            'processed': 0,
            'skipped': 0
        }
        self.rule_patterns = self._init_patterns()
        self.cache = CacheManager.get_instance()

    def _init_patterns(self):
        """预编译正则表达式"""
        return [
            (re.compile(r'^@@\|\|?([\w*.-]+)\^?'), 'allow'),
            (re.compile(r'^\|\|([\w*.-]+)\^'), 'domain'),
            (re.compile(r'^\|?https?://([\w*.-]+)/?'), 'url'),
            (re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)'), 'hosts'),
            (re.compile(r'^([\w*.-]+)$'), 'plain')
        ]

    def _is_ad_related(self, domain: str) -> bool:
        """检查域名是否与广告相关"""
        domain = domain.lower()
        return any(kw in domain for kw in self.AD_KEYWORDS)

    def _parse_rule(self, line: str) -> Optional[Dict]:
        """解析单条规则"""
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            self.stats['skipped'] += 1
            return None

        for pattern, pattern_type in self.rule_patterns:
            match = pattern.match(line)
            if match:
                if pattern_type == 'allow':
                    return {
                        'type': 'allow',
                        'domain': match.group(1).replace('*.', ''),
                        'raw': line
                    }

                domain = match.group(1) if pattern_type != 'hosts' else match.group(2)
                return {
                    'type': 'block',
                    'domain': domain.replace('*.', ''),
                    'raw': line,
                    'is_ad': True if STRICT_MODE else self._is_ad_related(domain)
                }
        
        self.stats['skipped'] += 1
        return None

    def _convert_rule(self, rule: Dict) -> Optional[str]:
        """转换单条规则"""
        if not rule['domain'] or '*' in rule['domain']:
            self.stats['skipped'] += 1
            return None

        # 检查缓存
        cached_rule = self.cache.get_cached_rule(rule['domain'])
        if cached_rule:
            self.stats['cached'] += 1
            return cached_rule

        # 转换规则
        if rule['type'] == 'allow':
            converted = f"DOMAIN-SUFFIX,{rule['domain']},DIRECT"
            self.stats['allow'] += 1
        else:
            if not rule.get('is_ad', True):
                self.stats['skipped'] += 1
                return None
            converted = f"DOMAIN-SUFFIX,{rule['domain']},REJECT,adblock"
            self.stats['block'] += 1

        # 缓存结果
        self.cache.cache_rule(rule['domain'], rule['type'], converted)
        return converted

    def process_file(self, input_path: Path) -> List[str]:
        """处理规则文件"""
        if not input_path.exists():
            print(f"错误: 文件不存在 {input_path}", file=sys.stderr)
            raise FileNotFoundError(input_path)

        print(f"开始处理: {input_path.name}")
        start_time = time.time()
        converted = []
        progress = CIProgressTracker(input_path.name) if CI_MODE else None
        
        try:
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # 检查处理时间
                    if time.time() - start_time > MAX_PROCESS_TIME:
                        raise TimeoutError(f"超过最大处理时间 {MAX_PROCESS_TIME}秒")
                    
                    # 解析和转换规则
                    rule = self._parse_rule(line)
                    if rule:
                        result = self._convert_rule(rule)
                        if result:
                            converted.append(result)
                    
                    self.stats['processed'] += 1
                    
                    # 报告进度
                    if progress and self.stats['processed'] % 1000 == 0:
                        progress.log(self.stats['processed'], len(converted))
                        
        except Exception as e:
            print(f"处理文件出错: {str(e)}", file=sys.stderr)
            raise

        elapsed = time.time() - start_time
        print(
            f"处理完成: {input_path.name}\n"
            f"总行数: {self.stats['processed']} | "
            f"生成规则: {len(converted)} | "
            f"耗时: {elapsed:.2f}s\n"
            f"统计: 拦截={self.stats['block']} 放行={self.stats['allow']} "
            f"缓存={self.stats['cached']} 跳过={self.stats['skipped']}"
        )
        return converted

def main():
    print(f"{datetime.now()} [启动] 广告规则转换 (CI模式: {'是' if CI_MODE else '否'})")
    start_time = time.time()
    
    try:
        # 1. 准备Mihomo工具链
        print("准备Mihomo工具链...")
        mihomo = MihomoManager()
        if not mihomo.prepare():
            sys.exit(1)

        # 2. 初始化缓存
        CacheManager.get_instance()

        # 3. 处理规则文件
        converter = AdRuleConverter()
        input_files = {
            'allow': REPO_ROOT / "allow.txt",
            'block': REPO_ROOT / "adblock.txt"
        }

        rules = []
        for name, path in input_files.items():
            try:
                rules.extend(converter.process_file(path))
            except Exception as e:
                print(f"处理失败: {path.name} - {str(e)}", file=sys.stderr)
                sys.exit(1)

        # 4. 生成最终规则文件
        output_path = REPO_ROOT / "adblock.mrs"
        print(f"生成最终规则文件: {output_path}")
        
        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            # 写入规则头
            tmp.write(f"""params:
  enable-adblock: true
  adblock-speedup: true
  strict-mode: {str(STRICT_MODE).lower()}
rules:
""")
            # 写入规则内容
            tmp.write("\n".join(rules))
            tmp.flush()
            
            # 调用mihomo生成规则
            try:
                subprocess.run(
                    [str(mihomo.binary_path), "rulegen",
                    "-i", tmp.name,
                    "-o", str(output_path),
                    "--adblock",
                    "--strict" if STRICT_MODE else "--loose"],
                    check=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                print(f"规则生成失败: {e.stderr}", file=sys.stderr)
                sys.exit(1)

        elapsed = time.time() - start_time
        print(
            f"{datetime.now()} [完成] 总耗时: {elapsed:.2f}s\n"
            f"输出文件: {output_path}\n"
            f"总规则数: {len(rules)}\n"
            f"拦截规则: {converter.stats['block']}\n"
            f"放行规则: {converter.stats['allow']}"
        )
        sys.exit(0)
        
    except Exception as e:
        print(f"致命错误: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()