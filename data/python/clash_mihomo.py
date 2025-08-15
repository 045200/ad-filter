#!/usr/bin/env python3
"""
广告规则转换终极完整版-长期优化版
功能：
1. 自动获取最新mihomo版本
2. 支持五大拦截器规则转换
3. 生成带广告优化参数的.mrs文件
4. 严格/宽容模式可选
5. 集成并行处理、缓存、增量更新和高效数据结构
"""

import os
import re
import sys
import json
import gzip
import shutil
import hashlib
import urllib.request
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess
import multiprocessing
import sqlite3
from typing import List, Set, Dict, Optional, Pattern, Tuple, Any
from hashlib import md5
from functools import partial
from concurrent.futures import ProcessPoolExecutor, as_completed

# 配置常量
REPO_ROOT = Path(__file__).parent.parent.parent
STRICT_MODE = False  # 广告规则严格模式开关
CACHE_DB = REPO_ROOT / "rule_cache.db"  # 规则缓存数据库
BLOOM_FILTER_SIZE = 1000000  # Bloom filter大小(预估规则数量)

class BloomFilter:
    """简易Bloom filter实现(仅使用标准库)"""
    def __init__(self, size: int, hash_count: int = 3):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = bytearray((size + 7) // 8)  # 用字节数组模拟位数组

    def _hashes(self, item: str) -> List[int]:
        """生成多个哈希位置"""
        h = md5(item.encode()).hexdigest()
        return [int(h[i*8:i*8+8], 16) % self.size for i in range(self.hash_count)]

    def add(self, item: str) -> None:
        """添加元素到过滤器"""
        for idx in self._hashes(item):
            byte_idx, bit_idx = divmod(idx, 8)
            self.bit_array[byte_idx] |= 1 << bit_idx

    def __contains__(self, item: str) -> bool:
        """检查元素是否存在"""
        for idx in self._hashes(item):
            byte_idx, bit_idx = divmod(idx, 8)
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

class CacheManager:
    """规则缓存管理器"""
    def __init__(self):
        self.conn = None
        self.bloom = None
        self._init_db()

    def _init_db(self) -> None:
        """初始化缓存数据库"""
        self.conn = sqlite3.connect(str(CACHE_DB))
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_cache (
            domain TEXT PRIMARY KEY,
            rule_type TEXT,
            converted_rule TEXT,
            file_hash TEXT,
            last_modified REAL
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_meta (
            path TEXT PRIMARY KEY,
            last_hash TEXT,
            last_modified REAL
        )
        """)
        self.conn.commit()

        # 预加载Bloom filter
        self.bloom = BloomFilter(BLOOM_FILTER_SIZE)
        cursor.execute("SELECT domain FROM rule_cache")
        for (domain,) in cursor.fetchall():
            self.bloom.add(domain)

    def get_file_meta(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """获取文件元数据"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT last_hash, last_modified FROM file_meta WHERE path = ?",
            (str(file_path),))
        row = cursor.fetchone()
        return {"last_hash": row[0], "last_modified": row[1]} if row else None

    def update_file_meta(self, file_path: Path, file_hash: str) -> None:
        """更新文件元数据"""
        mtime = file_path.stat().st_mtime
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO file_meta VALUES (?, ?, ?)",
            (str(file_path), file_hash, mtime))
        self.conn.commit()

    def get_cached_rule(self, domain: str) -> Optional[str]:
        """获取缓存规则"""
        if domain not in self.bloom:
            return None

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT converted_rule FROM rule_cache WHERE domain = ?",
            (domain,))
        row = cursor.fetchone()
        return row[0] if row else None

    def cache_rule(self, domain: str, rule_type: str, converted_rule: str) -> None:
        """缓存规则"""
        if domain not in self.bloom:
            self.bloom.add(domain)
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO rule_cache VALUES (?, ?, ?, NULL, NULL)",
                (domain, rule_type, converted_rule))
            self.conn.commit()

    def close(self) -> None:
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None

class MihomoManager:
    """Mihomo工具链全自动管理器"""
    
    def __init__(self):
        self.tool_dir = REPO_ROOT / "mihomo_tools"
        self.binary_path = None
        self.latest_version = None
        self.download_progress = 0

    def _progress_hook(self, count, block_size, total_size):
        """下载进度回调函数"""
        percent = int(count * block_size * 100 / total_size)
        if percent > self.download_progress and percent % 10 == 0:
            self.download_progress = percent
            print(f"下载进度: {percent}%")

    def _get_latest_version(self) -> Optional[str]:
        """获取GitHub最新发行版"""
        try:
            print("正在获取最新版本信息...")
            with urllib.request.urlopen(
                "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
                timeout=10
            ) as response:
                data = json.loads(response.read())
                version = data['tag_name']
                print(f"最新版本: {version}")
                return version
        except Exception as e:
            print(f"获取最新版本失败: {str(e)}", file=sys.stderr)
            return None

    def _download_tool(self, version: str) -> bool:
        """下载并解压mihomo工具"""
        try:
            self.tool_dir.mkdir(parents=True, exist_ok=True)
            platform = "linux-amd64"  # 可根据实际系统修改
            url = f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/mihomo-{platform}-{version}.gz"
            gz_path = self.tool_dir / f"mihomo-{version}.gz"
            
            print(f"开始下载mihomo {version}...")
            self.download_progress = 0
            urllib.request.urlretrieve(url, gz_path, reporthook=self._progress_hook)
            print("下载完成")
            
            # 解压并设置权限
            print("解压文件中...")
            self.binary_path = self.tool_dir / f"mihomo-{version}"
            with gzip.open(gz_path, 'rb') as f_in:
                with open(self.binary_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            self.binary_path.chmod(0o755)
            gz_path.unlink()
            print("工具准备就绪")
            return True
            
        except Exception as e:
            print(f"工具下载失败: {str(e)}", file=sys.stderr)
            return False

    def prepare(self) -> bool:
        """准备最新版mihomo工具链"""
        self.latest_version = self._get_latest_version()
        if not self.latest_version:
            return False
            
        self.binary_path = self.tool_dir / f"mihomo-{self.latest_version}"
        if self.binary_path.exists():
            print(f"使用缓存工具: {self.latest_version}")
            return True
            
        return self._download_tool(self.latest_version)

class AdRuleConverter:
    """广告规则转换引擎"""
    
    AD_KEYWORDS = {
        'ad', 'ads', 'advert', 'analytics', 'track', 
        'counter', 'metric', 'pixel', 'beacon'
    }

    def __init__(self):
        self.cache = None
        self.stats = {'block': 0, 'allow': 0, 'cached': 0}
        # 预编译正则表达式
        self.rule_patterns: List[Tuple[Pattern, str]] = [
            (re.compile(r'^@@\|\|?([\w*.-]+)\^?'), 'allow'),
            (re.compile(r'^\|\|([\w*.-]+)\^'), 'domain'),
            (re.compile(r'^\|?https?://([\w*.-]+)/?'), 'url'),
            (re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)'), 'hosts'),
            (re.compile(r'^([\w*.-]+)$'), 'plain')
        ]

    def _is_ad_related(self, domain: str) -> bool:
        """宽松模式广告检测"""
        domain = domain.lower()
        return any(kw in domain for kw in self.AD_KEYWORDS)

    def _parse_rule(self, line: str) -> Optional[Dict]:
        """支持所有主流广告规则语法(使用预编译正则)"""
        line = line.strip()
        if not line or line.startswith(('!', '#')):
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
        return None

    def _convert_rule(self, rule: Dict) -> Optional[str]:
        """高精度规则转换"""
        if not rule['domain'] or '*' in rule['domain']:
            return None

        # 检查缓存
        if self.cache:
            cached_rule = self.cache.get_cached_rule(rule['domain'])
            if cached_rule:
                self.stats['cached'] += 1
                return cached_rule

        if rule['type'] == 'allow':
            converted = f"DOMAIN-SUFFIX,{rule['domain']},DIRECT"
            self.stats['allow'] += 1
        else:
            if not rule.get('is_ad', True):
                return None
            converted = f"DOMAIN-SUFFIX,{rule['domain']},REJECT,adblock"
            self.stats['block'] += 1

        # 更新缓存
        if self.cache:
            self.cache.cache_rule(rule['domain'], rule['type'], converted)
        return converted

    def _process_chunk(self, chunk: List[str], file_hash: str) -> List[str]:
        """处理规则块(用于并行处理)"""
        # 每个子进程创建自己的缓存连接
        local_cache = CacheManager()
        self.cache = local_cache
        converted = []
        for line in chunk:
            rule = self._parse_rule(line)
            if rule:
                converted_rule = self._convert_rule(rule)
                if converted_rule:
                    converted.append(converted_rule)
        local_cache.close()
        return converted

    def _file_has_changed(self, file_path: Path) -> bool:
        """检查文件是否修改过"""
        if not file_path.exists():
            return False

        # 计算当前文件哈希
        hasher = md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        current_hash = hasher.hexdigest()

        # 获取上次记录的文件状态
        if not self.cache:
            self.cache = CacheManager()
        meta = self.cache.get_file_meta(file_path)
        if not meta:
            self.cache.update_file_meta(file_path, current_hash)
            return True

        # 检查文件是否修改
        if meta['last_hash'] != current_hash or meta['last_modified'] < file_path.stat().st_mtime:
            self.cache.update_file_meta(file_path, current_hash)
            return True
        return False

    def process_file(self, input_path: Path, is_allow: bool = False) -> List[str]:
        """处理规则文件(带并行处理和增量更新)"""
        converted = []
        if not input_path.exists():
            print(f"文件不存在: {input_path}")
            return converted

        # 增量更新检查
        if not self._file_has_changed(input_path):
            print(f"文件未修改，跳过处理: {input_path.name}")
            return []

        print(f"开始处理文件: {input_path.name}")
        total_lines = sum(1 for _ in open(input_path, 'r', encoding='utf-8', errors='ignore'))
        chunk_size = max(1000, total_lines // (multiprocessing.cpu_count() * 2))
        chunks = []
        current_chunk = []

        # 准备并行处理块
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                current_chunk.append(line)
                if len(current_chunk) >= chunk_size:
                    chunks.append(current_chunk)
                    current_chunk = []
            if current_chunk:
                chunks.append(current_chunk)

        # 并行处理
        print(f"使用 {multiprocessing.cpu_count()} 个进程并行处理...")
        with ProcessPoolExecutor() as executor:
            futures = []
            for chunk in chunks:
                futures.append(executor.submit(
                    self._process_chunk, chunk, str(input_path)))

            for i, future in enumerate(as_completed(futures)):
                print(f"完成块 {i+1}/{len(futures)}")
                converted.extend(future.result())

        print(f"文件处理完成: {len(converted)}条有效规则 (缓存命中: {self.stats['cached']})")
        return converted

    def close(self):
        """关闭缓存连接"""
        if self.cache:
            self.cache.close()
            self.cache = None

def main():
    print(f"{datetime.now()} [INFO] 开始广告规则转换")
    
    # 1. 准备mihomo工具链
    print("准备mihomo工具链...")
    mgr = MihomoManager()
    if not mgr.prepare():
        print(f"{datetime.now()} [ERROR] 无法准备mihomo工具链", file=sys.stderr)
        sys.exit(1)

    # 2. 处理规则文件
    print("处理规则文件中...")
    converter = AdRuleConverter()
    input_files = {
        'allow': REPO_ROOT / "allow.txt",
        'block': REPO_ROOT / "adblock.txt"
    }
    
    rules = []
    for name, path in input_files.items():
        file_rules = converter.process_file(path, is_allow=(name == 'allow'))
        if file_rules:
            rules.extend(file_rules)

    # 3. 添加系统必要规则
    print("添加系统必要规则...")
    essential_rules = [
        "GEOSITE,ads,REJECT",  # 广告域名分类
        "GEOIP,CN,DIRECT",     # 中国IP直连
        "MATCH,PROXY"          # 默认策略
    ]
    rules.extend(essential_rules)

    # 4. 生成临时规则文件（带广告参数）
    print("生成临时规则文件...")
    with tempfile.NamedTemporaryFile(mode='w+') as tmp:
        tmp.write(f"""params:
  enable-adblock: true
  adblock-speedup: true
  strict-mode: {str(STRICT_MODE).lower()}
  disable-geoip: false
rules:
""")
        tmp.write("\n".join(rules))
        tmp.flush()

        # 5. 转换为.mrs格式
        print("开始规则转换...")
        result = subprocess.run([
            str(mgr.binary_path), "rulegen",
            "-i", tmp.name,
            "-o", str(REPO_ROOT / "adb.mrs"),
            "--adblock",
            "--strict" if STRICT_MODE else "--loose"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"{datetime.now()} [ERROR] 规则生成失败: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    # 输出统计
    print(f"{datetime.now()} [INFO] 转换成功！")
    print(f"拦截规则: {converter.stats['block']}条")
    print(f"白名单规则: {converter.stats['allow']}条")
    print(f"缓存命中: {converter.stats['cached']}条")
    print(f"输出文件: {REPO_ROOT/'adblock.mrs'}")
    
    converter.close()

if __name__ == "__main__":
    multiprocessing.freeze_support()  # 确保在Windows下打包后多进程正常工作
    main()