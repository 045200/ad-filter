#!/usr/bin/env python3
"""
广告规则转换终极完整版-并行优化版
重点优化了adblock.txt的并行处理稳定性
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
BLOOM_FILTER_SIZE = 1000000  # Bloom filter大小

class BloomFilter:
    """优化版Bloom filter"""
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
        self.bloom = self._init_bloom_filter()

    def _init_db(self):
        """初始化数据库结构"""
        with self._get_connection() as conn:
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

    def _init_bloom_filter(self):
        """初始化Bloom filter"""
        bloom = BloomFilter(BLOOM_FILTER_SIZE)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM rule_cache")
            for (domain,) in cursor.fetchall():
                bloom.add(domain)
        return bloom

    def _get_connection(self):
        """获取新的数据库连接"""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    # 其他方法保持不变...
    def get_file_meta(self, file_path: Path) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT last_hash, last_modified FROM file_meta WHERE path = ?",
                (str(file_path),))
            row = cursor.fetchone()
            return dict(zip(['last_hash', 'last_modified'], row)) if row else None

    def update_file_meta(self, file_path: Path, file_hash: str) -> None:
        mtime = file_path.stat().st_mtime
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_meta VALUES (?, ?, ?)",
                (str(file_path), file_hash, mtime))
            conn.commit()

    def get_cached_rule(self, domain: str) -> Optional[str]:
        if domain not in self.bloom:
            return None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT converted_rule FROM rule_cache WHERE domain = ?",
                (domain,))
            row = cursor.fetchone()
            return row[0] if row else None

    def cache_rule(self, domain: str, rule_type: str, converted_rule: str) -> None:
        if domain not in self.bloom:
            self.bloom.add(domain)
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO rule_cache VALUES (?, ?, ?, NULL, NULL)",
                    (domain, rule_type, converted_rule))
                conn.commit()

class AdRuleConverter:
    """广告规则转换引擎（并行优化版）"""
    
    AD_KEYWORDS = {
        'ad', 'ads', 'advert', 'analytics', 'track', 
        'counter', 'metric', 'pixel', 'beacon'
    }

    def __init__(self):
        self.stats = {'block': 0, 'allow': 0, 'cached': 0}
        self.rule_patterns = [
            (re.compile(r'^@@\|\|?([\w*.-]+)\^?'), 'allow'),
            (re.compile(r'^\|\|([\w*.-]+)\^'), 'domain'),
            (re.compile(r'^\|?https?://([\w*.-]+)/?'), 'url'),
            (re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)'), 'hosts'),
            (re.compile(r'^([\w*.-]+)$'), 'plain')
        ]
        self.cache = CacheManager.get_instance()

    def _is_ad_related(self, domain: str) -> bool:
        domain = domain.lower()
        return any(kw in domain for kw in self.AD_KEYWORDS)

    def _parse_rule(self, line: str) -> Optional[Dict]:
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
        if not rule['domain'] or '*' in rule['domain']:
            return None

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

        self.cache.cache_rule(rule['domain'], rule['type'], converted)
        return converted

    def _process_chunk(self, chunk: List[str]) -> List[str]:
        """独立进程处理函数"""
        # 每个进程创建自己的转换器实例
        local_converter = AdRuleConverter()
        converted = []
        for line in chunk:
            rule = local_converter._parse_rule(line)
            if rule:
                converted_rule = local_converter._convert_rule(rule)
                if converted_rule:
                    converted.append(converted_rule)
        return converted

    def _file_has_changed(self, file_path: Path) -> bool:
        if not file_path.exists():
            return False

        hasher = md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        current_hash = hasher.hexdigest()

        meta = self.cache.get_file_meta(file_path)
        if not meta:
            self.cache.update_file_meta(file_path, current_hash)
            return True

        if meta['last_hash'] != current_hash or meta['last_modified'] < file_path.stat().st_mtime:
            self.cache.update_file_meta(file_path, current_hash)
            return True
        return False

    def process_file(self, input_path: Path, is_allow: bool = False) -> List[str]:
        if not input_path.exists():
            print(f"文件不存在: {input_path}")
            return []

        if not self._file_has_changed(input_path):
            print(f"文件未修改，跳过处理: {input_path.name}")
            return []

        print(f"开始处理文件: {input_path.name}")
        
        # 读取文件内容到内存
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # 动态调整块大小
        cpu_count = multiprocessing.cpu_count()
        chunk_size = max(1000, len(lines) // (cpu_count * 2))
        
        # 特别处理大文件（如adblock.txt）
        if len(lines) > 50000:  # 超过5万行
            chunk_size = max(5000, len(lines) // cpu_count)
            print(f"大文件检测，调整块大小为: {chunk_size}")

        chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
        
        print(f"使用 {cpu_count} 个进程处理 {len(chunks)} 个数据块...")
        
        # 使用进程池处理
        with ProcessPoolExecutor(max_workers=cpu_count) as executor:
            futures = [executor.submit(self._process_chunk, chunk) for chunk in chunks]
            
            converted = []
            for future in as_completed(futures):
                try:
                    converted.extend(future.result())
                except Exception as e:
                    print(f"处理块时出错: {str(e)}", file=sys.stderr)
                    continue

        print(f"处理完成: 生成 {len(converted)} 条规则 (缓存命中: {self.stats['cached']})")
        return converted

# MihomoManager 类保持不变...

def main():
    print(f"{datetime.now()} [INFO] 开始广告规则转换（并行优化版）")

    # 初始化缓存
    CacheManager.get_instance()

    # 准备工具链
    mgr = MihomoManager()
    if not mgr.prepare():
        print(f"{datetime.now()} [ERROR] 工具链准备失败", file=sys.stderr)
        sys.exit(1)

    # 处理规则文件
    converter = AdRuleConverter()
    input_files = {
        'allow': REPO_ROOT / "allow.txt",
        'block': REPO_ROOT / "adblock.txt"
    }

    rules = []
    for name, path in input_files.items():
        file_rules = converter.process_file(path, is_allow=(name == 'allow'))
        rules.extend(file_rules)

    # 添加系统规则
    rules.extend([
        "GEOSITE,ads,REJECT",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY"
    ])

    # 生成规则文件
    with tempfile.NamedTemporaryFile(mode='w+') as tmp:
        tmp.write(f"""params:
  enable-adblock: true
  adblock-speedup: true
  strict-mode: {str(STRICT_MODE).lower()}
rules:
""")
        tmp.write("\n".join(rules))
        tmp.flush()

        result = subprocess.run([
            str(mgr.binary_path), "rulegen",
            "-i", tmp.name,
            "-o", str(REPO_ROOT / "adblock.mrs"),
            "--adblock",
            "--strict" if STRICT_MODE else "--loose"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"规则生成失败: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    print(f"{datetime.now()} [SUCCESS] 转换完成")
    print(f"拦截规则: {converter.stats['block']}")
    print(f"放行规则: {converter.stats['allow']}")
    print(f"输出文件: {REPO_ROOT/'adblock.mrs'}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()