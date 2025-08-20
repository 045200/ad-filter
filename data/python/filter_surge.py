#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Surge规则转换工具（无头部信息）"""

import os
import sys
import glob
import re
import logging
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, List, Set, Dict


class Config:
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    OUTPUT_DIR = BASE_DIR / os.getenv('OUTPUT_DIR', 'output')
    OUTPUT_FILE = OUTPUT_DIR / "adblock_surge.conf"  # 拦截规则
    ALLOW_FILE = OUTPUT_DIR / "allow_surge.conf"     # 允许规则
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)\^?$')
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a-z]{2,}$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    SURGE_RULE = re.compile(r'^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR).+$')  # Surge原生规则


def setup_logger():
    logger = logging.getLogger('SurgeMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    
    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


def gh_group(name: str):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::endgroup::")


def check_file_size(file_path: Path) -> bool:
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > Config.MAX_FILESIZE_MB:
            logger.warning(f"跳过大文件 {file_path.name}（{size_mb:.1f}MB）")
            return False
        return True
    except Exception as e:
        logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
        return False


class SurgeMerger:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        # 清理原有输出
        if Config.OUTPUT_FILE.exists():
            Config.OUTPUT_FILE.unlink()
        if Config.ALLOW_FILE.exists():
            Config.ALLOW_FILE.unlink()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        gh_group("===== Surge规则转换 =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出拦截规则: {Config.OUTPUT_FILE}")
        logger.info(f"输出允许规则: {Config.ALLOW_FILE}")

        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        all_block: List[str] = []
        all_allow: List[str] = []
        block_cache: Set[str] = set()
        allow_cache: Set[str] = set()
        total_stats = self._empty_stats()

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, file): file for file in input_files}
            
            for future in as_completed(futures):
                file = futures[future]
                try:
                    block, allow, stats = future.result()
                    new_block = [r for r in block if r not in block_cache]
                    new_allow = [r for r in allow if r not in allow_cache]
                    
                    all_block.extend(new_block)
                    all_allow.extend(new_allow)
                    block_cache.update(new_block)
                    allow_cache.update(new_allow)
                    
                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效规则{stats['valid']}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败: {str(e)}")

        # 写入纯净Surge规则（无头部）
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_block) + '\n')

        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_allow) + '\n')

        elapsed = time.time() - start_time
        logger.info(f"\n处理完成：拦截规则{len(all_block)}条，允许规则{len(all_allow)}条，耗时{elapsed:.2f}秒")
        gh_endgroup()

        if os.getenv('GITHUB_ACTIONS') == 'true':
            logger.info(f"::set-output name=surge_file::{Config.OUTPUT_FILE}")
            logger.info(f"::set-output name=surge_allow_file::{Config.ALLOW_FILE}")

    def _process_file(self, file_path: Path) -> Tuple[List[str], List[str], Dict]:
        if not check_file_size(file_path):
            return [], [], self._empty_stats()

        stats = self._empty_stats()
        local_block: List[str] = []
        local_allow: List[str] = []
        block_cache: Set[str] = set()
        allow_cache: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    rule, is_allow = self._process_line(line, stats)
                    if rule:
                        if is_allow and rule not in allow_cache:
                            local_allow.append(rule)
                            allow_cache.add(rule)
                        elif not is_allow and rule not in block_cache:
                            local_block.append(rule)
                            block_cache.add(rule)
        except Exception as e:
            logger.error(f"读取{file_path.name}出错: {str(e)}")

        return local_block, local_allow, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        stats['total'] += 1

        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None, False

        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None, False

        # 转换为Surge规则
        surge_rule, is_allow = self._to_surge(line)
        if not surge_rule:
            stats['unsupported'] += 1
            return None, False

        stats['valid'] += 1
        return surge_rule, is_allow

    def _to_surge(self, line: str) -> Tuple[str, bool]:
        # 白名单规则（@@开头）
        if line.startswith('@@'):
            normalized = line[2:]
            adblock_match = self.regex.ADBLOCK_DOMAIN.match(normalized)
            if adblock_match:
                domain = adblock_match.group(1)
                return f"DOMAIN-SUFFIX,{domain},DIRECT", True  # Surge允许规则走DIRECT
            return None, True

        # Adblock域名规则 → Surge DOMAIN-SUFFIX
        adblock_match = self.regex.ADBLOCK_DOMAIN.match(line)
        if adblock_match:
            domain = adblock_match.group(1)
            return f"DOMAIN-SUFFIX,{domain},REJECT", False

        # Hosts规则 → Surge DOMAIN-SUFFIX
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            return f"DOMAIN-SUFFIX,{domain},REJECT", False

        # 纯域名 → Surge DOMAIN-SUFFIX
        if self.regex.PLAIN_DOMAIN.match(line):
            return f"DOMAIN-SUFFIX,{line},REJECT", False

        # 保留Surge原生规则
        if self.regex.SURGE_RULE.match(line):
            # 判断是否为允许规则（含DIRECT）
            is_allow = ',DIRECT' in line
            return line, is_allow

        return None, False

    @staticmethod
    def _empty_stats() -> Dict:
        return {'total': 0, 'valid': 0, 'filtered': 0, 'unsupported': 0}

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        for key in total:
            total[key] += new[key]
        return total


if __name__ == '__main__':
    try:
        merger = SurgeMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
