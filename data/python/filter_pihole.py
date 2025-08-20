#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pi-hole规则转换工具（无头部信息）"""

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
    # 输入：根目录下的临时目录
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    # 输出：直接在根目录
    OUTPUT_FILE = BASE_DIR / "adblock_pihole.txt"  # 拦截域名
    ALLOW_FILE = BASE_DIR / "allow_pihole.txt"     # 允许域名
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 255)  # Pi-hole域名长度限制
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')  # 提取域名
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)\^?$')  # 提取白名单域名
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # 提取hosts域名
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a-z]{2,}$')  # 纯域名匹配
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')


def setup_logger():
    logger = logging.getLogger('PiholeMerger')
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


class PiholeMerger:
    def __init__(self):
        # 确保临时目录存在（输入目录）
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        # 清理根目录下的旧输出文件
        if Config.OUTPUT_FILE.exists():
            Config.OUTPUT_FILE.unlink()
        if Config.ALLOW_FILE.exists():
            Config.ALLOW_FILE.unlink()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        gh_group("===== Pi-hole规则转换 =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出拦截域名: {Config.OUTPUT_FILE}")
        logger.info(f"输出允许域名: {Config.ALLOW_FILE}")

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
                    new_block = [d for d in block if d not in block_cache]
                    new_allow = [d for d in allow if d not in allow_cache]

                    all_block.extend(new_block)
                    all_allow.extend(new_allow)
                    block_cache.update(new_block)
                    allow_cache.update(new_allow)

                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效域名{stats['valid']}个")
                except Exception as e:
                    logger.error(f"处理{file.name}失败: {str(e)}")

        # 写入纯净域名（无头部，每行一个域名）到根目录
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_block) + '\n')

        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_allow) + '\n')

        elapsed = time.time() - start_time
        logger.info(f"\n处理完成：拦截域名{len(all_block)}个，允许域名{len(all_allow)}个，耗时{elapsed:.2f}秒")
        gh_endgroup()

        # 输出GitHub Actions变量（使用环境文件）
        if os.getenv('GITHUB_ACTIONS') == 'true':
            github_output = os.getenv('GITHUB_OUTPUT')
            if github_output:
                with open(github_output, 'a') as f:
                    f.write(f"pihole_file={Config.OUTPUT_FILE}\n")
                    f.write(f"pihole_allow_file={Config.ALLOW_FILE}\n")

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
                    domain, is_allow = self._process_line(line, stats)
                    if domain:
                        if is_allow and domain not in allow_cache:
                            local_allow.append(domain)
                            allow_cache.add(domain)
                        elif not is_allow and domain not in block_cache:
                            local_block.append(domain)
                            block_cache.add(domain)
        except Exception as e:
            logger.error(f"读取{file_path.name}出错: {str(e)}")

        return local_block, local_allow, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        stats['total'] += 1

        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None, False

        # 提取Adblock域名规则
        adblock_match = self.regex.ADBLOCK_DOMAIN.match(line)
        if adblock_match:
            domain = adblock_match.group(1)
            if self._is_valid_domain(domain):
                stats['valid'] += 1
                return domain, False

        # 提取Adblock白名单域名
        whitelist_match = self.regex.ADBLOCK_WHITELIST.match(line)
        if whitelist_match:
            domain = whitelist_match.group(1)
            if self._is_valid_domain(domain):
                stats['valid'] += 1
                return domain, True

        # 提取Hosts域名
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                stats['valid'] += 1
                return domain, False

        # 纯域名直接使用
        if self.regex.PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                stats['valid'] += 1
                return line, False

        stats['unsupported'] += 1
        return None, False

    def _is_valid_domain(self, domain: str) -> bool:
        """检查域名长度是否符合Pi-hole要求"""
        return self.len_min <= len(domain) <= self.len_max

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
        merger = PiholeMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
