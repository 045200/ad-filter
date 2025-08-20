#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Hosts规则转换工具（无头部信息）"""

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
    OUTPUT_FILE = OUTPUT_DIR / "hosts.txt"  # hosts格式拦截规则
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 255)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]
    HOSTS_IP = "0.0.0.0"  # 统一使用0.0.0.0作为拦截IP


class RegexPatterns:
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a.[]{2,}$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')


def setup_logger():
    logger = logging.getLogger('HostsMerger')
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


class HostsMerger:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        # 清理原有输出
        if Config.OUTPUT_FILE.exists():
            Config.OUTPUT_FILE.unlink()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        gh_group("===== Hosts规则转换 =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出文件: {Config.OUTPUT_FILE}（IP: {Config.HOSTS_IP}）")

        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        all_hosts: List[str] = []
        hosts_cache: Set[str] = set()  # 用域名去重（忽略IP差异）
        total_stats = self._empty_stats()

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, file): file for file in input_files}

            for future in as_completed(futures):
                file = futures[future]
                try:
                    hosts, stats = future.result()
                    # 去重逻辑：提取域名部分判断
                    new_hosts = []
                    for host_line in hosts:
                        domain = host_line.split()[1]
                        if domain not in hosts_cache:
                            new_hosts.append(host_line)
                            hosts_cache.add(domain)

                    all_hosts.extend(new_hosts)
                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效规则{stats['valid']}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败: {str(e)}")

        # 写入纯净hosts规则（无头部，每行格式：IP 域名）
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_hosts) + '\n')

        elapsed = time.time() - start_time
        logger.info(f"\n处理完成：共{len(all_hosts)}条hosts规则，耗时{elapsed:.2f}秒")
        gh_endgroup()

        # 替换已弃用的set-output，使用GITHUB_OUTPUT环境文件
        if os.getenv('GITHUB_ACTIONS') == 'true':
            github_output = os.getenv('GITHUB_OUTPUT')
            if github_output:
                with open(github_output, 'a', encoding='utf-8') as f:
                    f.write(f"hosts_file={Config.OUTPUT_FILE}\n")

    def _process_file(self, file_path: Path) -> Tuple[List[str], Dict]:
        if not check_file_size(file_path):
            return [], self._empty_stats()

        stats = self._empty_stats()
        local_hosts: List[str] = []
        local_cache: Set[str] = set()  # 按域名去重

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    host_line = self._process_line(line, stats)
                    if host_line:
                        domain = host_line.split()[1]
                        if domain not in local_cache:
                            local_hosts.append(host_line)
                            local_cache.add(domain)
        except Exception as e:
            logger.error(f"读取{file_path.name}出错: {str(e)}")

        return local_hosts, stats

    def _process_line(self, line: str, stats: Dict) -> str:
        stats['total'] += 1

        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None

        # 转换Adblock域名规则为hosts
        adblock_match = self.regex.ADBLOCK_DOMAIN.match(line)
        if adblock_match:
            domain = adblock_match.group(1)
            if self._is_valid_domain(domain):
                stats['valid'] += 1
                return f"{Config.HOSTS_IP} {domain}"

        # 转换纯域名为hosts
        if self.regex.PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                stats['valid'] += 1
                return f"{Config.HOSTS_IP} {line}"

        # 标准化现有hosts规则（统一IP）
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                stats['valid'] += 1
                return f"{Config.HOSTS_IP} {domain}"

        stats['unsupported'] += 1
        return None

    def _is_valid_domain(self, domain: str) -> bool:
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
        merger = HostsMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
