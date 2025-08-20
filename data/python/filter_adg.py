#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AdGuard规则转换工具（无头部信息）"""

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
    # 优先读取GitHub环境变量，适配GitHub Actions
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")  # GitHub工作区根目录
    RUNNER_TEMP = os.getenv("RUNNER_TEMP", os.getenv("TEMP_DIR", "tmp"))  # GitHub Runner临时目录
    # 输入目录：仓库根目录的临时目录（tmp）
    INPUT_DIR = Path(os.getenv("INPUT_DIR", Path(GITHUB_WORKSPACE) / "tmp" if GITHUB_WORKSPACE else "tmp"))
    # 输出目录：仓库根目录
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", GITHUB_WORKSPACE if GITHUB_WORKSPACE else "."))
    # 输出文件（基于输出目录，即根目录）
    OUTPUT_FILE = OUTPUT_DIR / "adblock_adg.txt"  # 拦截规则（根目录）
    ALLOW_FILE = OUTPUT_DIR / "allow_adg.txt"     # 白名单规则（根目录）
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)\^?$')
    ADBLOCK_ELEMENT = re.compile(r'^[\w.-]+##.+$')
    ADBLOCK_ELEMENT_EXCEPT = re.compile(r'^[\w.-]+#@#+$')
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a.[]{2,}$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    ADGUARD_CSP = re.compile(r'^[\w.-]+\$csp=')
    ADGUARD_REDIRECT = re.compile(r'^[\w.-]+\$redirect=')


def setup_logger():
    logger = logging.getLogger('AdGuardMerger')
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


class AdGuardMerger:
    def __init__(self):
        # 创建输入/输出目录（若不存在）
        Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        # 清理原有输出文件
        if Config.OUTPUT_FILE.exists():
            Config.OUTPUT_FILE.unlink()
        if Config.ALLOW_FILE.exists():
            Config.ALLOW_FILE.unlink()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        gh_group("===== AdGuard规则转换 =====")
        logger.info(f"输入目录: {Config.INPUT_DIR}")
        logger.info(f"输出规则: {Config.OUTPUT_FILE}")
        logger.info(f"输出白名单: {Config.ALLOW_FILE}")

        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.INPUT_DIR / pattern))])
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        all_rules: List[str] = []
        all_allows: List[str] = []
        global_cache: Set[str] = set()
        global_allow_cache: Set[str] = set()
        total_stats = self._empty_stats()

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, file): file for file in input_files}

            for future in as_completed(futures):
                file = futures[future]
                try:
                    rules, allows, stats = future.result()
                    new_rules = [r for r in rules if r not in global_cache]
                    new_allows = [a for a in allows if a not in global_allow_cache]

                    all_rules.extend(new_rules)
                    all_allows.extend(new_allows)
                    global_cache.update(new_rules)
                    global_allow_cache.update(new_allows)

                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效规则{stats['valid']}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败: {str(e)}")

        # 写入纯净规则（无头部）
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_rules) + '\n')

        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_allows) + '\n')

        elapsed = time.time() - start_time
        logger.info(f"\n处理完成：总规则{len(all_rules)}条，白名单{len(all_allows)}条，耗时{elapsed:.2f}秒")
        gh_endgroup()

        # 替换已弃用的set-output，使用GitHub环境文件设置输出
        if os.getenv('GITHUB_ACTIONS') == 'true':
            github_output = os.getenv('GITHUB_OUTPUT')
            if github_output:
                with open(github_output, 'a', encoding='utf-8') as f:
                    f.write(f"adguard_file={Config.OUTPUT_FILE}\n")
                    f.write(f"adguard_allow_file={Config.ALLOW_FILE}\n")

    def _process_file(self, file_path: Path) -> Tuple[List[str], List[str], Dict]:
        if not check_file_size(file_path):
            return [], [], self._empty_stats()

        stats = self._empty_stats()
        local_rules: List[str] = []
        local_allows: List[str] = []
        local_cache: Set[str] = set()
        local_allow_cache: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    rule, is_allow = self._process_line(line, stats)
                    if rule:
                        if is_allow and rule not in local_allow_cache:
                            local_allows.append(rule)
                            local_allow_cache.add(rule)
                        elif not is_allow and rule not in local_cache:
                            local_rules.append(rule)
                            local_cache.add(rule)
        except Exception as e:
            logger.error(f"读取{file_path.name}出错: {str(e)}")

        return local_rules, local_allows, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        stats['total'] += 1

        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None, False

        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None, False

        adguard_rule, is_allow = self._to_adguard(line)
        if not adguard_rule:
            stats['unsupported'] += 1
            return None, False

        stats['valid'] += 1
        return adguard_rule, is_allow

    def _to_adguard(self, line: str) -> Tuple[str, bool]:
        # 白名单规则（@@开头）
        if line.startswith('@@'):
            normalized = line[2:]
            if self.regex.ADBLOCK_DOMAIN.match(normalized):
                return normalized, True
            return line, True

        # Hosts规则转换
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            return f"||{hosts_match.group(2)}^", False

        # 纯域名转换
        if self.regex.PLAIN_DOMAIN.match(line):
            return f"||{line}^", False

        # 保留AdGuard特有规则
        if self.regex.ADGUARD_CSP.match(line) or self.regex.ADGUARD_REDIRECT.match(line):
            return line, False

        # 保留标准Adblock规则
        if self.regex.ADBLOCK_DOMAIN.match(line) or self.regex.ADBLOCK_ELEMENT.match(line):
            return line, False

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
        merger = AdGuardMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
