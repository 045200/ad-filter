#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adblock Plus规则处理（支持GitHub环境变量，分黑白名单输出）"""

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
    # 移除OUTPUT_DIR，直接在根目录输出文件
    OUTPUT_FILE = BASE_DIR / "adblock_adp.txt"  # 拦截规则（根目录）
    ALLOW_FILE = BASE_DIR / "allow_adp.txt"     # 白名单规则（根目录）
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    # 黑名单规则（Adblock Plus标准语法）
    BLACK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')  # ||domain.com^
    BLACK_ELEMENT = re.compile(r'^[\w.-]+##.+$')  # domain.com##.ad
    BLACK_WILDCARD = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)  # *adserver*
    BLACK_REGEX = re.compile(r'^/.*/$')  # /^https?:\/\/ad/
    BLACK_OPTIONS = re.compile(r'^[\w.-]+\$[\w,-]+$')  # domain.com$script,third-party

    # 白名单规则（Adblock Plus例外语法）
    WHITE_DOMAIN = re.compile(r'^@@\|\|([\w.-]+)\^?$')  # @@||domain.com^
    WHITE_ELEMENT = re.compile(r'^[\w.-]+#@#+$')  # domain.com#@#.ad
    WHITE_OPTIONS = re.compile(r'^@@[\w.-]+\$[\w,-]+$')  # @@domain.com$script

    # 可转换规则
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # Hosts -> 黑名单
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a.[]{2,}$')  # 纯域名 -> 黑名单

    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    UNSUPPORTED = re.compile(r'##\+js\(|\$csp=|\$redirect=')


def setup_logger():
    """适配GitHub Actions的日志格式，支持通知级别的日志显示"""
    logger = logging.getLogger('AdblockPlusSplit')
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
            # 对GitHub Actions输出特殊格式（::notice::message）
            if record.levelno == logging.INFO:
                return f"::notice::{record.getMessage()}"
            elif record.levelno == logging.WARNING:
                return f"::warning::{record.getMessage()}"
            elif record.levelno == logging.ERROR:
                return f"::error::{record.getMessage()}"
            return record.getMessage()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GitHubFormatter())
    logger.handlers = [handler]
    return logger

logger = setup_logger()


class AdblockPlusSplitter:
        def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
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
        logger.info("===== Adblock Plus 黑白名单处理（GitHub环境适配） =====")
        # 读取输入文件（支持GitHub工作目录下的input目录）
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            # 修复：补充闭合glob.glob的括号和列表推导式的括号
            input_files.extend([Path(p) for p in glob.glob(str(Path(Config.INPUT_DIR) / pattern))])

        if not input_files:
            logger.error(f"未在输入目录 {Config.INPUT_DIR} 找到文件（格式：{Config.INPUT_PATTERNS}）")
            return

        # 全局去重缓存
        black_cache: Set[str] = set()
        white_cache: Set[str] = set()
        total_stats = {'black': 0, 'white': 0, 'filtered': 0, 'unsupported': 0}

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file = futures[future]
                try:
                    (black_rules, white_rules), stats = future.result()
                    # 全局去重后添加
                    new_black = [r for r in black_rules if r not in black_cache]
                    new_white = [r for r in white_rules if r not in white_cache]
                    black_cache.update(new_black)
                    white_cache.update(new_white)
                    # 累加统计
                    total_stats['black'] += len(new_black)
                    total_stats['white'] += len(new_white)
                    total_stats['filtered'] += stats['filtered']
                    total_stats['unsupported'] += stats['unsupported']
                    logger.info(f"处理 {file.name}：新增黑名单{len(new_black)}条，白名单{len(new_white)}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败：{str(e)}")

        # 写入输出文件（支持GitHub工作目录下的output目录）
        with open(Config.OUTPUT_BLACK, 'w', encoding='utf-8') as f:
            f.write('\n'.join(black_cache) + '\n')
        with open(Config.OUTPUT_WHITE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(white_cache) + '\n')

        # 输出GitHub Actions可识别的结果（用于后续步骤引用）
        print(f"::set-output name=blacklist_path::{Config.OUTPUT_BLACK}")
        print(f"::set-output name=whitelist_path::{Config.OUTPUT_WHITE}")
        print(f"::set-output name=blacklist_count::{total_stats['black']}")
        print(f"::set-output name=whitelist_count::{total_stats['white']}")

        logger.info(f"\n处理完成：\n黑名单规则：{total_stats['black']}条\n白名单规则：{total_stats['white']}条")
        logger.info(f"过滤无效规则：{total_stats['filtered']}条，不支持规则：{total_stats['unsupported']}条")
        logger.info(f"耗时：{time.time()-start_time:.2f}秒")

    def _process_file(self, file_path: Path) -> Tuple[Tuple[List[str], List[str]], Dict]:
        """处理单个文件，返回（黑名单，白名单）及统计"""
        black_rules: List[str] = []
        white_rules: List[str] = []
        stats = {'filtered': 0, 'unsupported': 0}
        # 单文件内去重缓存
        file_black_cache: Set[str] = set()
        file_white_cache: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # 分类处理规则
                    rule_type, rule = self._classify_rule(line)
                    if rule_type == 'black' and rule not in file_black_cache:
                        file_black_cache.add(rule)
                        black_rules.append(rule)
                    elif rule_type == 'white' and rule not in file_white_cache:
                        file_white_cache.add(rule)
                        white_rules.append(rule)
                    elif rule_type == 'filtered':
                        stats['filtered'] += 1
                    else:
                        stats['unsupported'] += 1
        except Exception as e:
            logger.warning(f"读取{file_path.name}出错：{str(e)}")

        return (black_rules, white_rules), stats

    def _classify_rule(self, line: str) -> Tuple[str, str]:
        """判断规则类型（black/white/filtered/unsupported）"""
        # 过滤注释和无效长度
        if self.regex.COMMENT.match(line) or not (self.len_min <= len(line) <= self.len_max):
            return ('filtered', '')
        # 过滤不支持的语法
        if self.regex.UNSUPPORTED.search(line):
            return ('unsupported', '')

        # 白名单规则
        if (self.regex.WHITE_DOMAIN.match(line) or 
            self.regex.WHITE_ELEMENT.match(line) or 
            self.regex.WHITE_OPTIONS.match(line)):
            return ('white', line)

        # 黑名单规则（原生）
        if (self.regex.BLACK_DOMAIN.match(line) or 
            self.regex.BLACK_ELEMENT.match(line) or 
            self.regex.BLACK_WILDCARD.match(line) or 
            self.regex.BLACK_REGEX.match(line) or 
            self.regex.BLACK_OPTIONS.match(line)):
            return ('black', line)

        # 转换Hosts为黑名单
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            black_rule = f"||{hosts_match.group(2)}^"
            return ('black', black_rule)

        # 转换纯域名为黑名单
        if self.regex.PLAIN_DOMAIN.match(line):
            black_rule = f"||{line}^"
            return ('black', black_rule)

        # 未匹配的规则
        return ('unsupported', '')


if __name__ == '__main__':
    try:
        splitter = AdblockPlusSplitter()
        splitter.run()
    except Exception as e:
        logger.critical(f"运行失败：{str(e)}", exc_info=True)
        sys.exit(1)
