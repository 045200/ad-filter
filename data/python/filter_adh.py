#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AdGuard Home规则处理（GitHub环境适配，分黑白名单输出）"""

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
    # GitHub环境变量适配
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    RUNNER_TEMP = os.getenv("RUNNER_TEMP", os.getenv("TEMP_DIR", "tmp"))
    INPUT_DIR = os.getenv("INPUT_DIR", f"{GITHUB_WORKSPACE}/input" if GITHUB_WORKSPACE else "input")
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", f"{GITHUB_WORKSPACE}/output" if GITHUB_WORKSPACE else "output")

    # 输出文件路径
    OUTPUT_BLACK = Path(OUTPUT_DIR) / "adblock_adh.txt"
    OUTPUT_WHITE = Path(OUTPUT_DIR) / "allow_adh.txt"
    TEMP_DIR = Path(RUNNER_TEMP) / "adguard_processing"

    # 可配置参数
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", str(min(os.cpu_count() or 4, 4))))
    RULE_LEN_RANGE = (3, 4096)
    INPUT_PATTERNS = os.getenv("INPUT_PATTERNS", "*.txt,*.list,*.hosts").split(",")


class RegexPatterns:
    # 黑名单规则（AdGuard原生语法）
    BLACK_HOSTS = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # 原生hosts格式
    BLACK_DOMAIN = re.compile(r'^[\w.-]+$')  # 纯域名（AdGuard直接支持）
    BLACK_ADBLOCK = re.compile(r'^(||[\w.-]+\^?|[\w.-]+\$[\w,-]+)$')  # 兼容Adblock语法
    BLACK_CUSTOM = re.compile(r'^\/.+\//$')  # 正则规则（如/^https?:\/\/ad/）

    # 白名单规则（AdGuard允许规则）
    WHITE_PREFIX = re.compile(r'^@@.+$')  # @@前缀（兼容Adblock例外）
    WHITE_DOMAIN = re.compile(r'^#?allow:.+$')  # AdGuard原生允许格式（allow:domain.com）
    WHITE_ADBLOCK = re.compile(r'^@@\|\|[\w.-]+\^?$')  # 兼容Adblock白名单

    # 过滤项
    COMMENT = re.compile(r'^[!#;]')  # AdGuard注释支持!、#、;
    EMPTY_LINE = re.compile(r'^\s*$')
    UNSUPPORTED = re.compile(r'##\+js\(|\$redirect=')  # AdGuard不支持的uBO特有语法


def setup_logger():
    """GitHub Actions日志适配"""
    logger = logging.getLogger('AdGuardSplit')
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
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


class AdGuardSplitter:
    def __init__(self):
        # 创建目录（适配GitHub权限）
        for dir_path in [Config.TEMP_DIR, Path(Config.INPUT_DIR), Path(Config.OUTPUT_DIR)]:
            dir_path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(dir_path, 0o755)

        # 清理旧文件
        for f in [Config.OUTPUT_BLACK, Config.OUTPUT_WHITE]:
            if f.exists():
                f.unlink()

        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        logger.info("===== AdGuard Home 黑白名单处理（GitHub环境适配） =====")

        # 加载输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Path(Config.INPUT_DIR) / pattern))])

        if not input_files:
            logger.error(f"未在 {Config.INPUT_DIR} 找到文件（格式：{Config.INPUT_PATTERNS}）")
            return

        # 全局去重缓存
        black_cache: Set[str] = set()
        white_cache: Set[str] = set()
        total_stats = {'black': 0, 'white': 0, 'filtered': 0, 'unsupported': 0}

        # 并发处理文件
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file = futures[future]
                try:
                    (black_rules, white_rules), stats = future.result()
                    # 全局去重
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

        # 写入输出文件
        with open(Config.OUTPUT_BLACK, 'w', encoding='utf-8') as f:
            f.write('\n'.join(black_cache) + '\n')
        with open(Config.OUTPUT_WHITE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(white_cache) + '\n')

        # 输出GitHub Actions变量
        print(f"::set-output name=adguard_blacklist_path::{Config.OUTPUT_BLACK}")
        print(f"::set-output name=adguard_whitelist_path::{Config.OUTPUT_WHITE}")
        print(f"::set-output name=adguard_blacklist_count::{total_stats['black']}")
        print(f"::set-output name=adguard_whitelist_count::{total_stats['white']}")

        logger.info(f"\n处理完成：\n黑名单：{total_stats['black']}条\n白名单：{total_stats['white']}条")
        logger.info(f"过滤无效规则：{total_stats['filtered']}条，不支持规则：{total_stats['unsupported']}条")
        logger.info(f"耗时：{time.time()-start_time:.2f}秒")

    def _process_file(self, file_path: Path) -> Tuple[Tuple[List[str], List[str]], Dict]:
        """处理单个文件，返回黑白名单及统计"""
        black_rules: List[str] = []
        white_rules: List[str] = []
        stats = {'filtered': 0, 'unsupported': 0}
        file_black_cache: Set[str] = set()
        file_white_cache: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
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
        """分类规则类型（适配AdGuard语法）"""
        # 过滤注释和无效长度
        if self.regex.COMMENT.match(line) or not (self.len_min <= len(line) <= self.len_max):
            return ('filtered', '')

        # 过滤AdGuard不支持的语法
        if self.regex.UNSUPPORTED.search(line):
            return ('unsupported', '')

        # 白名单规则（AdGuard允许规则）
        if (self.regex.WHITE_PREFIX.match(line) or 
            self.regex.WHITE_DOMAIN.match(line) or 
            self.regex.WHITE_ADBLOCK.match(line)):
            # 统一白名单格式（AdGuard兼容@@前缀和allow:格式）
            if line.startswith('#allow:'):
                return ('white', line)
            return ('white', line)

        # 黑名单规则（AdGuard过滤规则）
        if self.regex.BLACK_HOSTS.match(line):
            # Hosts格式转换为纯域名（AdGuard直接支持域名拦截）
            return ('black', self.regex.BLACK_HOSTS.match(line).group(2))
        if (self.regex.BLACK_DOMAIN.match(line) or 
            self.regex.BLACK_ADBLOCK.match(line) or 
            self.regex.BLACK_CUSTOM.match(line)):
            return ('black', line)

        # 未匹配的规则
        return ('unsupported', '')


if __name__ == '__main__':
    try:
        splitter = AdGuardSplitter()
        splitter.run()
    except Exception as e:
        logger.critical(f"运行失败：{str(e)}", exc_info=True)
        sys.exit(1)
