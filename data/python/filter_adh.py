#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard规则转换工具（无头部信息） - 优化版
"""

import os
import sys
import glob
import re
import logging
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, List, Set, Dict


# ============== 配置集中管理 ==============
class Config:
    """规则处理配置（适配GitHub Actions）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    INPUT_DIR = Path(os.getenv("INPUT_DIR", Path(GITHUB_WORKSPACE) / "tmp" if GITHUB_WORKSPACE else "tmp"))
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", GITHUB_WORKSPACE if GITHUB_WORKSPACE else "."))
    OUTPUT_FILE = OUTPUT_DIR / "adblock_adg.txt"
    ALLOW_FILE = OUTPUT_DIR / "allow_adg.txt"
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["adblock_merged.txt"]

    # 域名与格式验证
    VALID_DOMAIN_CHARS = re.compile(r'^[a-zA-Z0-9.-_*]+$')
    TOP_LEVEL_DOMAINS = re.compile(r'\.[a-zA-Z]{2,}$')


# ============== 预编译正则 ==============
class RegexPatterns:
    """预编译正则表达式，提升匹配性能"""
    # 核心规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|(\$[\w,-]+))?$')
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|(\$[\w,-]+))?$')

    # 元素隐藏
    ELEMENT_HIDE = re.compile(r'^([\w.-*]+)##(.+)$')
    ELEMENT_HIDE_EXCEPT = re.compile(r'^([\w.-*]+)#@#(.+)$')

    # Hosts规则
    HOSTS_IPV4 = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
    HOSTS_IPV6 = re.compile(r'^(::1)\s+([\w.-]+)$')

    # 域名与通配符
    PLAIN_DOMAIN = re.compile(r'^(\*\.|)([\w.-]+)\.[a-zA-Z]{2,}$')
    ADBLOCK_WILDCARD = re.compile(r'^\*([\w.-]+)\*$')
    ADBLOCK_PREFIX = re.compile(r'^([\w.-]+)\*$')
    ADBLOCK_SUFFIX = re.compile(r'^\*([\w.-]+)$')

    # AdGuard特有
    ADGUARD_CSP = re.compile(r'^[\w.-]+\$csp=.+$')
    ADGUARD_REDIRECT = re.compile(r'^[\w.-]+\$redirect=.+$')
    ADGUARD_MODIFIER = re.compile(r'^[\w.-]+\$[\w,-]+=.+$')

    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger('AdGuardMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '%(asctime)s [%(levelname)s] %(message)s'
    handler.setFormatter(logging.Formatter(fmt, datefmt='%H:%M:%S'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()


# ============== GitHub Actions 分组 ==============
def gh_group(name: str):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


# ============== 文件大小检查 ==============
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


# ============== 核心处理类 ==============
class AdGuardMerger:
    def __init__(self):
        Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self._cleanup_outputs()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def _cleanup_outputs(self):
        """清理旧输出文件"""
        for file in [Config.OUTPUT_FILE, Config.ALLOW_FILE]:
            if file.exists():
                file.unlink()

    def run(self):
        start_time = time.time()
        gh_group("===== AdGuard规则转换 =====")
        logger.info(f"输入目录: {Config.INPUT_DIR}")
        logger.info(f"输出规则: {Config.OUTPUT_FILE}")
        logger.info(f"输出白名单: {Config.ALLOW_FILE}")

        input_files = self._discover_input_files()
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现 {len(input_files)} 个文件，开始处理...")

        all_rules, all
