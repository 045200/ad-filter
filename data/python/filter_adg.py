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
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    INPUT_DIR = Path(os.getenv("INPUT_DIR", Path(GITHUB_WORKSPACE) / "tmp" if GITHUB_WORKSPACE else "tmp"))
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", GITHUB_WORKSPACE if GITHUB_WORKSPACE else "."))
    OUTPUT_FILE = OUTPUT_DIR / "adblock_adg.txt"
    ALLOW_FILE = OUTPUT_DIR / "allow_adg.txt"
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["adblock_merged.txt"]


# ============== 预编译正则 ==============
class RegexPatterns:
    # 核心规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    ADBLOCK_ELEMENT = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}##.+$', re.IGNORECASE)
    ADBLOCK_ELEMENT_EXCEPT = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}#@#.+$', re.IGNORECASE)
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    ADGUARD_CSP = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\$csp=', re.IGNORECASE)
    ADGUARD_REDIRECT = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\$redirect=', re.IGNORECASE)
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')


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


# ============== 工具函数 ==============
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
        # 清理旧输出
        for f in [Config.OUTPUT_FILE, Config.ALLOW_FILE]:
            if f.exists():
                f.unlink()
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
            input_files.extend(Path(p) for p in glob.glob(str(Config.INPUT_DIR / pattern)))
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现 {len(input_files)} 个文件，开始处理...")

        all_rules, all_allows = [], []
        global_rule_cache, global_allow_cache = set(), set()
        total_stats = self._empty_stats()

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file = futures[future]
                try:
                    rules, allows, stats = future.result()
                    # 全局去重
                    new_rules = [r for r in rules if r not in global_rule_cache]
                    new_allows = [a for a in allows if a not in global_allow_cache]
                    all_rules.extend(new_rules)
                    all_allows.extend(new_allows)
                    global_rule_cache.update(new_rules)
                    global_allow_cache.update(new_allows)
                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效规则 {stats['valid']} 条")
                except Exception as e:
                    logger.error(f"处理 {file.name} 失败: {str(e)}")

        # 写出结果（无头部）
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(all_rules)) + '\n')
        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(all_allows)) + '\n')

        elapsed = time.time() - start_time
        logger.info(f"\n处理完成：总规则 {len(all_rules)} 条，白名单 {len(all_allows)} 条，耗时 {elapsed:.2f} 秒")
        gh_endgroup()

        # GitHub Actions 输出
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
        rules, allows = [], []
        rule_cache, allow_cache = set(), set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    rule, is_allow = self._process_line(line, stats)
                    if rule:
                        target_list = allows if is_allow else rules
                        cache = allow_cache if is_allow else rule_cache
                        if rule not in cache:
                            target_list.append(rule)
                            cache.add(rule)
        except Exception as e:
            logger.error(f"读取 {file_path.name} 出错: {str(e)}")

        return rules, allows, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        stats['total'] += 1
        if not line or self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None, False
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None, False

        rule, is_allow = self._to_adguard(line)
        if rule:
            stats['valid'] += 1
        else:
            stats['unsupported'] += 1
        return rule, is_allow

    def _to_adguard(self, line: str) -> Tuple[str, bool]:
        # 白名单
        if line.startswith('@@'):
            norm = line[2:]
            if self.regex.ADBLOCK_DOMAIN.match(norm) or \
               self.regex.ADBLOCK_ELEMENT_EXCEPT.match(norm):
                return norm, True
            return line, True

        # Hosts 转换
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                return f"||{domain}^", False

        # 纯域名
        if self.regex.PLAIN_DOMAIN.match(line) and self._is_valid_domain(line):
            return f"||{line}^", False

        # AdGuard 特有规则
        if self.regex.ADGUARD_CSP.match(line) or \
           self.regex.ADGUARD_REDIRECT.match(line) or \
           self.regex.ADBLOCK_ELEMENT.match(line) or \
           self.regex.ADBLOCK_DOMAIN.match(line):
            return line, False

        return None, False

    def _is_valid_domain(self, domain: str) -> bool:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$|^$?[a-f0-9:]+$?$', domain, re.IGNORECASE):
            return False
        if len(domain) < 4 or len(domain) > 253 or '..' in domain:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return False
        for p in parts:
            if not p or len(p) > 63 or not re.match(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$', p):
                return False
        return True

    @staticmethod
    def _empty_stats() -> Dict:
        return {'total': 0, 'valid': 0, 'filtered': 0, 'unsupported': 0}

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        return {k: total[k] + new[k] for k in total}


# ============== 主入口 ==============
if __name__ == '__main__':
    try:
        merger = AdGuardMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
