#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
通用广告规则处理器 - 优化版
针对 GitHub Actions 4核16GB环境优化
支持多格式规则语法，特殊规则按来源归类（白名单/黑名单）
最终仅输出adblock和allow初筛文件
"""

import os
import sys
import glob
import re
import logging
import time
from pathlib import Path
import ipaddress
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
from typing import Tuple, List, Set, Dict

# ============== 环境变量与配置 ==============
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')

# 规则文件配置
BLOCK_PATTERN = 'adblock*.txt'
ALLOW_PATTERN = 'allow*.txt'
OUTPUT_BLOCK = TEMP_DIR / 'adblock_intermediate.txt'
OUTPUT_ALLOW = TEMP_DIR / 'allow_intermediate.txt'

# 处理参数（4核16G环境优化）
MAX_WORKERS = min(mp.cpu_count(), 4)
MAX_RULE_LENGTH = 4096
MIN_RULE_LENGTH = 3
PRESERVE_HEADERS = True
MAX_FILESIZE_MB = 50
CHUNK_SIZE = 10000

# ============== 预编译正则表达式 ==============
# 白名单规则标记（Adblock风格）
WHITELIST_MARKER = re.compile(r'^@@')

# 基础规则模式
HOSTS_PATTERN = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
ADBLOCK_DOMAIN_PATTERN = re.compile(r'^\|\|([\w.-]+)\^?$')  # 标准域名拦截
ADBLOCK_WILDCARD_PATTERN = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)  # 通配符规则
ADBLOCK_REGEX_PATTERN = re.compile(r'^/.*/$')  # 正则表达式规则

# Surge规则模式
SURGE_DOMAIN_PATTERN = re.compile(r'^DOMAIN,([\w.-]+),.*$')
SURGE_SUFFIX_PATTERN = re.compile(r'^DOMAIN-SUFFIX,([\w.-]+),.*$')
SURGE_KEYWORD_PATTERN = re.compile(r'^DOMAIN-KEYWORD,([\w.-]+),.*$')
SURGE_CIDR_PATTERN = re.compile(r'^IP-CIDR,([\w./]+),.*$')

# 元素隐藏规则
ELEMENT_HIDING_PATTERN = re.compile(r'^.*##.*$')
ELEMENT_EXCEPTION_PATTERN = re.compile(r'^.*#@#.*$')  # 元素隐藏白名单

# 注释和文件头
COMMENT_PATTERN = re.compile(r'^[!#]|^\[Adblock')
EMPTY_LINE_PATTERN = re.compile(r'^\s*$')

# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger('RuleProcessor')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')

    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()

# ============== GitHub Actions支持 ==============
def gh_group(name: str):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")

# ============== 规则统计工具类 ==============
class RuleStats:
    """记录单文件处理统计信息"""
    def __init__(self):
        self.total = 0          # 总行数
        self.comments = 0       # 注释行数
        self.empty = 0          # 空行数
        self.length_filtered = 0  # 长度过滤
        self.unsupported = 0    # 不支持的语法
        self.valid = 0          # 有效通用规则
        self.special = 0        # 特殊规则

    def __str__(self) -> str:
        return (f"总行={self.total}, 注释={self.comments}, 空行={self.empty}, "
                f"长度过滤={self.length_filtered}, 不支持={self.unsupported}, "
                f"有效规则={self.valid}, 特殊规则={self.special}")

# ============== 主处理器类 ==============
class RuleProcessor:
    def __init__(self):
        # 确保临时目录存在
        TEMP_DIR.mkdir(parents=True, exist_ok=True)

    def run(self):
        """主执行流程"""
        gh_group("规则处理器启动")
        start_time = time.time()
        logger.info(f"工作目录: {BASE_DIR}")
        logger.info(f"输出文件: 黑名单={OUTPUT_BLOCK}, 白名单={OUTPUT_ALLOW}")
        gh_endgroup()

        # 并行处理黑白名单
        with ProcessPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self._process_rule_type, 'allow'),
                executor.submit(self._process_rule_type, 'block')
            ]

            for future in as_completed(futures):
                try:
                    rule_type, total_stats = future.result()
                    logger.info(f"\n{rule_type}规则汇总统计: {total_stats}")
                except Exception as e:
                    logger.error(f"处理{rule_type}规则失败: {str(e)}", exc_info=True)

        elapsed = time.time() - start_time
        logger.info(f"\n所有处理完成! 耗时 {elapsed:.2f}秒")
        logger.info(f"黑名单初筛结果: {OUTPUT_BLOCK.stat().st_size//1024}KB")
        logger.info(f"白名单初筛结果: {OUTPUT_ALLOW.stat().st_size//1024}KB")

    def _process_rule_type(self, rule_type: str) -> Tuple[str, RuleStats]:
        """处理指定类型（allow/block）的所有文件"""
        gh_group(f"开始处理{rule_type}规则")

        # 获取文件路径和输出文件
        pattern = ALLOW_PATTERN if rule_type == 'allow' else BLOCK_PATTERN
        file_paths = [Path(p) for p in glob.glob(str(TEMP_DIR / pattern))]
        output_file = OUTPUT_ALLOW if rule_type == 'allow' else OUTPUT_BLOCK

        if not file_paths:
            logger.warning(f"未找到匹配{pattern}的文件，创建空输出")
            output_file.write_text('')
            gh_endgroup()
            return (rule_type, RuleStats())

        logger.info(f"发现{len(file_paths)}个{rule_type}文件，启动并行处理")

        # 并行处理单个文件
        total_stats = RuleStats()
        all_rules: List[str] = []
        file_caches: List[Set[str]] = []  # 收集每个文件的去重缓存用于全局去重

        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._process_single_file, path, rule_type): path 
                for path in file_paths
            }

            for future in as_completed(futures):
                path = futures[future]
                try:
                    rules, cache, stats = future.result()
                    all_rules.extend(rules)
                    file_caches.append(cache)
                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {path.name}: {stats}")
                except Exception as e:
                    logger.error(f"处理文件{path.name}失败: {str(e)}")

        # 全局去重（跨文件去重）
        global_cache = set()
        for cache in file_caches:
            global_cache.update(cache)
        unique_rules = [rule for rule in all_rules if rule in global_cache]  # 保留首次出现的规则
        duplicate_count = len(all_rules) - len(unique_rules)
        if duplicate_count > 0:
            logger.info(f"全局去重: 移除{duplicate_count}条跨文件重复规则")

        # 写入最终结果
        output_file.write_text('\n'.join(unique_rules) + '\n')
        logger.info(f"{rule_type}规则处理完成，写入{len(unique_rules)}条规则到{output_file}")
        gh_endgroup()

        return (rule_type, total_stats)

    def _process_single_file(self, file_path: Path, rule_type: str) -> Tuple[List[str], Set[str], RuleStats]:
        """处理单个文件，返回规则、去重缓存和统计信息"""
        stats = RuleStats()
        local_cache: Set[str] = set()  # 本地去重缓存
        rules: List[str] = []          # 最终保留的规则（含通用+特殊）

        # 检查文件大小
        if not self._check_file_size(file_path):
            return ([], set(), stats)

        try:
            # 分块读取大文件
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                while True:
                    chunk = f.readlines(CHUNK_SIZE)
                    if not chunk:
                        break
                    for line in chunk:
                        line = line.strip()
                        stats.total += 1

                        # 处理空行
                        if EMPTY_LINE_PATTERN.match(line):
                            stats.empty += 1
                            continue

                        # 处理注释和文件头
                        if COMMENT_PATTERN.match(line):
                            stats.comments += 1
                            if PRESERVE_HEADERS:
                                self._add_rule(line, rules, local_cache, stats, is_special=True)
                            continue

                        # 长度过滤
                        if not (MIN_RULE_LENGTH <= len(line) <= MAX_RULE_LENGTH):
                            stats.length_filtered += 1
                            continue

                        # 规则标准化（区分通用/特殊规则）
                        normalized, is_special = self._normalize_rule(line, rule_type)
                        if normalized:
                            self._add_rule(normalized, rules, local_cache, stats, is_special)
                        else:
                            stats.unsupported += 1

        except Exception as e:
            logger.error(f"读取文件{file_path.name}出错: {str(e)}", exc_info=True)

        return (rules, local_cache, stats)

    def _add_rule(self, rule: str, rules_list: List[str], cache: Set[str], stats: RuleStats, is_special: bool):
        """添加规则到列表（含去重）"""
        if rule not in cache:
            cache.add(rule)
            rules_list.append(rule)
            if is_special:
                stats.special += 1
            else:
                stats.valid += 1

    @staticmethod
    def _merge_stats(total: RuleStats, new: RuleStats) -> RuleStats:
        """合并统计信息"""
        total.total += new.total
        total.comments += new.comments
        total.empty += new.empty
        total.length_filtered += new.length_filtered
        total.unsupported += new.unsupported
        total.valid += new.valid
        total.special += new.special
        return total

    @staticmethod
    @lru_cache(maxsize=100000)
    def _normalize_rule(line: str, rule_type: str) -> Tuple[str, bool]:
        """
        标准化规则，返回(标准化规则, 是否为特殊规则)
        特殊规则：无法标准化但符合语法的规则，按来源归类到allow/block
        """
        # 处理白名单标记（Adblock风格）
        is_whitelist_marker = WHITELIST_MARKER.match(line) is not None

        # 1. Hosts规则
        hosts_match = HOSTS_PATTERN.match(line)
        if hosts_match:
            return (hosts_match.group(2), False)  # 提取域名

        # 2. Adblock域名规则
        adblock_match = ADBLOCK_DOMAIN_PATTERN.match(line)
        if adblock_match:
            # 白名单规则（@@开头）应归到allow
            if is_whitelist_marker and rule_type == 'allow':
                return (line, False)  # 保留原始格式作为通用规则
            return (adblock_match.group(1), False)

        # 3. 元素隐藏规则（特殊规则，按来源归类）
        if ELEMENT_HIDING_PATTERN.match(line) or ELEMENT_EXCEPTION_PATTERN.match(line):
            return (line, True)

        # 4. Surge规则
        surge_domain = SURGE_DOMAIN_PATTERN.match(line)
        if surge_domain:
            return (surge_domain.group(1), False)

        surge_suffix = SURGE_SUFFIX_PATTERN.match(line)
        if surge_suffix:
            return (surge_suffix.group(1), False)

        surge_keyword = SURGE_KEYWORD_PATTERN.match(line)
        if surge_keyword:
            return (surge_keyword.group(1), False)

        # 5. IP/CIDR规则（通用规则）
        if RuleProcessor._is_valid_ip_or_cidr(line) or SURGE_CIDR_PATTERN.match(line):
            return (line, False)

        # 6. 通配符/正则规则（通用规则）
        if ADBLOCK_WILDCARD_PATTERN.match(line) or ADBLOCK_REGEX_PATTERN.match(line):
            return (line, False)

        # 7. 白名单特殊规则（仅allow保留）
        if is_whitelist_marker and rule_type == 'allow':
            return (line, True)

        # 未匹配到通用规则，但属于支持的特殊规则（按来源保留）
        return (line, True)

    @staticmethod
    @lru_cache(maxsize=10000)
    def _is_valid_ip_or_cidr(line: str) -> bool:
        """验证IP或CIDR格式"""
        try:
            ipaddress.ip_network(line, strict=False)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _check_file_size(file_path: Path) -> bool:
        """检查文件大小是否超过限制"""
        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > MAX_FILESIZE_MB:
                logger.warning(f"跳过大文件 {file_path.name} ({size_mb:.1f}MB > {MAX_FILESIZE_MB}MB)")
                return False
            return True
        except Exception as e:
            logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
            return False

# ============== 主流程 ==============
if __name__ == '__main__':
    try:
        processor = RuleProcessor()
        processor.run()
    except Exception as e:
        logger.critical(f"处理器崩溃: {str(e)}", exc_info=True)
        sys.exit(1)
