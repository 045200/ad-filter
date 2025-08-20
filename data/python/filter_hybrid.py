#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""支持混合语法的拦截器规则合并工具（Adblock Plus/UBO/AdGuard通用）"""

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
    """配置：适配支持混合语法的拦截器（Adblock Plus/UBO/AdGuard）"""
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    OUTPUT_DIR = BASE_DIR / os.getenv('OUTPUT_DIR', 'output')
    OUTPUT_FILE = OUTPUT_DIR / "adblock_hybrid.txt"  # 单一输出文件
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)  # 兼容长规则（如UBO的脚本拦截）
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    """混合语法规则正则（覆盖Adblock Plus/UBO/AdGuard通用及扩展语法）"""
    # 基础Adblock规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')  # 域名拦截：||domain.com^
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)\^?$')  # 域名白名单：@@||domain.com^
    ADBLOCK_ELEMENT = re.compile(r'^[\w.-]+##.+$')  # 元素隐藏：domain.com##.ad
    ADBLOCK_ELEMENT_EXCEPT = re.compile(r'^[\w.-]+#@#+$')  # 元素白名单：domain.com#@#.ad
    ADBLOCK_WILDCARD = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)  # 通配符：*adserver*
    ADBLOCK_REGEX = re.compile(r'^/.*/$')  # 正则规则：/^https?:\/\/ad/

    # 扩展语法（UBO/AdGuard支持）
    UBO_SCRIPT = re.compile(r'^##\+js\(.+\)$')  # UBO脚本拦截：##+js(abort-on-property-read.js)
    ADGUARD_CSP = re.compile(r'^[\w.-]+\$csp=.+$')  # AdGuard CSP规则：domain.com$csp=default-src 'self'
    ADGUARD_REDIRECT = re.compile(r'^[\w.-]+\$redirect=.+$')  # AdGuard重定向：domain.com$redirect=noop.txt

    # 可转换规则
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # Hosts规则
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a-z]{2,}$')  # 纯域名：domain.com

    # 过滤项
    COMMENT = re.compile(r'^[!#]')  # 注释行（! 或 # 开头）
    EMPTY_LINE = re.compile(r'^\s*$')  # 空行


def setup_logger():
    logger = logging.getLogger('HybridAdblockMerger')
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


class HybridAdblockMerger:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        # 清理原有输出文件（确保单一输出）
        if Config.OUTPUT_FILE.exists():
            Config.OUTPUT_FILE.unlink()
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        gh_group("===== 混合语法规则合并（Adblock Plus/UBO/AdGuard） =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出文件: {Config.OUTPUT_FILE}")

        # 获取输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        # 全局规则存储及去重
        all_rules: List[str] = []
        global_cache: Set[str] = set()
        total_stats = self._empty_stats()

        # 并行处理文件
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, file): file for file in input_files}
            
            for future in as_completed(futures):
                file = futures[future]
                try:
                    rules, stats = future.result()
                    # 全局去重（跨文件重复）
                    new_rules = [rule for rule in rules if rule not in global_cache]
                    all_rules.extend(new_rules)
                    global_cache.update(new_rules)
                    # 合并统计
                    total_stats = self._merge_stats(total_stats, stats)
                    logger.info(f"处理完成 {file.name}：有效规则{stats['valid']}条")
                except Exception as e:
                    logger.error(f"处理文件{file.name}失败: {str(e)}")

        # 写入单一纯净规则文件（无任何头信息，仅规则）
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(all_rules) + '\n')

        # 输出结果统计
        elapsed = time.time() - start_time
        logger.info(f"\n===== 处理完成 =====")
        logger.info(f"总处理文件: {len(input_files)}个")
        logger.info(f"总有效规则数（去重后）: {len(all_rules)}条")
        logger.info(f"过滤规则数: {total_stats['filtered'] + total_stats['unsupported']}条")
        logger.info(f"耗时: {elapsed:.2f}秒")
        gh_endgroup()

        # GitHub Actions输出产物路径
        if os.getenv('GITHUB_ACTIONS') == 'true':
            logger.info(f"::set-output name=hybrid_file::{Config.OUTPUT_FILE}")

    def _process_file(self, file_path: Path) -> Tuple[List[str], Dict]:
        """处理单个文件，返回有效规则和统计"""
        if not check_file_size(file_path):
            return [], self._empty_stats()

        stats = self._empty_stats()
        local_rules: List[str] = []
        local_cache: Set[str] = set()  # 单文件内去重

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    processed_rule = self._process_line(line, stats, local_cache)
                    if processed_rule:
                        local_rules.append(processed_rule)
        except Exception as e:
            logger.error(f"读取文件{file_path.name}出错: {str(e)}")

        return local_rules, stats

    def _process_line(self, line: str, stats: Dict, local_cache: Set[str]) -> str:
        """处理单行规则，保留混合语法兼容规则"""
        stats['total'] += 1

        # 过滤空行和注释
        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None

        # 转换/保留为混合语法兼容规则
        hybrid_rule = self._to_hybrid_rule(line)
        if not hybrid_rule:
            stats['unsupported'] += 1
            return None

        # 单文件内去重
        if hybrid_rule in local_cache:
            stats['filtered'] += 1
            return None

        local_cache.add(hybrid_rule)
        stats['valid'] += 1
        return hybrid_rule

    def _to_hybrid_rule(self, line: str) -> str:
        """转换为混合语法兼容规则（保留各工具通用及扩展语法）"""
        # 1. 保留UBO扩展语法（如脚本拦截）
        if self.regex.UBO_SCRIPT.match(line):
            return line

        # 2. 保留AdGuard扩展语法（如CSP、重定向）
        if self.regex.ADGUARD_CSP.match(line) or self.regex.ADGUARD_REDIRECT.match(line):
            return line

        # 3. 保留标准Adblock规则（Adblock Plus/UBO/AdGuard通用）
        if (self.regex.ADBLOCK_DOMAIN.match(line) or
            self.regex.ADBLOCK_WHITELIST.match(line) or
            self.regex.ADBLOCK_ELEMENT.match(line) or
            self.regex.ADBLOCK_ELEMENT_EXCEPT.match(line) or
            self.regex.ADBLOCK_WILDCARD.match(line) or
            self.regex.ADBLOCK_REGEX.match(line)):
            return line

        # 4. 转换Hosts规则为Adblock域名规则（通用格式）
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            return f"||{domain}^"

        # 5. 转换纯域名为Adblock域名规则（通用格式）
        if self.regex.PLAIN_DOMAIN.match(line):
            return f"||{line}^"

        # 不支持的规则（如其他工具特有语法）
        return None

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
        merger = HybridAdblockMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"工具运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
