#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adblock规则合并去重工具（GitHub Actions适配版）
功能：处理下载脚本生成的临时规则文件，合并去重为纯净Adblock规则，适配GitHub工作流
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


# ============== 配置集中管理（与下载脚本对齐） ==============
class Config:
    """规则处理配置参数（与下载脚本共享环境变量，确保路径一致）"""
    # 路径配置（优先从GitHub环境变量获取，兼容本地运行）
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 与下载脚本共享临时目录
    OUTPUT_DIR = BASE_DIR / os.getenv('OUTPUT_DIR', 'output')  # 输出目录（GitHub Actions产物目录）
    OUTPUT_FILE = OUTPUT_DIR / "adblock_merged.txt"  # 最终输出文件

    # 处理参数（适配GitHub Runner资源）
    MAX_WORKERS = min(os.cpu_count() or 4, 4)  # GitHub Runner通常为2-4核，限制并行数
    RULE_LEN_RANGE = (3, 4096)  # 规则长度过滤范围（最小，最大）
    PRESERVE_HEADERS = True  # 保留Adblock文件头（如[Adblock Plus 3.0]）
    MAX_FILESIZE_MB = 50  # 单个文件最大处理大小（MB）
    INPUT_PATTERNS = ["*.txt", "*.list"]  # 输入文件匹配模式（与下载脚本输出格式对齐）


# ============== 预编译正则 ==============
class RegexPatterns:
    """Adblock核心语法及可转换规则的正则"""
    # Adblock原生规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')  # 域名规则（||example.com 或 ||example.com^）
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)\^?$')  # 白名单规则（@@||example.com^）
    ADBLOCK_ELEMENT = re.compile(r'^[\w.-]+##.+$')  # 元素隐藏（example.com##.ad）
    ADBLOCK_ELEMENT_EXCEPT = re.compile(r'^[\w.-]+#@#+$')  # 元素白名单（example.com#@#.ad）
    ADBLOCK_WILDCARD = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)  # 通配符（*example*）
    ADBLOCK_REGEX = re.compile(r'^/.*/$')  # 正则规则（/^https?:\/\//）
    ADBLOCK_HEADER = re.compile(r'^\[Adblock.*\]$')  # 文件头（[Adblock Plus 3.0]）

    # 可转换为Adblock的规则（与下载脚本内容对齐）
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # Hosts规则
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a-z]{2,}$')  # 纯域名（Pi-hole格式，如example.com）

    # 过滤项
    COMMENT = re.compile(r'^[!#]')  # 注释行（! 或 # 开头）
    EMPTY_LINE = re.compile(r'^\s*$')  # 空行


# ============== 日志配置（适配GitHub Actions） ==============
def setup_logger():
    logger = logging.getLogger('AdblockMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    # 适配GitHub Actions日志格式（无时间戳，便于Actions识别）
    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ============== GitHub Actions工具函数 ==============
def gh_group(name: str):
    """GitHub Actions分组显示（与下载脚本保持一致）"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    """结束GitHub Actions分组"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


# ============== 工具函数 ==============
def check_file_size(file_path: Path) -> bool:
    """检查文件大小是否超过限制（适配GitHub Runner存储）"""
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > Config.MAX_FILESIZE_MB:
            logger.warning(f"跳过大文件 {file_path.name}（{size_mb:.1f}MB > 限制{Config.MAX_FILESIZE_MB}MB）")
            return False
        return True
    except Exception as e:
        logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
        return False


# ============== 规则处理核心 ==============
class AdblockMerger:
    def __init__(self):
        # 确保目录存在（与下载脚本路径对齐）
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        """主流程：处理所有规则文件，合并去重后输出（适配GitHub工作流）"""
        start_time = time.time()
        gh_group("===== Adblock规则合并去重工具启动 =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出文件: {Config.OUTPUT_FILE}")

        # 获取所有输入文件（与下载脚本输出的临时文件匹配）
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("未找到任何输入文件（可能下载脚本失败），退出")
            gh_endgroup()
            return

        logger.info(f"发现{len(input_files)}个输入文件，开始处理...")

        # 并行处理文件（适配GitHub Runner CPU核心数）
        all_rules: List[str] = []
        global_cache: Set[str] = set()
        total_stats = self._empty_stats()

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
                    logger.info(f"处理完成 {file.name}：有效规则{stats['valid']}条，过滤{stats['filtered'] + stats['unsupported']}条")
                except Exception as e:
                    logger.error(f"处理文件{file.name}失败: {str(e)}")

        # 写入最终结果（输出到GitHub Actions产物目录）
        self._write_output(all_rules)

        # 输出汇总信息（适配GitHub Actions日志展示）
        elapsed = time.time() - start_time
        logger.info("\n===== 处理完成 =====")
        logger.info(f"总处理文件: {len(input_files)}个")
        logger.info(f"总规则数: {total_stats['total']}条")
        logger.info(f"有效规则数（去重后）: {len(all_rules)}条")
        logger.info(f"过滤规则数: {total_stats['filtered'] + total_stats['unsupported']}条")
        logger.info(f"耗时: {elapsed:.2f}秒")
        gh_endgroup()

        # 若在GitHub Actions中，输出产物路径（供后续步骤使用）
        if os.getenv('GITHUB_ACTIONS') == 'true':
            logger.info(f"::set-output name=merged_file::{Config.OUTPUT_FILE}")

    def _process_file(self, file_path: Path) -> Tuple[List[str], Dict]:
        """处理单个文件，返回有效规则和统计信息"""
        if not check_file_size(file_path):
            return [], self._empty_stats()

        stats = self._empty_stats()
        local_rules: List[str] = []
        local_cache: Set[str] = set()  # 单文件内去重

        try:
            # 兼容不同编码（与下载脚本的编码处理对齐）
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
        """处理单行规则，返回标准化后的Adblock规则（或None）"""
        stats['total'] += 1

        # 过滤空行
        if self.regex.EMPTY_LINE.match(line):
            stats['filtered'] += 1
            return None

        # 处理文件头（保留）
        if self.regex.ADBLOCK_HEADER.match(line) and Config.PRESERVE_HEADERS:
            if line not in local_cache:
                local_cache.add(line)
                stats['valid'] += 1
                return line
            stats['filtered'] += 1  # 重复文件头过滤
            return None

        # 过滤注释（非文件头的注释行）
        if self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None

        # 转换为Adblock格式
        adblock_rule = self._to_adblock(line)
        if not adblock_rule:
            stats['unsupported'] += 1
            return None

        # 单文件内去重
        if adblock_rule in local_cache:
            stats['filtered'] += 1
            return None

        local_cache.add(adblock_rule)
        stats['valid'] += 1
        return adblock_rule

    def _to_adblock(self, line: str) -> str:
        """将规则转换为Adblock标准格式（与下载脚本内容匹配）"""
        # 1. 转换Hosts规则（0.0.0.0 example.com → ||example.com^）
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            return f"||{domain}^"

        # 2. 转换纯域名（example.com → ||example.com^）
        if self.regex.PLAIN_DOMAIN.match(line):
            return f"||{line}^"

        # 3. 识别Adblock原生规则（直接返回）
        if (self.regex.ADBLOCK_DOMAIN.match(line) or
            self.regex.ADBLOCK_WHITELIST.match(line) or
            self.regex.ADBLOCK_ELEMENT.match(line) or
            self.regex.ADBLOCK_ELEMENT_EXCEPT.match(line) or
            self.regex.ADBLOCK_WILDCARD.match(line) or
            self.regex.ADBLOCK_REGEX.match(line)):
            return line

        # 无法转换的规则（由后续脚本处理）
        return None

    def _write_output(self, rules: List[str]):
        """写入合并后的规则到输出文件（GitHub Actions产物目录）"""
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')
        logger.info(f"已写入{len(rules)}条规则到 {Config.OUTPUT_FILE}")

    # ============== 统计辅助方法 ==============
    @staticmethod
    def _empty_stats() -> Dict:
        return {'total': 0, 'valid': 0, 'filtered': 0, 'unsupported': 0}

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        for key in total:
            total[key] += new[key]
        return total


# ============== 主入口 ==============
if __name__ == '__main__':
    try:
        merger = AdblockMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"工具运行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))  # GitHub环境简化错误输出
        sys.exit(1)
