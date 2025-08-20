#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adblock Plus规则黑白名单分离器（GitHub Actions优化版）
支持高性能并行处理与精准语法识别
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
    """GitHub环境变量适配的配置参数"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")  # GitHub工作区根目录
    RUNNER_TEMP = os.getenv("RUNNER_TEMP", os.getenv("TEMP_DIR", "tmp"))  # Runner临时目录
    
    # 输入/输出路径配置
    INPUT_DIR = Path(os.getenv("INPUT_DIR", Path(GITHUB_WORKSPACE) / "tmp" if GITHUB_WORKSPACE else "tmp"))
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", GITHUB_WORKSPACE if GITHUB_WORKSPACE else "."))
    
    # 输出文件路径
    OUTPUT_BLACK = OUTPUT_DIR / "adblock_adp.txt"
    OUTPUT_WHITE = OUTPUT_DIR / "allow_adp.txt"
    
    # 临时处理目录
    TEMP_DIR = Path(RUNNER_TEMP) / "adblock_processing"
    
    # 并行处理配置
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (4, 253)  # 域名长度范围（最小，最大）


# ============== 预编译正则 ==============
class RegexPatterns:
    """预编译正则表达式集合"""
    # 标准Adblock Plus规则
    BLACK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    WHITE_DOMAIN = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    
    # 元素隐藏规则
    ELEMENT_HIDE = re.compile(r'^[a-z0-9-\.]+##[a-z0-9.#_:]+$')
    
    # 通配符规则
    WILDCARD = re.compile(r'^[\*\$]?[a-z0-9\.\-]+\$$[a-z0-9\,\-]*$', re.IGNORECASE)
    
    # 正则表达式规则
    REGEX_RULE = re.compile(r'^/(?:[^/\$|\\.|$(?:\^[0-9a-fA-F]?[^$]*$|[^$]+$)*)+/[a-z0-9\,\$\-]*$', re.IGNORECASE)
    
    # Hosts规则转换
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    
    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    UNSUPPORTED = re.compile(r'##\+js$|\$csp=|\$redirect=')


# ============== 日志配置 ==============
def setup_logger():
    """GitHub Actions兼容的日志系统"""
    logger = logging.getLogger('AdblockSplitter')
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


# ============== 核心处理类 ==============
class AdblockPlusSplitter:
    def __init__(self):
        """初始化工作目录和缓存"""
        # 创建必要目录
        for dir_path in [Config.TEMP_DIR, Config.INPUT_DIR, Config.OUTPUT_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(dir_path, 0o755)

        # 清理旧输出文件
        for f in [Config.OUTPUT_BLACK, Config.OUTPUT_WHITE]:
            if f.exists():
                f.unlink()

        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        """主流程：黑白名单分离处理"""
        start_time = time.time()
        logger.info("===== Adblock Plus黑白名单分离器 =====")
        logger.info(f"输入目录: {Config.INPUT_DIR}")
        logger.info(f"输出黑名单: {Config.OUTPUT_BLACK}")
        logger.info(f"输出白名单: {Config.OUTPUT_WHITE}")

        input_files = self._discover_input_files()
        if not input_files:
            logger.error(f"未找到输入文件（路径：{Config.INPUT_DIR}）")
            return

        # 全局去重缓存
        black_cache, white_cache = set(), set()
        total_stats = {'black': 0, 'white': 0, 'filtered': 0, 'unsupported': 0}

        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    (black_rules, white_rules), stats = future.result()
                    new_black = [r for r in black_rules if r not in black_cache]
                    new_white = [r for r in white_rules if r not in white_cache]
                    black_cache.update(new_black)
                    white_cache.update(new_white)
                    
                    total_stats['black'] += len(new_black)
                    total_stats['white'] += len(new_white)
                    total_stats['filtered'] += stats['filtered']
                    total_stats['unsupported'] += stats['unsupported']
                    
                    logger.info(f"处理 {file_path.name}："
                                f"新增黑名单{len(new_black)}条，白名单{len(new_white)}条")
                except Exception as e:
                    logger.error(f"处理{file_path.name}失败：{str(e)}")

        # 写入最终结果
        self._write_output(black_cache, white_cache)

        # GitHub Actions输出
        if os.getenv('GITHUB_ACTIONS') == 'true':
            self._github_actions_output(total_stats)

        logger.info("\n处理完成：")
        logger.info(f"黑名单规则：{total_stats['black']}条（保存至 {Config.OUTPUT_BLACK}）")
        logger.info(f"白名单规则：{total_stats['white']}条（保存至 {Config.OUTPUT_WHITE}）")
        logger.info(f"过滤无效规则：{total_stats['filtered']}条，不支持规则：{total_stats['unsupported']}条")
        logger.info(f"耗时：{time.time()-start_time:.2f}秒")

    def _discover_input_files(self) -> List[Path]:
        """发现输入文件"""
        input_files = []
        for pattern in ["*.txt", "*.list"]:
            input_files.extend([Path(p) for p in glob.glob(str(Config.INPUT_DIR / pattern))])
        return input_files

    def _process_file(self, file_path: Path) -> Tuple[Tuple[List[str], List[str]], Dict]:
        """处理单个文件"""
        black_rules, white_rules = [], []
        stats = {'filtered': 0, 'unsupported': 0}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    rule_type, rule = self._classify_rule(line)
                    if rule_type == 'black' and rule not in black_rules:
                        black_rules.append(rule)
                    elif rule_type == 'white' and rule not in white_rules:
                        white_rules.append(rule)
                    elif rule_type == 'filtered':
                        stats['filtered'] += 1
                    else:
                        stats['unsupported'] += 1
        except Exception as e:
            logger.warning(f"读取{file_path.name}出错：{str(e)}")

        return (black_rules, white_rules), stats

    def _classify_rule(self, line: str) -> Tuple[str, str]:
        """规则分类器"""
        # 快速过滤
        if self.regex.COMMENT.match(line) or not (self.len_min <= len(line) <= self.len_max):
            return ('filtered', '')
        if self.regex.UNSUPPORTED.search(line):
            return ('unsupported', '')

        # 白名单规则
        if self.regex.WHITE_DOMAIN.match(line):
            return ('white', line)
        if self.regex.ELEMENT_HIDE.match(line) and line.startswith('#@#'):
            return ('white', line)
        if self.regex.WILDCARD.match(line) and line.startswith('@@'):
            return ('white', line)

        # 黑名单规则
        if self.regex.BLACK_DOMAIN.match(line):
            return ('black', line)
        if self.regex.ELEMENT_HIDE.match(line) and not line.startswith('#@#'):
            return ('black', line)
        if self.regex.WILDCARD.match(line) and not line.startswith('@@'):
            return ('black', line)
        if self.regex.REGEX_RULE.match(line) and not line.startswith('@@'):
            return ('black', line)

        # Hosts规则转换
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            return ('black', f'||{hosts_match.group(2)}^')

        return ('unsupported', '')

    def _write_output(self, black_rules: Set[str], white_rules: Set[str]):
        """写入输出文件"""
        with open(Config.OUTPUT_BLACK, 'w', encoding='utf-8') as f:
            f.write('\n'.join(black_rules) + '\n')
        with open(Config.OUTPUT_WHITE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(white_rules) + '\n')

    def _github_actions_output(self, stats: Dict):
        """GitHub Actions输出"""
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output and os.getenv('GITHUB_ACTIONS') == 'true':
            with open(github_output, 'a', encoding='utf-8') as f:
                f.write(f"blacklist_path={Config.OUTPUT_BLACK}\n")
                f.write(f"whitelist_path={Config.OUTPUT_WHITE}\n")
                f.write(f"blacklist_count={stats['black']}\n")
                f.write(f"whitelist_count={stats['white']}\n")


if __name__ == '__main__':
    try:
        splitter = AdblockPlusSplitter()
        splitter.run()
    except Exception as e:
        logger.critical(f"运行失败：{str(e)}", exc_info=True)
        sys.exit(1)
