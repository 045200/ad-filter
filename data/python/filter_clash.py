#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Clash/Mihomo规则转换工具（输出.yaml规则集，适配GitHub环境）"""

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
    # 环境变量适配（同之前）
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    RUNNER_TEMP = os.getenv("RUNNER_TEMP", os.getenv("TEMP_DIR", "tmp"))
    INPUT_DIR = os.getenv("INPUT_DIR", f"{GITHUB_WORKSPACE}/input" if GITHUB_WORKSPACE else "input")
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", f"{GITHUB_WORKSPACE}/output" if GITHUB_WORKSPACE else "output")

    # 输出文件改为.yaml（Clash规则集格式）
    OUTPUT_BLOCK = Path(OUTPUT_DIR) / "clash_block.yaml"  # 拦截规则集
    OUTPUT_ALLOW = Path(OUTPUT_DIR) / "clash_allow.yaml"  # 放行规则集
    TEMP_DIR = Path(RUNNER_TEMP) / "clash_processing"

    MAX_WORKERS = int(os.getenv("MAX_WORKERS", str(min(os.cpu_count() or 4, 4))))
    RULE_LEN_RANGE = (3, 4096)
    INPUT_PATTERNS = os.getenv("INPUT_PATTERNS", "*.txt,*.list").split(",")


class RegexPatterns:
    # 规则匹配正则（同之前）
    BLOCK_ADBLOCK = re.compile(r'^\|\|([\w.-]+)\^?$')
    BLOCK_HOSTS = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    BLOCK_WILDCARD = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)
    BLOCK_REGEX = re.compile(r'^/.*/$')
    BLOCK_OPTIONS = re.compile(r'^[\w.-]+\$[\w,-]+$')

    ALLOW_ADBLOCK = re.compile(r'^@@\|\|([\w.-]+)\^?$')
    ALLOW_OPTIONS = re.compile(r'^@@[\w.-]+\$[\w,-]+$')

    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a.[]{2,}$')

    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    UNSUPPORTED = re.compile(r'##\+js\(|\$csp=|\$redirect=')


def setup_logger():
    """适配GitHub Actions日志格式"""
    logger = logging.getLogger('ClashYamlConverter')
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


class ClashYamlConverter:
    def __init__(self):
        # 目录初始化（同之前）
        for dir_path in [Config.TEMP_DIR, Path(Config.INPUT_DIR), Path(Config.OUTPUT_DIR)]:
            dir_path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(dir_path, 0o755)

        # 清理旧文件
        for f in [Config.OUTPUT_BLOCK, Config.OUTPUT_ALLOW]:
            if f.exists():
                f.unlink()

        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        logger.info("===== Clash/Mihomo .yaml规则集转换（GitHub适配） =====")

        # 收集输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Path(Config.INPUT_DIR) / pattern))])

        if not input_files:
            logger.error(f"未在输入目录 {Config.INPUT_DIR} 找到文件（格式：{Config.INPUT_PATTERNS}）")
            return

        # 全局去重缓存
        block_cache: Set[str] = set()
        allow_cache: Set[str] = set()
        total_stats = {'block': 0, 'allow': 0, 'filtered': 0, 'unsupported': 0}

        # 并发处理文件
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file = futures[future]
                try:
                    (block_rules, allow_rules), stats = future.result()
                    new_block = [r for r in block_rules if r not in block_cache]
                    new_allow = [r for r in allow_rules if r not in allow_cache]
                    block_cache.update(new_block)
                    allow_cache.update(new_allow)
                    total_stats['block'] += len(new_block)
                    total_stats['allow'] += len(new_allow)
                    total_stats['filtered'] += stats['filtered']
                    total_stats['unsupported'] += stats['unsupported']
                    logger.info(f"处理 {file.name}：新增拦截{len(new_block)}条，放行{len(new_allow)}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败：{str(e)}")

        # 写入.yaml规则集（核心修改：添加Clash规则集格式）
        self._write_yaml(Config.OUTPUT_BLOCK, block_cache)
        self._write_yaml(Config.OUTPUT_ALLOW, allow_cache)

        # GitHub Actions输出参数
        print(f"::set-output name=block_path::{Config.OUTPUT_BLOCK}")
        print(f"::set-output name=allow_path::{Config.OUTPUT_ALLOW}")
        print(f"::set-output name=block_count::{total_stats['block']}")
        print(f"::set-output name=allow_count::{total_stats['allow']}")

        # 总结日志
        logger.info(f"\n处理完成：\n拦截规则集：{total_stats['block']}条\n放行规则集：{total_stats['allow']}条")
        logger.info(f"过滤无效规则：{total_stats['filtered']}条，不支持规则：{total_stats['unsupported']}条")
        logger.info(f"耗时：{time.time() - start_time:.2f}秒")

    def _process_file(self, file_path: Path) -> Tuple[Tuple[List[str], List[str]], Dict]:
        """处理单个文件（逻辑同之前）"""
        block_rules: List[str] = []
        allow_rules: List[str] = []
        stats = {'filtered': 0, 'unsupported': 0}
        file_block_cache: Set[str] = set()
        file_allow_cache: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rule_type, clash_rule = self._convert_rule(line)
                    if rule_type == 'block' and clash_rule not in file_block_cache:
                        file_block_cache.add(clash_rule)
                        block_rules.append(clash_rule)
                    elif rule_type == 'allow' and clash_rule not in file_allow_cache:
                        file_allow_cache.add(clash_rule)
                        allow_rules.append(clash_rule)
                    elif rule_type == 'filtered':
                        stats['filtered'] += 1
                    else:
                        stats['unsupported'] += 1
        except Exception as e:
            logger.warning(f"读取{file_path.name}出错：{str(e)}")

        return (block_rules, allow_rules), stats

    def _convert_rule(self, line: str) -> Tuple[str, str]:
        """转换规则为Clash格式（逻辑同之前）"""
        if self.regex.COMMENT.match(line) or not (self.len_min <= len(line) <= self.len_max):
            return ('filtered', '')
        if self.regex.UNSUPPORTED.search(line):
            return ('unsupported', '')

        # 放行规则（DIRECT）
        if self.regex.ALLOW_ADBLOCK.match(line):
            domain = self.regex.ALLOW_ADBLOCK.match(line).group(1)
            return ('allow', f"DOMAIN-SUFFIX,{domain},DIRECT")
        if self.regex.ALLOW_OPTIONS.match(line):
            domain = re.sub(r'^@@([\w.-]+)\$.*$', r'\1', line)
            return ('allow', f"DOMAIN-SUFFIX,{domain},DIRECT")

        # 拦截规则（REJECT）
        if self.regex.BLOCK_ADBLOCK.match(line):
            domain = self.regex.BLOCK_ADBLOCK.match(line).group(1)
            return ('block', f"DOMAIN-SUFFIX,{domain},REJECT,no-resolve")
        if self.regex.BLOCK_HOSTS.match(line):
            domain = self.regex.BLOCK_HOSTS.match(line).group(2)
            return ('block', f"DOMAIN,{domain},REJECT,no-resolve")
        if self.regex.BLOCK_WILDCARD.match(line):
            if line.startswith('*.'):
                suffix = line[2:]
                return ('block', f"DOMAIN-SUFFIX,{suffix},REJECT")
            elif '*' in line:
                keyword = line.replace('*', '')
                return ('block', f"DOMAIN-KEYWORD,{keyword},REJECT")
        if self.regex.BLOCK_REGEX.match(line):
            pattern = line.strip('/')
            return ('block', f"URL-REGEX,{pattern},REJECT")
        if self.regex.BLOCK_OPTIONS.match(line):
            domain = re.sub(r'^([\w.-]+)\$.*$', r'\1', line)
            return ('block', f"DOMAIN-SUFFIX,{domain},REJECT")
        if self.regex.PLAIN_DOMAIN.match(line):
            return ('block', f"DOMAIN-SUFFIX,{line},REJECT")

        return ('unsupported', '')

    def _write_yaml(self, file_path: Path, rules: Set[str]):
        """写入.yaml规则集（核心调整：符合Clash Rule Set格式）"""
        with open(file_path, 'w', encoding='utf-8') as f:
            # Clash规则集必须包含payload字段，规则列表缩进2空格
            f.write("payload:\n")
            for rule in rules:
                f.write(f"  - {rule}\n")  # 每条规则前加"- "和缩进


if __name__ == '__main__':
    try:
        converter = ClashYamlConverter()
        converter.run()
    except Exception as e:
        logger.critical(f"运行失败：{str(e)}", exc_info=True)
        sys.exit(1)
