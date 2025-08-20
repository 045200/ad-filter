#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Clash/Mihomo规则转换工具（输出结构化.yaml规则集，适配GitHub环境）"""

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
    # 环境变量适配
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    RUNNER_TEMP = os.getenv("RUNNER_TEMP", os.getenv("TEMP_DIR", "tmp"))
    INPUT_DIR = os.getenv("INPUT_DIR", f"{GITHUB_WORKSPACE}/input" if GITHUB_WORKSPACE else "input")
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", f"{GITHUB_WORKSPACE}/output" if GITHUB_WORKSPACE else "output")

    # 输出文件（Clash规则集格式）
    OUTPUT_BLOCK = Path(OUTPUT_DIR) / "clash_adblock.yaml"  # 拦截规则集
    OUTPUT_ALLOW = Path(OUTPUT_DIR) / "clash_allow.yaml"    # 放行规则集
    TEMP_DIR = Path(RUNNER_TEMP) / "clash_processing"

    # 规则处理配置
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", str(min(os.cpu_count() or 4, 4))))
    RULE_LEN_RANGE = (3, 4096)  # 有效规则长度范围
    INPUT_PATTERNS = os.getenv("INPUT_PATTERNS", "adblock_merged.txt").split(",")
    SUPPORTED_RULE_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}  # 下游支持的规则类型


class RegexPatterns:
    # 规则匹配正则
    BLOCK_ADBLOCK = re.compile(r'^\|\|([\w.-]+)\^?$')          # AdBlock拦截规则（||example.com^）
    BLOCK_HOSTS = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # Hosts拦截规则
    BLOCK_WILDCARD = re.compile(r'^[\*a-z0-9\-\.]+$', re.IGNORECASE)  # 通配符规则（*.example.com）
    BLOCK_REGEX = re.compile(r'^/.*/$')                        # 正则拦截规则（/example/）
    BLOCK_OPTIONS = re.compile(r'^[\w.-]+\$[\w,-]+$')          # 带选项的拦截规则（example.com$third-party）

    ALLOW_ADBLOCK = re.compile(r'^@@\|\|([\w.-]+)\^?$')        # AdBlock放行规则（@@||example.com^）
    ALLOW_OPTIONS = re.compile(r'^@@[\w.-]+\$[\w,-]+$')        # 带选项的放行规则（@@example.com$domain=test.com）

    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a-zA-Z]{2,}$')      # 纯域名（example.com）

    COMMENT = re.compile(r'^[!#]')                             # 注释行（!或#开头）
    EMPTY_LINE = re.compile(r'^\s*$')                          # 空行
    UNSUPPORTED = re.compile(r'##\+js\(|\$csp=|\$redirect=')   # 不支持的脚本/跳转规则


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
        # 初始化目录
        for dir_path in [Config.TEMP_DIR, Path(Config.INPUT_DIR), Path(Config.OUTPUT_DIR)]:
            dir_path.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(dir_path, 0o755)

        # 清理旧输出文件
        for f in [Config.OUTPUT_BLOCK, Config.OUTPUT_ALLOW]:
            if f.exists():
                f.unlink()

        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        logger.info("===== Clash/Mihomo 结构化规则集生成工具 =====")

        # 收集输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Path(Config.INPUT_DIR) / pattern))])

        if not input_files:
            logger.error(f"未在输入目录 {Config.INPUT_DIR} 找到文件（格式：{Config.INPUT_PATTERNS}）")
            return

        # 全局去重缓存（基于规则类型+域名，避免误去重）
        block_cache: Set[Tuple[str, str]] = set()  # (rule_type, domain)
        allow_cache: Set[Tuple[str, str]] = set()
        total_stats = {'block': 0, 'allow': 0, 'filtered': 0, 'unsupported': 0}

        # 并发处理文件
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, f): f for f in input_files}
            for future in as_completed(futures):
                file = futures[future]
                try:
                    (block_rules, allow_rules), stats = future.result()
                    # 过滤全局重复规则
                    new_block = []
                    for rule in block_rules:
                        rule_key = (rule['type'], rule['value'])
                        if rule_key not in block_cache:
                            block_cache.add(rule_key)
                            new_block.append(rule)
                    new_allow = []
                    for rule in allow_rules:
                        rule_key = (rule['type'], rule['value'])
                        if rule_key not in allow_cache:
                            allow_cache.add(rule_key)
                            new_allow.append(rule)
                    # 更新统计
                    total_stats['block'] += len(new_block)
                    total_stats['allow'] += len(new_allow)
                    total_stats['filtered'] += stats['filtered']
                    total_stats['unsupported'] += stats['unsupported']
                    logger.info(f"处理 {file.name}：新增拦截{len(new_block)}条，放行{len(new_allow)}条")
                except Exception as e:
                    logger.error(f"处理{file.name}失败：{str(e)}")

        # 写入结构化YAML规则集
        self._write_yaml(Config.OUTPUT_BLOCK, new_block, "ad-filter", "REJECT")
        self._write_yaml(Config.OUTPUT_ALLOW, new_allow, "allow-list", "DIRECT")

        # 替换已弃用的set-output，使用GITHUB_OUTPUT环境文件
        if os.getenv('GITHUB_ACTIONS') == 'true':
            github_output = os.getenv('GITHUB_OUTPUT')
            if github_output:
                with open(github_output, 'a', encoding='utf-8') as f:
                    f.write(f"block_path={Config.OUTPUT_BLOCK}\n")
                    f.write(f"allow_path={Config.OUTPUT_ALLOW}\n")
                    f.write(f"block_count={total_stats['block']}\n")
                    f.write(f"allow_count={total_stats['allow']}\n")

        # 总结日志
        logger.info(f"\n处理完成：\n拦截规则集：{total_stats['block']}条\n放行规则集：{total_stats['allow']}条")
        logger.info(f"过滤无效规则：{total_stats['filtered']}条，不支持规则：{total_stats['unsupported']}条")
        logger.info(f"耗时：{time.time() - start_time:.2f}秒")

    def _process_file(self, file_path: Path) -> Tuple[Tuple[List[Dict], List[Dict]], Dict]:
        """处理单个文件，返回结构化规则（{type, value, policy}）"""
        block_rules: List[Dict] = []  # 拦截规则
        allow_rules: List[Dict] = []  # 放行规则
        stats = {'filtered': 0, 'unsupported': 0}
        # 文件内去重缓存（基于类型+域名）
        file_block_cache: Set[Tuple[str, str]] = set()
        file_allow_cache: Set[Tuple[str, str]] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # 转换规则为结构化字典（{type, value, policy}）
                    rule_type, rule_data = self._convert_rule(line)
                    if rule_type == 'block' and rule_data:
                        key = (rule_data['type'], rule_data['value'])
                        if key not in file_block_cache:
                            file_block_cache.add(key)
                            block_rules.append(rule_data)
                    elif rule_type == 'allow' and rule_data:
                        key = (rule_data['type'], rule_data['value'])
                        if key not in file_allow_cache:
                            file_allow_cache.add(key)
                            allow_rules.append(rule_data)
                    elif rule_type == 'filtered':
                        stats['filtered'] += 1
                    else:
                        stats['unsupported'] += 1
        except Exception as e:
            logger.warning(f"读取{file_path.name}出错：{str(e)}")

        return (block_rules, allow_rules), stats

    def _convert_rule(self, line: str) -> Tuple[str, Dict]:
        """转换规则为结构化数据（{type, value, policy}）"""
        # 过滤无效规则（注释、长度异常）
        if self.regex.COMMENT.match(line) or not (self.len_min <= len(line) <= self.len_max):
            return ('filtered', {})
        # 过滤不支持的规则（脚本、跳转等）
        if self.regex.UNSUPPORTED.search(line):
            logger.debug(f"不支持的规则内容：{line}")  # 仅调试模式显示
            return ('unsupported', {})

        # 处理放行规则（策略：DIRECT）
        if self.regex.ALLOW_ADBLOCK.match(line):
            domain = self.regex.ALLOW_ADBLOCK.match(line).group(1)
            return ('allow', {
                'type': 'DOMAIN-SUFFIX',
                'value': domain,
                'policy': 'DIRECT'
            })
        if self.regex.ALLOW_OPTIONS.match(line):
            domain = re.sub(r'^@@([\w.-]+)\$.*$', r'\1', line)
            return ('allow', {
                'type': 'DOMAIN-SUFFIX',
                'value': domain,
                'policy': 'DIRECT'
            })

        # 处理拦截规则（策略：REJECT）
        if self.regex.BLOCK_ADBLOCK.match(line):
            domain = self.regex.BLOCK_ADBLOCK.match(line).group(1)
            return ('block', {
                'type': 'DOMAIN-SUFFIX',
                'value': domain,
                'policy': 'REJECT,no-resolve'
            })
        if self.regex.BLOCK_HOSTS.match(line):
            domain = self.regex.BLOCK_HOSTS.match(line).group(2)
            return ('block', {
                'type': 'DOMAIN',
                'value': domain,
                'policy': 'REJECT,no-resolve'
            })
        if self.regex.BLOCK_WILDCARD.match(line):
            if line.startswith('*.'):
                suffix = line[2:]  # 移除前缀*
                return ('block', {
                    'type': 'DOMAIN-SUFFIX',
                    'value': suffix,
                    'policy': 'REJECT'
                })
            elif '*' in line:
                keyword = line.replace('*', '')  # 提取关键词
                return ('block', {
                    'type': 'DOMAIN-KEYWORD',
                    'value': keyword,
                    'policy': 'REJECT'
                })
        if self.regex.BLOCK_OPTIONS.match(line):
            domain = re.sub(r'^([\w.-]+)\$.*$', r'\1', line)
            return ('block', {
                'type': 'DOMAIN-SUFFIX',
                'value': domain,
                'policy': 'REJECT'
            })
        if self.regex.PLAIN_DOMAIN.match(line):
            return ('block', {
                'type': 'DOMAIN-SUFFIX',
                'value': line,
                'policy': 'REJECT'
            })

        # 正则规则（下游可能不支持，标记为不支持）
        if self.regex.BLOCK_REGEX.match(line):
            logger.warning(f"检测到不支持的正则规则：{line}（下游MRS转换可能失败）")
            return ('unsupported', {})

        # 未匹配到任何规则类型
        logger.debug(f"无法识别的规则：{line}")
        return ('unsupported', {})

    def _write_yaml(self, file_path: Path, rules: List[Dict], rule_set_name: str, default_policy: str):
        """写入结构化YAML规则集（适配下游解析）"""
        with open(file_path, 'w', encoding='utf-8') as f:
            # 规则集引用头信息（Clash规范）
            f.write(f"#RULE-SET,{rule_set_name},{default_policy}\n")
            # 结构化payload（便于下游提取type/value）
            f.write("payload:\n")
            for rule in rules:
                # 确保规则包含必要字段
                rule_type = rule.get('type', '')
                domain = rule.get('value', '')
                policy = rule.get('policy', default_policy)
                if rule_type and domain:
                    f.write(f"  - type: {rule_type}\n")
                    f.write(f"    value: {domain}\n")
                    f.write(f"    policy: {policy}\n")


if __name__ == '__main__':
    try:
        converter = ClashYamlConverter()
        converter.run()
    except Exception as e:
        logger.critical(f"运行失败：{str(e)}", exc_info=True)
        sys.exit(1)
