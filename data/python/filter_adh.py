#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard Home 规则转换器
功能：转换黑白名单规则为纯净AdGuard语法，去重后输出
核心逻辑：严格转换→自动去重→纯净输出
"""

import os
import re
import time
import logging
from pathlib import Path
from typing import Set

# ============== 环境变量与路径配置 ==============
# 与步骤1/2/3保持一致的路径定义
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 与步骤1的临时目录保持一致
DATA_DIR = BASE_DIR / os.getenv('DATA_DIR', 'data')  # 预留数据目录，与步骤1对齐

# 文件路径配置（统一关联到基础目录，与步骤1/2/3路径逻辑一致）
FILE_CONFIG = {
    "black_input": TEMP_DIR / "adblock_intermediate.txt",  # 输入文件位于临时目录
    "white_input": TEMP_DIR / "allow_intermediate.txt",
    "black_output": BASE_DIR / "adblock_adh.txt",  # 输出文件位于根目录
    "white_output": BASE_DIR / "allow_adh.txt"
}

# ============== 预编译正则（精确匹配规则类型，减少重复匹配开销） ==============
REGEX = {
    # 黑名单规则模式
    "black": {
        "standard": re.compile(r'^[\w.-]+\.?$'),  # 标准域名（example.com 或 example.com.）
        "dns_rewrite": re.compile(r'^||[\w.-]+\^$'),  # ABP标准DNS规则（||example.com^）
        "hosts": re.compile(r'^(\d+\.\d+\.\d+\.\d+|\[?[0-9a-fA-F:]+\]?)\s+([\w.-]+\.?)$'),  # 支持IPv4/IPv6 hosts
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$'),  # 通配符（*.example.com 或 example.*）
        "path": re.compile(r'^||[\w.-]+/.+$')  # 带路径（||example.com/path）
    },
    # 白名单规则模式
    "white": {
        "standard": re.compile(r'^[\w.-]+\.?$'),  # 标准域名
        "dns": re.compile(r'^@@\|\|[\w.-]+\^$'),  # ABP例外规则（@@||example.com^）
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$')  # 通配符
    },
    # 需跳过的行（确保输出纯净）
    "skip": re.compile(r'^\s*$|^(!|#|//|\[Adblock(?:\sPlus)?\]).*', re.IGNORECASE)  # 空行、注释、标记行
}


# ============== 日志配置 ==============
def setup_logger():
    """配置日志（仅记录处理状态，不干扰输出文件）"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(levelname)s] %(message)s'
    handler.setFormatter(logging.Formatter(fmt))
    logger.handlers = [handler]
    return logger


logger = setup_logger()


# ============== GitHub Actions支持 ==============
def gh_group(name):
    """GitHub Actions日志分组开始（与步骤1/2/3保持一致）"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")


def gh_endgroup():
    """GitHub Actions日志分组结束（与步骤1/2/3保持一致）"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


# ============== 清理历史输出文件（对齐步骤3逻辑） ==============
def clean_history_outputs():
    """清理步骤4生成的历史输出文件，避免旧文件残留"""
    gh_group("清理历史输出文件")
    deleted = 0
    # 定义需要清理的输出文件列表（与FILE_CONFIG中的输出路径对应）
    output_files = [
        FILE_CONFIG["black_output"],
        FILE_CONFIG["white_output"]
    ]
    for file in output_files:
        if file.exists() and file.is_file():
            file.unlink(missing_ok=True)
            deleted += 1
    logger.info(f"清理完成：{deleted}个历史输出文件已删除")
    gh_endgroup()
    return deleted


# ============== 规则处理核心逻辑 ==============
def is_valid_domain(domain: str) -> bool:
    """验证域名合法性（避免生成无效规则）"""
    domain = domain.rstrip('.')  # 移除可能的末尾点
    if len(domain) > 255:
        return False
    # 校验每个域名片段（符合DNS规范）
    return all(re.match(r'^[a-zA-Z0-9-]{1,63}$', part) for part in domain.split('.'))


def convert_rule(line: str, rule_type: str) -> str:
    """
    转换单条规则为AdGuard语法
    rule_type: "black"（黑名单）或 "white"（白名单）
    """
    line = line.strip()
    patterns = REGEX[rule_type]  # 按类型获取对应正则

    if rule_type == "black":
        # 标准域名规则（优先匹配，高频场景）
        if (match := patterns["standard"].match(line)):
            domain = match.group()
            if is_valid_domain(domain):
                return f"||{domain}^"

        # ABP DNS重写规则
        if (match := patterns["dns_rewrite"].match(line)):
            return f"{line}$important"

        # Hosts规则（转换为dnsrewrite）
        if (match := patterns["hosts"].match(line)):
            ip, domain = match.groups()
            if is_valid_domain(domain):
                return f"||{domain}^$dnsrewrite=NOERROR;A;{ip}"

        # 通配符规则
        if patterns["wildcard"].match(line):
            return f"{line}$important"

        # 带路径规则
        if patterns["path"].match(line):
            return f"{line}$important"

    elif rule_type == "white":
        # 标准域名白名单
        if (match := patterns["standard"].match(line)):
            domain = match.group()
            if is_valid_domain(domain):
                return f"@@||{domain}^"

        # ABP例外规则（直接保留）
        if patterns["dns"].match(line):
            return line

        # 通配符白名单
        if patterns["wildcard"].match(line):
            return f"@@||{line}^"

    # 未匹配的规则返回None（跳过）
    return None


def process_file(input_path: Path, rule_type: str) -> Set[str]:
    """
    处理输入文件：转换规则→自动去重
    仅保留有效规则，过滤所有注释、空行和不支持的规则
    """
    if not input_path.exists():
        logger.warning(f"输入文件不存在：{input_path}")
        return set()

    unique_rules: Set[str] = set()
    total = 0
    skipped = 0

    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            line_stripped = line.strip()
            total += 1

            # 跳过空行、注释和标记行（确保输出纯净）
            if REGEX["skip"].match(line_stripped):
                skipped += 1
                continue

            # 转换规则并检查有效性
            converted = convert_rule(line_stripped, rule_type)
            if converted:
                unique_rules.add(converted)
            else:
                skipped += 1
                logger.debug(f"跳过不支持的{rule_type}规则：{line_stripped}")

    logger.info(
        f"处理{rule_type}：总输入{total}条，有效{len(unique_rules)}条，跳过{skipped}条"
    )
    return unique_rules


def write_output(rules: Set[str], output_path: Path):
    """写入输出文件：仅含去重后的纯净规则，无多余内容"""
    if not rules:
        logger.warning(f"无有效{output_path.name}规则可写入")
        return

    # 排序后单次写入（减少IO操作，确保无多余空行）
    with output_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(rules)))  # 不额外加换行，避免最后一行空行

    logger.info(f"生成{output_path.name}：{len(rules)}条纯净规则")


# ============== 主流程 ==============
def main():
    start_time = time.time()  # 耗时统计，与步骤1对齐

    # 环境准备：先清理历史输出，再检查目录
    clean_history_outputs()  # 新增清理历史输出逻辑，与步骤3对齐

    gh_group("规则转换准备")
    # 验证目录存在性（与步骤1的环境准备逻辑一致）
    for dir in [TEMP_DIR, DATA_DIR]:
        dir.mkdir(exist_ok=True, parents=True)
    logger.info("转换环境就绪")
    gh_endgroup()

    # 处理黑名单
    gh_group("处理黑名单规则")
    black_rules = process_file(FILE_CONFIG["black_input"], "black")
    write_output(black_rules, FILE_CONFIG["black_output"])
    gh_endgroup()

    # 处理白名单
    gh_group("处理白名单规则")
    white_rules = process_file(FILE_CONFIG["white_input"], "white")
    write_output(white_rules, FILE_CONFIG["white_output"])
    gh_endgroup()

    # 检查黑白名单重复规则
    gh_group("重复规则检查")
    duplicates = black_rules & white_rules
    if duplicates:
        logger.warning(f"发现{len(duplicates)}条重复规则（同时存在于黑白名单）")
    else:
        logger.info("未发现黑白名单重复规则")
    gh_endgroup()

    # 输出总耗时（与步骤1对齐）
    elapsed = time.time() - start_time
    logger.info(f"规则转换完成 | 总耗时: {elapsed:.2f}s")


if __name__ == "__main__":
    main()
