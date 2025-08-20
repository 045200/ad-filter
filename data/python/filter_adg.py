#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard规则转换处理脚本
将中间规则转换为AdGuard兼容格式，保留有效规则并去重
适配4核16G环境，优化处理效率
"""

import os
import sys
import re
import logging
from pathlib import Path
from typing import Callable, Set, Tuple
from concurrent.futures import ThreadPoolExecutor

# ============== 环境变量与配置 ==============
# 基础路径（优先使用GitHub工作目录）
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
BASE_DIR = Path(GITHUB_WORKSPACE)
TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 临时输入目录
OUTPUT_DIR = BASE_DIR  # 输出目录（根目录）

# 规则文件映射配置
RULES_CONFIG = {
    "block": {
        "input": TEMP_DIR / "adblock_intermediate.txt",  # 临时目录输入
        "output": OUTPUT_DIR / "adblock_adg.txt"         # 根目录输出
    },
    "allow": {
        "input": TEMP_DIR / "allow_intermediate.txt",
        "output": OUTPUT_DIR / "allow_adg.txt"
    }
}

# 性能优化参数（适配4核16G环境）
MAX_WORKERS = 2  # 并行处理黑白名单（匹配CPU核心效率）
IO_BUFFER_SIZE = 8192  # 文件IO缓冲区大小（字节）

# AdGuard支持的修饰符（严格按官方规范）
SUPPORTED_MODIFIERS = {
    'domain', 'third-party', 'script', 'image', 'stylesheet', 'xmlhttprequest',
    'subdocument', 'document', 'elemhide', 'important', 'popup', 'dnsrewrite'
}

# ============== 日志配置 ==============
def setup_logger():
    """配置日志输出，适配GitHub Actions环境"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # 清空默认处理器，避免重复输出
    if logger.handlers:
        logger.handlers = []
    # 输出格式（CI环境简化显示）
    handler = logging.StreamHandler(sys.stdout)
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(asctime)s] %(levelname)s: %(message)s'
    datefmt = '%H:%M:%S' if os.getenv('GITHUB_ACTIONS') == 'true' else '%Y-%m-%d %H:%M:%S'
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ============== GitHub Actions支持 ==============
def gh_group(name: str):
    """GitHub Actions分组显示开始"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    """GitHub Actions分组显示结束"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")

# ============== 环境准备 ==============
def clean_output_files():
    """清理历史输出文件"""
    gh_group("清理历史输出")
    deleted = 0
    for rule_type in RULES_CONFIG:
        output_path = RULES_CONFIG[rule_type]["output"]
        if output_path.exists():
            output_path.unlink()
            deleted += 1
    logger.info(f"已清理 {deleted} 个历史规则文件")
    gh_endgroup()
    return deleted

def prepare_environment():
    """准备工作目录（创建临时目录、确保输出目录存在）"""
    gh_group("环境准备")
    # 创建临时目录（存放输入文件）
    TEMP_DIR.mkdir(exist_ok=True, parents=True)
    # 确保输出目录存在（根目录已存在，此处仅做验证）
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
    logger.info(f"工作目录就绪: 临时目录={TEMP_DIR}, 输出目录={OUTPUT_DIR}")
    gh_endgroup()

# ============== 正则模式定义 ==============
class RegexPatterns:
    """规则匹配正则表达式集合"""
    # 跳过空行和注释行（严格匹配）
    SKIP_LINE = re.compile(r'^\s*$|^(!|#|//|\[Adblock(?:\sPlus)?\]).*', re.IGNORECASE)

    # 黑名单规则模式
    BLOCK = {
        "abp_dns": re.compile(r'^||([\w.-]+)\^$'),
        "hosts": re.compile(r'^(\d+\.\d+\.\d+\.\d+|\[?[0-9a-fA-F:]+\]?)\s+([\w.-]+)$'),
        "domain": re.compile(r'^([\w.-]+)$'),
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$'),
        "elem_hide": re.compile(r'^##.+$')
    }

    # 白名单规则模式
    ALLOW = {
        "abp_exception": re.compile(r'^@@\|\|([\w.-]+)\^$'),
        "domain": re.compile(r'^([\w.-]+)$'),
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$'),
        "elem_allow": re.compile(r'^#@#.+$')
    }

    # 修饰符提取
    MODIFIERS = re.compile(r'\$(.*)$')

# ============== 核心规则处理 ==============
def filter_modifiers(rule: str) -> Tuple[str, bool]:
    """过滤规则中不支持的修饰符，保留有效部分"""
    if '$' not in rule:
        return rule, True
    # 分割规则主体与修饰符
    base, mods_part = rule.split('$', 1)
    if not base.strip():  # 规则主体为空则无效
        return "", False
    # 仅保留支持的修饰符（忽略大小写）
    valid_mods = [
        m for m in mods_part.split(',')
        if m.split('=', 1)[0].lower() in SUPPORTED_MODIFIERS
    ]
    # 重组规则
    filtered_rule = f"{base}${','.join(valid_mods)}" if valid_mods else base
    return filtered_rule, True

def is_valid_domain(domain: str) -> bool:
    """验证域名合法性（符合RFC规范）"""
    if len(domain) > 255 or domain.endswith('.'):
        return False
    # 每个标签需满足：1-63字符，首尾非连字符，仅含字母/数字/连字符
    part_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
    return all(part_pattern.match(part) for part in domain.split('.'))

def is_valid_ip(ip: str) -> bool:
    """验证IP地址有效性（支持IPv4和简化IPv6检查）"""
    # IPv4验证
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        parts = ip.split('.')
        return len(parts) == 4 and all(
            part.isdigit() and 0 <= int(part) <= 255 and (part == '0' or not part.startswith('0'))
            for part in parts
        )
    # 简化IPv6验证（基本格式）
    return re.match(r'^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$', ip) is not None

def convert_block(line: str) -> Tuple[str, bool]:
    """转换黑名单规则为AdGuard格式"""
    line_stripped = line.strip()
    # ABP DNS规则（如 ||example.com^）
    if (match := RegexPatterns.BLOCK["abp_dns"].match(line_stripped)) and is_valid_domain(match[1]):
        return filter_modifiers(f"{line_stripped}$important")
    # Hosts规则（如 127.0.0.1 example.com）
    if (match := RegexPatterns.BLOCK["hosts"].match(line_stripped)) and is_valid_domain(match[2]):
        ip = match[1].strip('[]')  # 移除IPv6可能的括号
        if is_valid_ip(ip):
            return filter_modifiers(f"||{match[2]}^$dnsrewrite=NOERROR;A;{ip}")
        return "", False
    # 纯域名规则（如 example.com）
    if (match := RegexPatterns.BLOCK["domain"].match(line_stripped)) and is_valid_domain(match[1]):
        return filter_modifiers(f"||{match[1]}^")
    # 通配符规则（如 *example.com*）
    if RegexPatterns.BLOCK["wildcard"].match(line_stripped):
        return filter_modifiers(f"{line_stripped}$important")
    # 元素隐藏规则（如 ##.ad-class）
    if RegexPatterns.BLOCK["elem_hide"].match(line_stripped):
        return filter_modifiers(line_stripped)
    # 其他规则仅过滤修饰符
    return filter_modifiers(line_stripped)

def convert_allow(line: str) -> Tuple[str, bool]:
    """转换白名单规则为AdGuard格式"""
    line_stripped = line.strip()
    # ABP例外规则（如 @@||example.com^）
    if (match := RegexPatterns.ALLOW["abp_exception"].match(line_stripped)) and is_valid_domain(match[1]):
        return filter_modifiers(line_stripped)
    # 纯域名白名单（如 example.com）
    if (match := RegexPatterns.ALLOW["domain"].match(line_stripped)) and is_valid_domain(match[1]):
        return filter_modifiers(f"@@||{match[1]}^")
    # 通配符白名单（如 *example.com*）
    if RegexPatterns.ALLOW["wildcard"].match(line_stripped):
        return filter_modifiers(f"@@{line_stripped}^")
    # 元素隐藏例外（如 #@#.ad-class）
    if RegexPatterns.ALLOW["elem_allow"].match(line_stripped):
        return filter_modifiers(line_stripped)
    # 其他规则仅过滤修饰符
    return filter_modifiers(line_stripped)

# ============== 文件处理 ==============
def process_file(
    in_path: Path,
    out_path: Path,
    converter: Callable[[str], Tuple[str, bool]]
) -> int:
    """处理单个规则文件：转换并去重"""
    if not in_path.exists():
        logger.warning(f"输入文件不存在: {in_path}")
        return 0

    unique_rules: Set[str] = set()
    total_lines = 0
    skipped_lines = 0

    # 高效读写（大缓冲+编码指定）
    with open(in_path, 'r', encoding='utf-8', buffering=IO_BUFFER_SIZE) as fin, \
         open(out_path, 'w', encoding='utf-8', buffering=IO_BUFFER_SIZE, newline='\n') as fout:

        for line in fin:
            total_lines += 1
            line_stripped = line.strip()
            # 跳过空行和注释
            if RegexPatterns.SKIP_LINE.match(line_stripped):
                skipped_lines += 1
                continue
            # 转换规则并验证
            rule, valid = converter(line_stripped)
            if valid and rule:
                unique_rules.add(rule)
            else:
                skipped_lines += 1

        # 写入去重后的规则（不排序以节省CPU）
        fout.write('\n'.join(unique_rules))

    logger.info(f"处理完成: {in_path.name} -> {out_path.name} "
                f"[总行数: {total_lines}, 有效规则: {len(unique_rules)}, 跳过: {skipped_lines}]")
    return len(unique_rules)

# ============== 主流程 ==============
def main():
    start_time = time.time()

    # 环境准备
    clean_output_files()
    prepare_environment()

    # 并行处理黑白名单规则
    gh_group("规则转换处理")
    tasks = [
        (
            RULES_CONFIG["block"]["input"],
            RULES_CONFIG["block"]["output"],
            convert_block
        ),
        (
            RULES_CONFIG["allow"]["input"],
            RULES_CONFIG["allow"]["output"],
            convert_allow
        )
    ]

    # 使用线程池并行处理
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(lambda args: process_file(*args), tasks))

    block_cnt, allow_cnt = results
    elapsed = time.time() - start_time
    gh_endgroup()

    # 输出汇总信息
    logger.info(f"\n处理完成 | 总耗时: {elapsed:.2f}s")
    logger.info(f"黑名单规则: {block_cnt} 条（输出至 {RULES_CONFIG['block']['output'].name}）")
    logger.info(f"白名单规则: {allow_cnt} 条（输出至 {RULES_CONFIG['allow']['output'].name}）")

if __name__ == "__main__":
    import time  # 延迟导入，仅主流程使用
    main()
