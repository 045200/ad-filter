#!/usr/bin/env python3
"""
AdGuard Home 规则转换器
优化点：通过变量统一管理预编译正则，减少重复匹配开销
"""

import os
import re
import logging
from pathlib import Path

# 文件配置
FILE_CONFIG = {
    "black_input": "adblock_intermediate.txt",
    "white_input": "allow_intermediate.txt",
    "black_output": "adblock_adh.txt",
    "white_output": "allow_adh.txt"
}

# 预编译正则表达式 - 三大类规则统一管理
REGEX_PATTERNS = {
    # 黑名单专用规则
    "black": {
        "dns_rewrite": re.compile(r'^||.+\^$'),         # ||example.com^
        "hosts": re.compile(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+\.?$'),  # IP + 域名
        "standard": re.compile(r'^[\w.-]+\.?$')         # 标准域名
    },
    # 白名单专用规则
    "white": {
        "standard": re.compile(r'^[\w.-]+\.?$'),        # 标准域名
        "dns": re.compile(r'^@@\|\|.+\^$')              # @@||example.com^
    },
    # 特殊语法规则（黑白共用）
    "special": {
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$'),     # 带通配符 *.example.com 或 example.*
        "path": re.compile(r'^||[\w.-]+/.+$')           # 带路径 ||example.com/path
    }
}


def setup_logger():
    """配置日志记录器"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def convert_rule(line: str, rule_type: str) -> str:
    """
    统一转换规则函数，通过rule_type区分黑白名单
    减少重复函数定义，通过变量引用正则减少开销
    """
    line = line.strip()
    patterns = REGEX_PATTERNS  # 简化引用

    if rule_type == "black":
        # 黑名单规则匹配（按出现频率排序，优先匹配常见规则）
        if patterns["black"]["standard"].match(line):
            return f"||{line}^"
        if patterns["black"]["dns_rewrite"].match(line):
            return f"{line}$important"
        if patterns["black"]["hosts"].match(line):
            ip, domain = line.split()
            return f"||{domain}^$dnsrewrite=NOERROR;A;{ip}"
        if patterns["special"]["wildcard"].match(line) or patterns["special"]["path"].match(line):
            return f"{line}$important"

    elif rule_type == "white":
        # 白名单规则匹配（按出现频率排序）
        if patterns["white"]["standard"].match(line):
            return f"@@||{line}^"
        if patterns["white"]["dns"].match(line):
            return line
        if patterns["special"]["wildcard"].match(line):
            return f"@@||{line}^"

    return None


def process_file(input_path: Path, rule_type: str):
    """处理输入文件，通过rule_type统一控制逻辑"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return set()

    unique_rules = set()
    skipped_count = 0
    total_processed = 0

    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释（统一处理，减少分支）
            if not line or line.startswith('!'):
                continue

            total_processed += 1
            converted = convert_rule(line, rule_type)
            if converted:
                unique_rules.add(converted)
            else:
                skipped_count += 1
                logger.debug(f"跳过不支持的{rule_type}规则: {line}")

    logger.info(
        f"处理{rule_type}规则: 输入 {total_processed} 条, "
        f"有效 {len(unique_rules)} 条, 跳过 {skipped_count} 条"
    )
    return unique_rules


def write_output(rules: set, output_path: Path):
    """写入输出文件，保持排序一致性"""
    with output_path.open('w', encoding='utf-8') as f:
        # 单次写入减少IO操作
        f.write('\n'.join(sorted(rules)) + '\n')
    logger.info(f"生成 {output_path.name}: {len(rules)} 条规则")


def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 统一通过字符串变量控制规则类型，减少条件判断
    black_rules = process_file(repo_root / FILE_CONFIG["black_input"], "黑名单")
    write_output(black_rules, repo_root / FILE_CONFIG["black_output"])

    white_rules = process_file(repo_root / FILE_CONFIG["white_input"], "白名单")
    write_output(white_rules, repo_root / FILE_CONFIG["white_output"])

    # 重复规则检查（仅统计数量）
    duplicate_count = len(black_rules & white_rules)
    if duplicate_count > 0:
        logger.warning(f"发现 {duplicate_count} 条重复规则（同时存在于黑白名单）")


if __name__ == "__main__":
    main()
