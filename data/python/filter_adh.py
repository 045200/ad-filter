#!/usr/bin/env python3
"""
AdGuard Home 规则转换器
功能：转换黑白名单规则为纯净AdGuard语法，去重后输出
核心逻辑：严格转换→自动去重→纯净输出
"""

import os
import re
import logging
from pathlib import Path
from typing import Set

# 文件路径配置（统一管理输入输出）
FILE_CONFIG = {
    "black_input": "adblock_intermediate.txt",
    "white_input": "allow_intermediate.txt",
    "black_output": "adblock_adh.txt",
    "white_output": "allow_adh.txt"
}

# 预编译正则（精确匹配规则类型，减少重复匹配开销）
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


def setup_logger():
    """配置日志（仅记录处理状态，不干扰输出文件）"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


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


def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))

    # 处理黑名单（规则类型统一为"black"）
    black_rules = process_file(repo_root / FILE_CONFIG["black_input"], "black")
    write_output(black_rules, repo_root / FILE_CONFIG["black_output"])

    # 处理白名单（规则类型统一为"white"）
    white_rules = process_file(repo_root / FILE_CONFIG["white_input"], "white")
    write_output(white_rules, repo_root / FILE_CONFIG["white_output"])

    # 检查黑白名单重复规则（仅提示数量，不影响输出）
    duplicates = black_rules & white_rules
    if duplicates:
        logger.warning(f"发现{len(duplicates)}条重复规则（同时存在于黑白名单）")


if __name__ == "__main__":
    main()
