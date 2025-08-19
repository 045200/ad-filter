#!/usr/bin/env python3
"""
Adblock Plus 规则转换器
功能：将各类中间规则（hosts、域名列表等）转换为标准ABP语法，去重后输出纯净规则
ABP核心语法参考：
- 基本拦截规则：||example.com^（匹配所有子域名及协议）
- 例外规则（白名单）：@@||example.com^（跳过拦截）
- 通配符：*（匹配任意字符）、^（匹配分隔符，如/、:等）
"""

import os
import re
import logging
from pathlib import Path
from typing import Set

# 文件路径配置
FILE_CONFIG = {
    "block_input": "block_intermediate.txt",  # 待转换的拦截规则输入
    "allow_input": "allow_intermediate.txt",  # 待转换的允许规则输入
    "block_output": "abp_block.txt",          # ABP格式拦截规则输出
    "allow_output": "abp_allow.txt"           # ABP格式允许规则输出
}

# 预编译正则（匹配输入规则类型，按ABP语法转换）
REGEX_PATTERNS = {
    # 通用需跳过的行（注释、空行等，确保输出纯净）
    "skip": re.compile(r'^\s*$|^(!|#|//).*', re.IGNORECASE),  # 空行、注释行（!/#//开头）
    
    # 拦截规则（黑名单）匹配模式
    "block": {
        "domain": re.compile(r'^[\w.-]+\.?$'),  # 标准域名（example.com 或 example.com.）
        "hosts": re.compile(r'^\d+\.\d+\.\d+\.\d+\s+([\w.-]+\.?)$'),  # hosts格式（IP 域名）
        "abp_raw": re.compile(r'^(\|\||\*)\S+\^?$'),  # 已符合ABP格式的规则（如||example.com^）
        "path": re.compile(r'^[\w.-]+/.*$')  # 带路径的规则（example.com/path）
    },
    
    # 允许规则（白名单）匹配模式
    "allow": {
        "domain": re.compile(r'^[\w.-]+\.?$'),  # 标准域名
        "abp_raw": re.compile(r'^@@(\|\||\*)\S+\^?$'),  # 已符合ABP例外格式的规则（如@@||example.com^）
        "path": re.compile(r'^[\w.-]+/.*$')  # 带路径的允许规则
    }
}


def setup_logger():
    """配置日志，记录处理状态（不干扰输出文件）"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def is_valid_abp_domain(domain: str) -> bool:
    """验证域名合法性（符合ABP规则要求，避免无效规则）"""
    domain = domain.rstrip('.')  # 移除可能的末尾点
    if len(domain) > 253:  # DNS域名最大长度限制
        return False
    # 校验域名片段（仅允许字母、数字、-，且不允许首尾为-）
    return all(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', part) 
               for part in domain.split('.'))


def convert_block_rule(line: str) -> str:
    """将单行规则转换为ABP拦截规则格式"""
    line = line.strip()
    patterns = REGEX_PATTERNS["block"]

    # 已符合ABP格式的规则直接保留
    if patterns["abp_raw"].match(line):
        return line

    # 标准域名（转换为||domain^）
    if (match := patterns["domain"].match(line)):
        domain = match.group()
        if is_valid_abp_domain(domain):
            return f"||{domain}^"

    # hosts格式（提取域名，转换为||domain^）
    if (match := patterns["hosts"].match(line)):
        domain = match.group(1)
        if is_valid_abp_domain(domain):
            return f"||{domain}^"

    # 带路径的规则（补全为||domain/path^）
    if (match := patterns["path"].match(line)):
        path_rule = match.group()
        # 拆分域名和路径（简单处理，假设首个/前为域名）
        domain_part = path_rule.split('/')[0]
        if is_valid_abp_domain(domain_part):
            return f"||{path_rule}^"

    # 未匹配的规则返回None（跳过）
    return None


def convert_allow_rule(line: str) -> str:
    """将单行规则转换为ABP例外规则格式（白名单）"""
    line = line.strip()
    patterns = REGEX_PATTERNS["allow"]

    # 已符合ABP例外格式的规则直接保留
    if patterns["abp_raw"].match(line):
        return line

    # 标准域名（转换为@@||domain^）
    if (match := patterns["domain"].match(line)):
        domain = match.group()
        if is_valid_abp_domain(domain):
            return f"@@||{domain}^"

    # 带路径的允许规则（补全为@@||domain/path^）
    if (match := patterns["path"].match(line)):
        path_rule = match.group()
        domain_part = path_rule.split('/')[0]
        if is_valid_abp_domain(domain_part):
            return f"@@||{path_rule}^"

    # 未匹配的规则返回None（跳过）
    return None


def process_rules(input_path: Path, rule_type: str) -> Set[str]:
    """
    处理输入文件：读取规则→转换为ABP格式→自动去重
    rule_type: "block"（拦截规则）或 "allow"（允许规则）
    """
    if not input_path.exists():
        logger.warning(f"输入文件不存在：{input_path}")
        return set()

    unique_rules: Set[str] = set()
    total = 0  # 总处理行数
    skipped = 0  # 跳过的行数（无效/不支持的规则）

    with input_path.open('r', encoding='utf-8') as f:
        for line in f:
            total += 1
            line_stripped = line.strip()

            # 跳过注释、空行（确保输出纯净无冗余）
            if REGEX_PATTERNS["skip"].match(line_stripped):
                skipped += 1
                continue

            # 按规则类型转换
            if rule_type == "block":
                converted = convert_block_rule(line_stripped)
            else:  # allow
                converted = convert_allow_rule(line_stripped)

            if converted:
                unique_rules.add(converted)
            else:
                skipped += 1
                logger.debug(f"跳过不支持的{rule_type}规则：{line_stripped}")

    logger.info(
        f"处理{rule_type}规则：共{total}行，有效转换{len(unique_rules)}条，跳过{skipped}条"
    )
    return unique_rules


def write_abp_rules(rules: Set[str], output_path: Path):
    """写入ABP规则文件（纯净格式，仅含有效规则，无注释/空行）"""
    if not rules:
        logger.warning(f"无有效规则可写入{output_path.name}")
        return

    # 排序后写入（规则按字母序排列，便于查看）
    with output_path.open('w', encoding='utf-8') as f:
        # 每行一条规则，最后一行无多余空行
        f.write('\n'.join(sorted(rules)))

    logger.info(f"已生成ABP规则文件：{output_path.name}（{len(rules)}条规则）")


def main():
    # 确定工作目录（支持GitHub Actions环境）
    work_dir = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))

    # 处理拦截规则（黑名单）
    block_rules = process_rules(work_dir / FILE_CONFIG["block_input"], "block")
    write_abp_rules(block_rules, work_dir / FILE_CONFIG["block_output"])

    # 处理允许规则（白名单）
    allow_rules = process_rules(work_dir / FILE_CONFIG["allow_input"], "allow")
    write_abp_rules(allow_rules, work_dir / FILE_CONFIG["allow_output"])

    # 检查黑白名单冲突（同一规则同时存在于拦截和允许列表）
    conflicts = block_rules & allow_rules
    if conflicts:
        logger.warning(f"发现{len(conflicts)}条冲突规则（同时在拦截和允许列表中）")


if __name__ == "__main__":
    main()
