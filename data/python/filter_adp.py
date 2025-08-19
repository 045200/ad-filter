#!/usr/bin/env python3
"""
AdBlock Plus 纯净规则提取工具
功能：仅提取符合ABP语法的规则，去重、分黑白名单，输出无任何冗余内容的纯净规则文件
输入：adblock_intermediate.txt（待处理黑名单）、allow_intermediate.txt（待处理白名单）
输出：adblock_abp.txt（纯净黑名单规则）、allow_abp.txt（纯净白名单规则）
"""

import os
import re
import logging
from pathlib import Path

# 路径配置
CONFIG = {
    "black": {"input": "adblock_intermediate.txt", "output": "adblock_abp.txt"},
    "white": {"input": "allow_intermediate.txt", "output": "allow_abp.txt"}
}

# 日志配置（仅用于过程记录，不影响输出文件）
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[处理日志] %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# ABP核心语法定义（严格匹配规则格式）
class ABPSyntax:
    # 规则前缀正则：覆盖所有ABP支持的规则起始格式
    # 包括：
    # - 普通域名规则：||example.com、example.com
    # - 元素隐藏规则：##.ad、#@#.ad（例外元素隐藏）
    # - 例外规则前缀：@@||example.com
    # - 正则规则：/^https?:\/\/example\.com/
    BASE_PREFIXES = re.compile(
        r'^(|||@@\|\||@@|##|#@#|/|[\w\-.])'
    )
    EXCEPTION_MARKER = '@@'  # 白名单规则标记（例外规则）
    MODIFIER_SEPARATOR = '$'  # 修饰符分隔符（如$domain=example.com）
    SPECIAL_MARKERS = re.compile(r'^\[(Adblock|AdBlock Plus)\]')  # 需跳过的规则头标记


def extract_pure_abp_rule(line: str) -> str:
    """提取严格符合ABP语法的纯净规则，过滤所有非规则内容"""
    line = line.strip()
    # 跳过空行、注释（!开头）、特殊标记（如[Adblock]）
    if not line or line.startswith('!') or ABPSyntax.SPECIAL_MARKERS.match(line):
        return ""
    
    # 处理带修饰符的规则（如||example.com$domain=test.com）
    if ABPSyntax.MODIFIER_SEPARATOR in line:
        base_part, modifier_part = line.split(ABPSyntax.MODIFIER_SEPARATOR, 1)
        base_part = base_part.strip()
        modifier_part = modifier_part.strip()
        # 基础部分必须符合ABP前缀规则，修饰符部分非空
        if ABPSyntax.BASE_PREFIXES.match(base_part) and modifier_part:
            return f"{base_part}{ABPSyntax.MODIFIER_SEPARATOR}{modifier_part}"
        return ""
    
    # 处理无修饰符的规则（基础部分必须符合ABP前缀规则）
    if ABPSyntax.BASE_PREFIXES.match(line):
        return line
    
    # 不符合ABP语法的内容全部过滤
    return ""


def process_rules(input_path: Path, output_path: Path, is_whitelist: bool):
    """处理规则文件：提取纯净规则、去重、按黑白名单分类"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在：{input_path}")
        return 0, 0, 0

    total_lines = 0  # 总处理行数
    valid_rules = 0  # 有效规则数
    duplicate_rules = 0  # 重复规则数
    seen_rules = set()  # 去重集合

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            for line in infile:
                total_lines += 1
                # 提取纯净ABP规则
                pure_rule = extract_pure_abp_rule(line)
                if not pure_rule:
                    continue  # 跳过非规则内容
                
                # 黑白名单分类校验
                is_exception_rule = pure_rule.startswith(ABPSyntax.EXCEPTION_MARKER)
                if (is_whitelist and not is_exception_rule) or (not is_whitelist and is_exception_rule):
                    continue  # 分类不匹配则过滤
                
                # 去重处理
                if pure_rule in seen_rules:
                    duplicate_rules += 1
                    continue
                
                # 写入纯净规则（无额外内容，仅规则本身）
                outfile.write(pure_rule + '\n')
                seen_rules.add(pure_rule)
                valid_rules += 1

    except Exception as e:
        logger.error(f"文件处理失败：{str(e)}")

    return total_lines, valid_rules, duplicate_rules


def main():
    work_dir = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))

    # 处理黑名单规则
    black_total, black_valid, black_dups = process_rules(
        work_dir / CONFIG["black"]["input"],
        work_dir / CONFIG["black"]["output"],
        is_whitelist=False
    )
    logger.info(
        f"黑名单处理结果：总行数{black_total}，有效规则{black_valid}，重复规则{black_dups}"
    )

    # 处理白名单规则
    white_total, white_valid, white_dups = process_rules(
        work_dir / CONFIG["white"]["input"],
        work_dir / CONFIG["white"]["output"],
        is_whitelist=True
    )
    logger.info(
        f"白名单处理结果：总行数{white_total}，有效规则{white_valid}，重复规则{white_dups}"
    )


if __name__ == "__main__":
    main()
