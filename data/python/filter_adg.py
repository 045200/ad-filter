#!/usr/bin/env python3
"""
AdGuard 规则转换器 - 独立处理版
功能：独立处理黑名单、白名单，不交叉提取，仅转换各自规则为AdGuard格式
输入: 
  - adblock_intermediate.txt (黑名单)
  - allow_intermediate.txt (白名单)
输出:
  - adblock_adg.txt (转换后黑名单)
  - allow_adg.txt (转换后白名单)
"""

import os
import re
import logging
from pathlib import Path

# 配置统一管理
CONFIG = {
    "block": {
        "input": "adblock_intermediate.txt",
        "output": "adblock_adg.txt"
    },
    "allow": {
        "input": "allow_intermediate.txt",
        "output": "allow_adg.txt"
    }
}

# 预编译正则表达式（三大类规则分类管理）
REGEX = {
    # 黑名单规则模式
    "block": {
        "dns_rewrite": re.compile(r'^||.+\^$'),         # ||example.com^
        "hosts": re.compile(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$'),  # IP + 域名
        "standard": re.compile(r'^[\w.-]+$'),           # 标准域名
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$')      # 带通配符
    },
    # 白名单规则模式
    "allow": {
        "standard": re.compile(r'^[\w.-]+$'),           # 标准域名
        "adblock": re.compile(r'^@@\|\|.+\^$'),         # @@||example.com^
        "wildcard": re.compile(r'^\*?[\w.-]+\*?$')      # 带通配符
    },
    # 通用模式
    "common": {
        "comment": re.compile(r'^(!|#|\[Adblock).*'),   # 注释行
        "empty": re.compile(r'^\s*$'),                  # 空行
        "modifiers": re.compile(r'\$(.*)$')             # 规则修饰符部分
    }
}

# AdGuard支持的修饰符列表
SUPPORTED_MODIFIERS = {
    'domain', 'third-party', 'script', 'image', 'stylesheet', 'object',
    'xmlhttprequest', 'subdocument', 'ping', 'websocket', 'webrtc', 'document',
    'elemhide', 'genericblock', 'generichide', 'important', 'popup',
    'csp', 'redirect', 'removeparam', 'badfilter', 'all', 'inline-script',
    'removeheader', 'hls', 'jsonprune', 'app', 'network', 'dnsrewrite',
    'replace', 'cname', 'dnstype', 'dns'
}


def setup_logger():
    """配置日志"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def filter_modifiers(rule: str) -> str:
    """过滤规则中不支持的修饰符"""
    if '$' not in rule:
        return rule

    base, modifiers_part = rule.split('$', 1)
    valid_modifiers = []

    for mod in modifiers_part.split(','):
        mod = mod.strip()
        if not mod:
            continue

        # 分离修饰符名称和值（如 domain=example.com）
        mod_name = mod.split('=', 1)[0].strip()
        if mod_name in SUPPORTED_MODIFIERS:
            valid_modifiers.append(mod)

    return f"{base}${','.join(valid_modifiers)}" if valid_modifiers else base


def convert_block_rule(line: str) -> str:
    """转换黑名单规则为AdGuard格式"""
    line = line.strip()
    if REGEX["block"]["dns_rewrite"].match(line):
        return filter_modifiers(f"{line}$important")
    if REGEX["block"]["hosts"].match(line):
        ip, domain = line.split()
        return filter_modifiers(f"||{domain}^$dnsrewrite=NOERROR;A;{ip}")
    if REGEX["block"]["standard"].match(line):
        return filter_modifiers(f"||{line}^")
    if REGEX["block"]["wildcard"].match(line):
        return filter_modifiers(f"{line}$important")
    return filter_modifiers(line)  # 未匹配到特定模式的规则直接过滤修饰符


def convert_allow_rule(line: str) -> str:
    """转换白名单规则为AdGuard格式"""
    line = line.strip()
    if REGEX["allow"]["adblock"].match(line):
        return filter_modifiers(line)
    if REGEX["allow"]["standard"].match(line):
        return filter_modifiers(f"@@||{line}^")
    if REGEX["allow"]["wildcard"].match(line):
        return filter_modifiers(f"@@||{line}^")
    return filter_modifiers(line)  # 未匹配到特定模式的规则直接过滤修饰符


def process_single_file(input_path: Path, output_path: Path, rule_type: str) -> int:
    """独立处理单个文件（黑名单/白名单）"""
    if not input_path.exists():
        logger.warning(f"输入文件不存在: {input_path}")
        return 0

    # 选择对应的转换函数
    convert_func = convert_block_rule if rule_type == "block" else convert_allow_rule
    unique_rules = set()  # 自动去重
    total = 0
    skipped = 0

    with input_path.open('r', encoding='utf-8') as fin, \
         output_path.open('w', encoding='utf-8') as fout:

        for line in fin:
            line = line.strip()
            total += 1

            # 跳过空行和注释行（不写入输出，避免冗余）
            if REGEX["common"]["empty"].match(line) or REGEX["common"]["comment"].match(line):
                skipped += 1
                continue

            # 转换规则
            converted = convert_func(line)
            if converted:
                unique_rules.add(converted)
            else:
                skipped += 1

        # 写入去重后的规则（排序保证输出一致性）
        fout.write('\n'.join(sorted(unique_rules)))

    logger.info(f"{rule_type}处理: 总规则{total} 有效{len(unique_rules)} 跳过{skipped}")
    return len(unique_rules)


def main():
    repo_root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))

    # 独立处理黑名单
    block_count = process_single_file(
        repo_root / CONFIG["block"]["input"],
        repo_root / CONFIG["block"]["output"],
        "黑名单"
    )

    # 独立处理白名单
    allow_count = process_single_file(
        repo_root / CONFIG["allow"]["input"],
        repo_root / CONFIG["allow"]["output"],
        "白名单"
    )

    logger.info(f"生成 {CONFIG['block']['output']}: {block_count} 条规则")
    logger.info(f"生成 {CONFIG['allow']['output']}: {allow_count} 条规则")


if __name__ == "__main__":
    main()
