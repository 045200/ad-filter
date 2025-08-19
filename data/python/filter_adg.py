#!/usr/bin/env python3
import os
import re
import logging
from pathlib import Path
from typing import Callable, Set, Tuple

# 配置：输入输出路径（仅保留核心映射）
CONFIG = {
    "block": {"input": "adblock_intermediate.txt", "output": "adblock_adg.txt"},
    "allow": {"input": "allow_intermediate.txt", "output": "allow_adg.txt"}
}

# 正则模式（聚焦规则匹配，移除冗余注释判断）
class Regex:
    # 严格匹配需跳过的行（空行、所有注释格式）
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

# AdGuard支持的修饰符（精简集合）
SUPPORTED_MODIFIERS = {
    'domain', 'third-party', 'script', 'image', 'stylesheet', 'xmlhttprequest',
    'subdocument', 'document', 'elemhide', 'important', 'popup', 'dnsrewrite'
}

def setup_logger():
    """配置日志（仅记录处理状态，不影响输出文件）"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()

def filter_modifiers(rule: str) -> Tuple[str, bool]:
    """过滤无效修饰符，返回有效规则"""
    if '$' not in rule:
        return rule, True
    base, mods_part = rule.split('$', 1)
    if not base.strip():
        return "", False
    valid_mods = [m for m in mods_part.split(',') if m.split('=',1)[0].lower() in SUPPORTED_MODIFIERS]
    return f"{base}${','.join(valid_mods)}" if valid_mods else base, True

def is_valid_domain(domain: str) -> bool:
    """验证域名合法性（避免生成无效规则）"""
    if len(domain) > 255 or domain.endswith('.'):
        return False
    return all(re.match(r'^[a-zA-Z0-9-]{1,63}$', part) for part in domain.split('.'))

def convert_block(line: str) -> Tuple[str, bool]:
    """转换黑名单规则为AdGuard格式"""
    line = line.strip()
    # ABP DNS规则
    if (m := Regex.BLOCK["abp_dns"].match(line)) and is_valid_domain(m[1]):
        return filter_modifiers(f"{line}$important")
    # Hosts规则
    if (m := Regex.BLOCK["hosts"].match(line)) and is_valid_domain(m[2]):
        return filter_modifiers(f"||{m[2]}^$dnsrewrite=NOERROR;A;{m[1]}")
    # 纯域名
    if (m := Regex.BLOCK["domain"].match(line)) and is_valid_domain(m[1]):
        return filter_modifiers(f"||{m[1]}^")
    # 通配符
    if Regex.BLOCK["wildcard"].match(line):
        return filter_modifiers(f"{line}$important")
    # 元素隐藏
    if Regex.BLOCK["elem_hide"].match(line):
        return filter_modifiers(line)
    # 其他规则直接过滤修饰符
    return filter_modifiers(line)

def convert_allow(line: str) -> Tuple[str, bool]:
    """转换白名单规则为AdGuard格式"""
    line = line.strip()
    # ABP例外规则
    if (m := Regex.ALLOW["abp_exception"].match(line)) and is_valid_domain(m[1]):
        return filter_modifiers(line)
    # 纯域名白名单
    if (m := Regex.ALLOW["domain"].match(line)) and is_valid_domain(m[1]):
        return filter_modifiers(f"@@||{m[1]}^")
    # 通配符白名单
    if Regex.ALLOW["wildcard"].match(line):
        return filter_modifiers(f"@@||{line}^")
    # 元素隐藏例外
    if Regex.ALLOW["elem_allow"].match(line):
        return filter_modifiers(line)
    # 其他规则直接过滤修饰符
    return filter_modifiers(line)

def process_file(
    in_path: Path, 
    out_path: Path, 
    converter: Callable[[str], Tuple[str, bool]]
) -> int:
    """处理文件：提取并转换规则，仅保留纯净有效规则"""
    if not in_path.exists():
        logger.warning(f"文件不存在: {in_path}")
        return 0

    unique_rules: Set[str] = set()
    total = 0
    skipped = 0

    with in_path.open('r', encoding='utf-8') as fin, \
         out_path.open('w', encoding='utf-8') as fout:

        for line in fin:
            total += 1
            # 跳过空行和所有注释（核心：确保无任何注释进入输出）
            if Regex.SKIP_LINE.match(line.strip()):
                skipped += 1
                continue
            # 转换并验证规则
            rule, valid = converter(line.strip())
            if valid and rule:
                unique_rules.add(rule)
            else:
                skipped += 1

        # 写入去重后的纯净规则（无任何额外内容）
        fout.write('\n'.join(sorted(unique_rules)))

    logger.info(f"处理完成: 总{total} 有效{len(unique_rules)} 跳过{skipped}")
    return len(unique_rules)

def main():
    root = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    # 处理黑名单
    block_cnt = process_file(
        root / CONFIG["block"]["input"],
        root / CONFIG["block"]["output"],
        convert_block
    )
    # 处理白名单
    allow_cnt = process_file(
        root / CONFIG["allow"]["input"],
        root / CONFIG["allow"]["output"],
        convert_allow
    )
    logger.info(f"输出: {CONFIG['block']['output']}({block_cnt}), {CONFIG['allow']['output']}({allow_cnt})")

if __name__ == "__main__":
    main()
