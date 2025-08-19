#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard to Clash规则转换器 (最终版)
• 支持同路径allow.txt白名单
• 全语法覆盖 • 预编译正则 • 多线程处理
• 固定根目录路径 • 强制北京时间
"""

import re
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict, Pattern
from multiprocessing import Pool, cpu_count
import argparse

# === 常量配置 ===
BEIJING_TZ = 'Asia/Shanghai'
WHITELIST_FILE = "allow.txt"  # 白名单文件（与脚本同目录）

# 预编译正则表达式
RE_RULE_CLEAN = re.compile(r'[\^\$].*$')
RE_DOMAIN_EXTRACT = re.compile(r'^\|\|([^\^\$]+)')
RE_REGEX_RULE = re.compile(r'^/(.*)/[ims]*$')

# === 路径处理 ===
def get_io_paths() -> tuple[Path, Path, Path]:
    """获取输入/输出/白名单文件路径"""
    script_dir = Path(__file__).absolute().parent
    root_dir = script_dir.parent.parent if script_dir.parts[-2:] == ('data', 'python') else script_dir
    return (
        root_dir / "dns.txt",          # 输入文件
        root_dir / "ads.yaml",         # 输出文件
        script_dir / WHITELIST_FILE    # 白名单文件（与脚本同目录）
    )

# === 时间处理 ===
def beijing_time() -> str:
    """强制使用北京时间"""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(BEIJING_TZ)).strftime('%Y-%m-%d %H:%M:%S')
    except ImportError:
        import pytz
        return datetime.now(pytz.timezone(BEIJING_TZ)).strftime('%Y-%m-%d %H:%M:%S')

# === 白名单处理 ===
def load_whitelist(whitelist_path: Path) -> Set[str]:
    """加载白名单规则"""
    whitelist = set()
    if whitelist_path.exists():
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('!', '#')):
                    # 标准化白名单域名（去除修饰符）
                    domain = RE_RULE_CLEAN.sub('', line)
                    if domain.startswith('@@'):
                        domain = domain[2:]
                    whitelist.add(domain.lower())
    return whitelist

# === 核心转换器 ===
class RuleConverter:
    """AdGuard规则转换引擎（线程安全）"""
    
    def __init__(self, whitelist: Set[str]):
        self.whitelist = whitelist
    
    def convert(self, rule: str) -> str:
        """转换单条规则（主入口）"""
        rule = rule.strip()
        if not rule or rule.startswith(('!', '#')):
            return rule if rule.startswith('#') else f"# {rule[1:]}" if rule.startswith('!') else ""
        
        # 检查白名单
        clean_rule = RE_RULE_CLEAN.sub('', rule[2:] if rule.startswith('@@') else rule)
        if clean_rule.lower() in self.whitelist:
            return f"# Skipped (whitelist): {rule}"
        
        is_allow = rule.startswith('@@')
        clean_rule = rule[2:] if is_allow else rule
        
        # 处理各类型规则
        if clean_rule.startswith('||'):
            return self._handle_domain_suffix(clean_rule, is_allow)
        elif clean_rule.startswith('|'):
            return self._handle_exact_domain(clean_rule, is_allow)
        elif clean_rule.startswith('/') and clean_rule.endswith('/'):
            return self._handle_regex(clean_rule, is_allow)
        elif '*' in clean_rule:
            return self._handle_wildcard(clean_rule, is_allow)
        else:
            return self._handle_simple_domain(clean_rule, is_allow)
    
    @staticmethod
    def _handle_domain_suffix(rule: str, is_allow: bool) -> str:
        domain = RE_DOMAIN_EXTRACT.match(rule)
        if not domain:
            return ""
        domain = domain.group(1).strip('.')
        action = "DIRECT" if is_allow else "REJECT"
        return f"DOMAIN-SUFFIX,{domain},{action}"
    
    @staticmethod
    def _handle_exact_domain(rule: str, is_allow: bool) -> str:
        domain = RE_RULE_CLEAN.sub('', rule[1:])
        action = "DIRECT" if is_allow else "REJECT"
        return f"DOMAIN,{domain},{action}"
    
    @staticmethod
    def _handle_regex(rule: str, is_allow: bool) -> str:
        regex = RE_REGEX_RULE.match(rule)
        if not regex or len(regex.group(1)) < 3:
            return ""
        action = "DIRECT" if is_allow else "REJECT"
        return f"URL-REGEX,{regex.group(1)},{action}"
    
    @staticmethod
    def _handle_wildcard(rule: str, is_allow: bool) -> str:
        domain = RE_RULE_CLEAN.sub('', rule).replace('*', '')
        if not domain:
            return ""
        action = "DIRECT" if is_allow else "REJECT"
        return f"DOMAIN-KEYWORD,{domain},{action}"
    
    @staticmethod
    def _handle_simple_domain(rule: str, is_allow: bool) -> str:
        domain = RE_RULE_CLEAN.sub('', rule)
        if '.' in domain:
            action = "DIRECT" if is_allow else "REJECT"
            return f"DOMAIN-SUFFIX,{domain},{action}"
        return f"# Unsupported: {rule}"

# === 主处理器 ===
def process_rules(input_path: Path, output_path: Path, whitelist_path: Path) -> None:
    """规则处理流水线"""
    # 加载白名单
    whitelist = load_whitelist(whitelist_path)
    print(f"已加载白名单规则: {len(whitelist)}条")
    
    # 读取输入文件
    with open(input_path, 'r', encoding='utf-8') as f:
        rules = [line.strip() for line in f if line.strip()]
    
    # 多线程转换
    converter = RuleConverter(whitelist)
    with Pool(min(cpu_count(), 8)) as pool:
        converted = list(filter(None, pool.map(converter.convert, rules)))
    
    # 去重并排序
    unique_rules = sorted(set(converted), key=lambda x: (x.startswith('#'), x))
    
    # 生成YAML
    yaml_content = [
        f"# Generated: {beijing_time()} (北京时间)",
        f"# Whitelist: {whitelist_path}",
        "# Format: Clash/Mihomo RULE-SET",
        "payload:"
    ]
    yaml_content.extend(f"  - {r}" if not r.startswith('#') else r for r in unique_rules)
    
    # 写入输出
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(yaml_content))

# === 入口 ===
if __name__ == "__main__":
    input_path, output_path, whitelist_path = get_io_paths()
    
    print(f"脚本位置: {Path(__file__).absolute()}")
    print(f"输入文件: {input_path}")
    print(f"白名单文件: {whitelist_path}")
    print(f"输出文件: {output_path}")
    
    if not input_path.exists():
        print(f"错误: 输入文件不存在 {input_path}", file=sys.stderr)
        sys.exit(1)
    
    process_rules(input_path, output_path, whitelist_path)
    print(f"转换完成! 输出位置: {output_path}")