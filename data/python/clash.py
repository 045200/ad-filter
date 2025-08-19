#!/usr/bin/env python3
"""
AdGuard规则转换器 (Clash/Mihomo兼容版)
• 支持完整AdGuard语法 | 高性能转换 | 自动过滤无效规则
• 输入: 根目录/dns.txt
• 输出: 根目录/ads.yaml
"""

import os
import re
import sys
from datetime import datetime
from typing import List, Tuple, Optional
from pathlib import Path

# 配置区
INPUT_FILE = "dns.txt"           # 根目录输入文件
OUTPUT_FILE = "ads.yaml"          # 根目录输出文件
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())  # 统一工作区路径

# 预编译正则表达式 - 提升性能
COMMENT_PATTERN = re.compile(r'^[!#]')
META_PATTERN = re.compile(r'^\[.*\]$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')
WILDCARD_PATTERN = re.compile(r'^\*\.([a-zA-Z0-9.-]+)$')
ADGUARD_DOMAIN_PATTERN = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^?$')

# 时区处理
try:
    from zoneinfo import ZoneInfo
    beijing_tz = ZoneInfo("Asia/Shanghai")
except ImportError:
    import pytz
    beijing_tz = pytz.timezone("Asia/Shanghai")

def convert_adguard_rule(adguard_rule: str) -> Optional[str]:
    """
    高性能AdGuard规则转换
    返回: Clash兼容规则 或 None(无效规则)
    """
    stripped_rule = adguard_rule.strip()
    
    # 处理空行
    if not stripped_rule:
        return None
    
    # 处理注释
    if COMMENT_PATTERN.match(stripped_rule):
        return f"# {stripped_rule[1:].strip()}"
    
    # 忽略元信息行
    if META_PATTERN.match(stripped_rule):
        return None
    
    # 提取规则主体和选项
    rule_body, options = parse_rule(stripped_rule)
    if not rule_body:
        return None
    
    # 检查是否支持选项
    if options and not is_supported_option(options):
        return None
    
    # 确定策略类型
    is_whitelist = rule_body.startswith('@@')
    action = "DIRECT" if is_whitelist else "REJECT"
    rule_body = rule_body[2:] if is_whitelist else rule_body
    
    # 转换规则类型
    return convert_rule_body(rule_body, action)

def parse_rule(full_rule: str) -> Tuple[Optional[str], Optional[str]]:
    """分离规则主体和选项部分"""
    if '$' in full_rule:
        parts = full_rule.split('$', 1)
        return parts[0].strip(), parts[1].strip()
    return full_rule.strip(), None

def is_supported_option(options: str) -> bool:
    """检查是否支持AdGuard选项"""
    # 支持的选项列表（黑名单方式）
    unsupported_options = {
        'dnstype', 'dnsrewrite', 'cname', 'important', 
        'redirect', 'app', 'extension', 'document'
    }
    
    # 检查是否包含不支持选项
    for opt in options.split(','):
        opt_name = opt.strip().split('=')[0]
        if opt_name in unsupported_options:
            return False
    return True

def convert_rule_body(rule_body: str, action: str) -> Optional[str]:
    """转换规则主体为Clash格式"""
    # 处理通配符规则 (*.example.com)
    if wildcard_match := WILDCARD_PATTERN.match(rule_body):
        return f"DOMAIN-SUFFIX,{wildcard_match.group(1)},{action}"
    
    # 处理AdGuard域名规则 (||example.com^)
    if domain_match := ADGUARD_DOMAIN_PATTERN.match(rule_body):
        return f"DOMAIN-SUFFIX,{domain_match.group(1)},{action}"
    
    # 处理纯域名规则 (example.com)
    if DOMAIN_PATTERN.match(rule_body):
        if '.' in rule_body:
            return f"DOMAIN-SUFFIX,{rule_body},{action}"
        return f"DOMAIN,{rule_body},{action}"
    
    # 跳过正则规则和其他复杂规则
    return None

def generate_ads_yaml() -> bool:
    """生成ads.yaml文件 - 返回是否成功"""
    input_path = Path(WORKSPACE) / INPUT_FILE
    output_path = Path(WORKSPACE) / OUTPUT_FILE
    
    # 验证输入文件
    if not input_path.exists():
        print(f"错误：输入文件不存在: {input_path}")
        return False
    
    # 读取并转换规则
    converted_rules = set()
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if converted := convert_adguard_rule(line):
                    converted_rules.add(converted)
    except Exception as e:
        print(f"文件处理错误: {e}")
        return False
    
    # 准备YAML内容
    beijing_time = datetime.now(beijing_tz)
    time_str = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
    
    yaml_content = [
        "# Title: AdGuard 转换的广告过滤规则集",
        f"# Update time: {time_str} 北京时间",
        "# Source: https://github.045200/EasyAds",
        "# Script location: 每12小时更新一次，有问题提交issues",
        "# Compatible: Clash / Mihomo",
        "",
        "payload:"
    ]
    
    # 添加规则并排序
    sorted_rules = sorted(converted_rules)
    for rule in sorted_rules:
        if rule.startswith('#'):
            yaml_content.append(rule)
        else:
            yaml_content.append(f"  - {rule}")
    
    # 写入输出文件
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(yaml_content))
        print(f"转换成功！生成规则文件: {output_path}")
        print(f"有效规则数量: {len(sorted_rules)}")
        return True
    except Exception as e:
        print(f"写入文件失败: {e}")
        return False

if __name__ == "__main__":
    print("🚀 AdGuard规则转换器启动")
    print(f"工作目录: {WORKSPACE}")
    
    if generate_ads_yaml():
        sys.exit(0)
    else:
        sys.exit(1)