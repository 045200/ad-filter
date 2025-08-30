#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo规则转换工具 - GitHub Actions优化版
支持AdGuard Home语法，输出Clash/Mihomo兼容规则
针对GitHub Actions环境优化，仅终端打印，只生成adb.mrs文件
"""

import os
import re
import sys
import subprocess
from typing import List, Set, Dict, Any, Tuple

# ==============================================================================
# 配置
# ==============================================================================
class Config:
    BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

    INPUT = {
        "BLACKLIST": os.path.join(BASE_DIR, "adblock_adh.txt"),
        "WHITELIST": os.path.join(BASE_DIR, "allow_adh.txt")
    }

    OUTPUT = {
        "MIHOMO": os.path.join(BASE_DIR, "adb.mrs"),
        "TEMP_CLASH": os.path.join(BASE_DIR, "temp_clash.yaml")
    }

    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")

    # 广告相关关键词（用于识别广告子域名）
    AD_KEYWORDS = ['ad', 'ads', 'advert', 'advertising', 'track', 'tracking', 
                  'analytics', 'metric', 'pixel', 'beacon', 'doubleclick', 
                  'googlead', 'facebookad', 'affiliate', 'promo', 'banner']

    # AdGuard规则类型映射
    AG_RULE_TYPES = {
        'domain': r'^\|\|([^\^]+)\^',
        'exact': r'^\|([^\^]+)\^',
        'regex': r'^/(.+)/$',
        'element': r'^##',
        'exception': r'^@@'
    }


# ==============================================================================
# 日志函数 - 仅终端输出
# ==============================================================================
def log_info(message: str):
    """输出信息日志"""
    print(f"ℹ️  {message}")


def log_success(message: str):
    """输出成功日志"""
    print(f"✅ {message}")


def log_warning(message: str):
    """输出警告日志"""
    print(f"⚠️  {message}")


def log_error(message: str):
    """输出错误日志"""
    print(f"❌ {message}")


def log_debug(message: str):
    """输出调试日志"""
    if os.getenv('ENABLE_DEBUG') == 'true':
        print(f"🐛 {message}")


# ==============================================================================
# AdGuard Home规则处理
# ==============================================================================
def parse_adguard_rule(rule: str) -> Dict[str, Any]:
    """解析AdGuard Home规则，返回规则类型和内容"""
    rule = rule.strip()
    result = {'original': rule, 'type': 'unknown', 'content': ''}
    
    # 跳过注释和空行
    if not rule or rule.startswith('!') or rule.startswith('#'):
        result['type'] = 'comment'
        return result
    
    # 检查规则类型
    for rule_type, pattern in Config.AG_RULE_TYPES.items():
        if re.match(pattern, rule):
            result['type'] = rule_type
            break
    
    # 提取规则内容
    if result['type'] == 'domain':
        match = re.match(Config.AG_RULE_TYPES['domain'], rule)
        if match:
            result['content'] = match.group(1)
    elif result['type'] == 'exact':
        match = re.match(Config.AG_RULE_TYPES['exact'], rule)
        if match:
            result['content'] = match.group(1)
    elif result['type'] == 'exception':
        # 处理例外规则(@@)
        result['content'] = rule[2:]
    else:
        result['content'] = rule
    
    return result


def extract_domains_from_adguard_rules(file_path: str) -> Tuple[Set[str], Dict[str, int]]:
    """从AdGuard Home规则文件中提取域名"""
    domains = set()
    rule_stats = {'total': 0, 'domain_rules': 0, 'other_rules': 0}

    if not os.path.exists(file_path):
        log_warning(f"文件不存在: {file_path}")
        return domains, rule_stats

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                rule_stats['total'] += 1
                parsed = parse_adguard_rule(line)
                
                if parsed['type'] == 'comment':
                    continue
                elif parsed['type'] == 'domain':
                    domains.add(parsed['content'])
                    rule_stats['domain_rules'] += 1
                else:
                    rule_stats['other_rules'] += 1
                    # 对于非域名规则，尝试提取可能包含的域名
                    if re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+', parsed['content']):
                        domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)', parsed['content'])
                        if domain_match:
                            domains.add(domain_match.group(1))

    except Exception as e:
        log_error(f"读取文件时出错 {file_path}: {e}")

    return domains, rule_stats


# ==============================================================================
# 域名处理和过滤
# ==============================================================================
def is_valid_domain(domain: str) -> bool:
    """验证域名是否合法"""
    if not domain or domain.strip() == "":
        return False

    domain = domain.strip()

    # 排除纯IP地址
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
        return False

    # 基本域名格式检查
    if not re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z0-9.*-]+$', domain):
        return False

    # 检查通配符位置
    if domain.startswith('*') and not domain.startswith('*.'):
        return False

    return True


def is_ad_subdomain(subdomain: str) -> bool:
    """检查域名是否是广告相关的子域名"""
    subdomain_lower = subdomain.lower()
    for keyword in Config.AD_KEYWORDS:
        if keyword in subdomain_lower:
            return True
    return False


def filter_domains(black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
    """使用白名单过滤黑名单域名"""
    filtered_domains = set()
    
    for black_domain in black_domains:
        # 检查是否在白名单中
        if black_domain in white_domains:
            log_debug(f"过滤域名 (精确匹配): {black_domain}")
            continue
            
        # 检查是否是白名单域名的子域名（但排除广告子域名）
        whitelisted = False
        for white_domain in white_domains:
            if (black_domain == white_domain or 
                black_domain.endswith('.' + white_domain)):
                if is_ad_subdomain(black_domain):
                    # 广告子域名不过滤
                    log_debug(f"保留广告子域名: {black_domain} (白名单: {white_domain})")
                    continue
                else:
                    whitelisted = True
                    log_debug(f"过滤域名 (子域名匹配): {black_domain} (白名单: {white_domain})")
                    break
        
        if not whitelisted:
            filtered_domains.add(black_domain)
    
    return filtered_domains


# ==============================================================================
# Clash/Mihomo规则生成
# ==============================================================================
def convert_to_clash_rules(domains: Set[str]) -> List[str]:
    """将域名集合转换为Clash规则，按优先级排序"""
    exact_rules = []    # 精确域名匹配
    suffix_rules = []   # 域名后缀匹配
    
    for domain in domains:
        if domain.startswith('*.'):
            # 通配符域名 -> DOMAIN-SUFFIX规则
            base_domain = domain[2:]
            suffix_rules.append(f"DOMAIN-SUFFIX,{base_domain},REJECT")
        elif re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+$', domain):
            # 普通域名 -> DOMAIN-SUFFIX规则（匹配域名及其子域）
            suffix_rules.append(f"DOMAIN-SUFFIX,{domain},REJECT")
        else:
            # 其他情况 -> DOMAIN规则（精确匹配）
            exact_rules.append(f"DOMAIN,{domain},REJECT")
    
    # 按Clash推荐的优先级排序：精确匹配优先，然后是后缀匹配
    return exact_rules + suffix_rules


def create_clash_yaml(rules: List[str], output_path: str) -> None:
    """创建Clash格式的YAML文件"""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("payload:\n")
            for rule in rules:
                f.write(f"  - {rule}\n")
        log_info(f"Clash临时文件创建成功: {output_path}")
    except Exception as e:
        log_error(f"创建Clash临时文件失败: {e}")
        raise


# ==============================================================================
# Mihomo编译
# ==============================================================================
def compile_mihomo(clash_yaml_path: str, output_path: str) -> bool:
    """使用mihomo-tool编译规则集"""
    if not os.path.exists(Config.MIHOMO_TOOL):
        log_error(f"Mihomo工具不存在: {Config.MIHOMO_TOOL}")
        return False

    cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        "domain",
        "yaml",
        clash_yaml_path,
        output_path
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.returncode == 0:
            log_success("Mihomo编译成功")
            return True
        else:
            log_error(f"Mihomo编译失败: {result.stderr}")
            return False
    except subprocess.CalledProcessError as e:
        log_error(f"Mihomo编译异常: {e.stderr if e.stderr else e}")
        return False
    except Exception as e:
        log_error(f"Mihomo执行异常: {e}")
        return False


# ==============================================================================
# 主流程
# ==============================================================================
def main():
    # 检查是否在GitHub Actions环境中运行
    github_actions = os.getenv('GITHUB_ACTIONS') == 'true'
    
    if github_actions:
        log_info("在GitHub Actions环境中运行Mihomo规则转换")
    else:
        log_info("在本地环境中运行Mihomo规则转换")
    
    log_info("开始处理规则文件...")

    # 步骤1：提取域名
    log_info("【1/4】提取AdGuard Home规则域名...")
    black_domains, black_stats = extract_domains_from_adguard_rules(Config.INPUT["BLACKLIST"])
    white_domains, white_stats = extract_domains_from_adguard_rules(Config.INPUT["WHITELIST"])

    log_info(f"📊 提取统计:")
    log_info(f"  黑名单: {len(black_domains)} 个域名 (共 {black_stats['total']} 条规则)")
    log_info(f"  白名单: {len(white_domains)} 个域名 (共 {white_stats['total']} 条规则)")

    # 步骤2：过滤黑名单
    log_info("【2/4】使用白名单过滤黑名单...")
    filtered_domains = filter_domains(black_domains, white_domains)
    
    filtered_count = len(black_domains) - len(filtered_domains)
    log_info(f"📊 过滤统计:")
    log_info(f"  过滤前: {len(black_domains)} 个域名")
    log_info(f"  过滤后: {len(filtered_domains)} 个域名")
    log_info(f"  过滤掉: {filtered_count} 个域名")

    # 步骤3：转换为Clash规则并创建临时文件
    log_info("【3/4】转换为Clash规则并创建临时文件...")
    clash_rules = convert_to_clash_rules(filtered_domains)
    create_clash_yaml(clash_rules, Config.OUTPUT["TEMP_CLASH"])

    # 步骤4：编译Mihomo规则集
    log_info("【4/4】编译Mihomo规则集...")
    if compile_mihomo(Config.OUTPUT["TEMP_CLASH"], Config.OUTPUT["MIHOMO"]):
        mrs_size = os.path.getsize(Config.OUTPUT["MIHOMO"]) / 1024 if os.path.exists(Config.OUTPUT["MIHOMO"]) else 0
        log_success(f"Mihomo规则集生成成功: {Config.OUTPUT['MIHOMO']} ({mrs_size:.2f} KB)")
    else:
        log_error("Mihomo规则集生成失败")
        sys.exit(1)

    # 清理临时文件
    if os.path.exists(Config.OUTPUT["TEMP_CLASH"]):
        os.remove(Config.OUTPUT["TEMP_CLASH"])
        log_info(f"已清理临时文件: {Config.OUTPUT['TEMP_CLASH']}")

    log_info("🎉 Mihomo转换任务完成！")


if __name__ == "__main__":
    main()