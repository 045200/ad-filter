#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH规则转Clash/Surge工具（增强转换率版）
专注于生成Clash和Surge规则，Mihomo部分独立处理
"""

import os
import re
from typing import List, Tuple, Dict, Set, Pattern
from urllib.parse import urlparse

# ==============================================================================
# 1. 核心配置
# ==============================================================================
class Config:
    """全局配置类：统一管理输入输出路径、功能开关"""
    BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

    INPUT = {
        "BLACKLIST": os.path.join(BASE_DIR, "adblock_adh.txt"),  # 对应REJECT
        "WHITELIST": os.path.join(BASE_DIR, "allow_adh.txt")     # 对应DIRECT
    }

    OUTPUT = {
        "CLASH_BLOCK": os.path.join(BASE_DIR, "adblock_clash.yaml"),
        "CLASH_ALLOW": os.path.join(BASE_DIR, "allow_clash.yaml"),
        "SURGE_BLOCK": os.path.join(BASE_DIR, "adblock_surge.conf"),
        "SURGE_ALLOW": os.path.join(BASE_DIR, "allow_surge.conf")
    }

    # 功能开关
    ENABLE_DEDUPLICATION = True
    VERBOSE_LOG = False

    # 预编译正则表达式
    UNSUPPORTED_RULE_PATTERNS = [
        re.compile(r'^##|^#@#|^#%#|^#?#'),  # 元素隐藏/JS注入
        re.compile(r'\$(redirect|cookie|header|removeparam|csp|dnsrewrite|dnsblock|dnstype|dnsrewrite-ip|dnsrewrite-host)(?:=|,)'),  # 不可兼容修饰符
        re.compile(r'\$client=|\$server=|\$local=|\$important'),  # AGH定向标记
        re.compile(r'^\/[^/]*\/$'),  # 无域名纯正则
        re.compile(r'^\|?https?://.*\?.*$'),  # 含复杂参数URL
        re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$'),  # 纯IP/CIDR（排除Hosts）
        re.compile(r'^\!.*$'),  # 注释行
    ]

    # 支持的规则模式
    SUPPORTED_RULE_PATTERNS = {
        "DOMAIN_DOUBLE_PIPE": re.compile(r'^\|\|([a-zA-Z0-9-.*]+(?:\.[a-zA-Z0-9-.*]+)*)\^(?:\$.*)?$'),
        "DOMAIN_PLAIN": re.compile(r'^([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)(?:\^)?(?:\$.*)?$'),
        "URL_FULL": re.compile(r'^\|?https?://([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)(?::\d+)?/.*(?:\^)?(?:\$.*)?$'),
        "HOSTS_FORMAT": re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)$'),
        "EXCEPTION_RULE": re.compile(r'^@@\|\|([a-zA-Z0-9-.*]+(?:\.[a-zA-Z0-9-.*]+)*)\^(?:\$.*)?$'),
        "EXCEPTION_PLAIN": re.compile(r'^@@([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-.*]+)(?:\^)?(?:\$.*)?$'),
        "DOMAIN_KEYWORD": re.compile(r'^/([a-zA-Z0-9-.*]+)/$'),  # 关键字规则
    }


# ==============================================================================
# 2. 工具函数
# ==============================================================================
def is_valid_domain(domain: str) -> bool:
    """验证域名是否合法"""
    if not domain or domain.strip() == "":
        return False

    domain = domain.strip()

    # 排除纯IP地址
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
        return False

    # 排除包含非法字符的域名
    if re.search(r'[:/\\\s#,@]', domain):
        return False

    # 检查通配符位置
    if domain.startswith('*') and not domain.startswith('*.'):
        return False
    if domain.endswith('*'):
        return False

    # 检查开头和结尾的点
    if domain.startswith('.') or domain.endswith('.'):
        return False

    # 校验域名分段
    parts = domain.split('.')
    if len(parts) < 2:
        return False

    for part in parts:
        if not part or len(part) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9-*]+$', part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False

    return True


def extract_domain_from_url(url: str) -> str:
    """从URL中提取域名"""
    try:
        # 确保URL有协议头
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        return parsed.hostname or ''
    except:
        return ''


def extract_domain_from_pattern(pattern: str) -> str:
    """从模式中提取可能的域名"""
    # 移除常见的前缀和后缀
    clean_pattern = pattern.strip()

    # 移除开头和结尾的特殊字符
    clean_pattern = re.sub(r'^[\|@\*\^]+', '', clean_pattern)
    clean_pattern = re.sub(r'[\|@\*\^]+$', '', clean_pattern)

    # 尝试分割路径和参数
    clean_pattern = clean_pattern.split('/')[0]
    clean_pattern = clean_pattern.split('?')[0]
    clean_pattern = clean_pattern.split('$')[0]

    # 检查是否是有效域名
    if is_valid_domain(clean_pattern):
        return clean_pattern

    return ''


def is_unsupported_rule(rule: str) -> bool:
    """检查规则是否不支持"""
    return any(pattern.search(rule) for pattern in Config.UNSUPPORTED_RULE_PATTERNS)


def normalize_domain(domain: str) -> str:
    """规范化域名，用于去重比较"""
    if not domain:
        return ""

    domain = domain.lower()

    # 移除开头的通配符和点
    if domain.startswith('*.'):
        domain = domain[2:]
    # 移除末尾的^等符号
    if domain.endswith('^'):
        domain = domain[:-1]

    return domain


def deduplicate_rules(rules: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """去重规则，考虑主域名和子域名的关系"""
    if not Config.ENABLE_DEDUPLICATION:
        return rules

    # 使用字典存储规则，键为规范化后的域名
    rule_dict = {}

    for rule_type, target, action in rules:
        norm_target = normalize_domain(target)

        if not norm_target:
            continue

        # 如果已经存在规则，保留更具体的规则
        if norm_target in rule_dict:
            existing_rule = rule_dict[norm_target]
            existing_has_wildcard = '*' in existing_rule[1]
            current_has_wildcard = '*' in target

            if not current_has_wildcard and existing_has_wildcard:
                # 当前规则更具体，替换现有规则
                rule_dict[norm_target] = (rule_type, target, action)
            # 如果两个规则都有通配符或都没有，保留第一个
        else:
            rule_dict[norm_target] = (rule_type, target, action)

    return list(rule_dict.values())


def write_file(content: List[str], file_path: str) -> None:
    """写入文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


# ==============================================================================
# 3. 规则解析模块
# ==============================================================================
def parse_adguard_rules() -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]], int, int, int, int]:
    """解析AGH规则文件，分别返回黑名单规则和白名单规则"""
    black_rules = []  # REJECT规则
    white_rules = []  # DIRECT规则
    total_count = 0
    unsupported_count = 0
    duplicate_count_black = 0
    duplicate_count_white = 0

    # 处理黑名单文件
    if os.path.exists(Config.INPUT["BLACKLIST"]):
        with open(Config.INPUT["BLACKLIST"], "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            total_count += len(lines)
            print(f"\n📥 读取AGH黑名单：共{len(lines)}条规则")

            for rule in lines:
                # 跳过注释行
                if rule.startswith("!"):
                    continue

                if is_unsupported_rule(rule):
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  跳过不可兼容规则：{rule}")
                    continue

                # 确定规则动作（黑名单中@@开头的是例外规则，转为DIRECT）
                if rule.startswith("@@"):
                    action = "DIRECT"
                    rule_for_matching = rule[2:]
                else:
                    action = "REJECT"
                    rule_for_matching = rule

                matched = False
                domain = ""

                # 尝试匹配各种支持的规则模式
                for pattern_name, pattern in Config.SUPPORTED_RULE_PATTERNS.items():
                    match = pattern.match(rule_for_matching)
                    if not match:
                        continue

                    # 处理不同的模式
                    if pattern_name == "HOSTS_FORMAT":
                        domain = match.group(1).strip()
                    elif pattern_name in ["DOMAIN_DOUBLE_PIPE", "DOMAIN_PLAIN", 
                                         "EXCEPTION_RULE", "EXCEPTION_PLAIN"]:
                        domain = match.group(1).strip()
                    elif pattern_name == "URL_FULL":
                        domain = match.group(1).strip()
                    elif pattern_name == "DOMAIN_KEYWORD":
                        # 关键字规则，直接使用整个模式
                        keyword = match.group(1).strip()
                        if keyword and len(keyword) > 3:  # 关键字长度阈值
                            # 添加到相应的规则列表
                            if action == "REJECT":
                                black_rules.append(("DOMAIN-KEYWORD", keyword, action))
                            else:
                                white_rules.append(("DOMAIN-KEYWORD", keyword, action))
                            matched = True
                        break
                    else:
                        continue

                    # 校验域名合法性
                    if not domain or not is_valid_domain(domain):
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无效域名：{domain}（规则：{rule}）")
                        break

                    # 添加到相应的规则列表
                    if action == "REJECT":
                        black_rules.append(("DOMAIN-SUFFIX", domain, action))
                    else:
                        white_rules.append(("DOMAIN-SUFFIX", domain, action))

                    matched = True

                    if Config.VERBOSE_LOG:
                        print(f"  ✅ 解析成功：{rule} → 域名[{domain}]（动作={action}）")
                    break

                if not matched:
                    # 尝试处理其他格式的规则
                    domain = extract_domain_from_url(rule_for_matching)
                    if not domain:
                        domain = extract_domain_from_pattern(rule_for_matching)

                    if domain and is_valid_domain(domain):
                        if action == "REJECT":
                            black_rules.append(("DOMAIN-SUFFIX", domain, action))
                        else:
                            white_rules.append(("DOMAIN-SUFFIX", domain, action))
                        if Config.VERBOSE_LOG:
                            print(f"  ✅ 通过通用解析成功：{rule} → 域名[{domain}]（动作={action}）")
                    else:
                        unsupported_count += 1
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无法提取域名：{rule}")

    # 处理白名单文件
    if os.path.exists(Config.INPUT["WHITELIST"]):
        with open(Config.INPUT["WHITELIST"], "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            total_count += len(lines)
            print(f"\n📥 读取AGH白名单：共{len(lines)}条规则")

            for rule in lines:
                # 跳过注释行
                if rule.startswith("!"):
                    continue

                if is_unsupported_rule(rule):
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  跳过不可兼容规则：{rule}")
                    continue

                # 白名单规则默认动作是DIRECT
                action = "DIRECT"
                rule_for_matching = rule[2:] if rule.startswith("@@") else rule

                matched = False
                domain = ""

                # 尝试匹配各种支持的规则模式
                for pattern_name, pattern in Config.SUPPORTED_RULE_PATTERNS.items():
                    match = pattern.match(rule_for_matching)
                    if not match:
                        continue

                    # 处理不同的模式
                    if pattern_name == "HOSTS_FORMAT":
                        domain = match.group(1).strip()
                    elif pattern_name in ["DOMAIN_DOUBLE_PIPE", "DOMAIN_PLAIN", 
                                         "EXCEPTION_RULE", "EXCEPTION_PLAIN"]:
                        domain = match.group(1).strip()
                    elif pattern_name == "URL_FULL":
                        domain = match.group(1).strip()
                    elif pattern_name == "DOMAIN_KEYWORD":
                        # 关键字规则，直接使用整个模式
                        keyword = match.group(1).strip()
                        if keyword and len(keyword) > 3:  # 关键字长度阈值
                            white_rules.append(("DOMAIN-KEYWORD", keyword, action))
                            matched = True
                        break
                    else:
                        continue

                    # 校验域名合法性
                    if not domain or not is_valid_domain(domain):
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无效域名：{domain}（规则：{rule}）")
                        break

                    # 添加到白名单规则列表
                    white_rules.append(("DOMAIN-SUFFIX", domain, action))
                    matched = True

                    if Config.VERBOSE_LOG:
                        print(f"  ✅ 解析成功：{rule} → 域名[{domain}]（动作={action}）")
                    break

                if not matched:
                    # 尝试处理其他格式的规则
                    domain = extract_domain_from_url(rule_for_matching)
                    if not domain:
                        domain = extract_domain_from_pattern(rule_for_matching)

                    if domain and is_valid_domain(domain):
                        white_rules.append(("DOMAIN-SUFFIX", domain, action))
                        if Config.VERBOSE_LOG:
                            print(f"  ✅ 通过通用解析成功：{rule} → 域名[{domain}]（动作={action}）")
                    else:
                        unsupported_count += 1
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无法提取域名：{rule}")

    # 分别去重黑名单和白名单规则
    before_dedup_black = len(black_rules)
    black_rules = deduplicate_rules(black_rules)
    duplicate_count_black = before_dedup_black - len(black_rules)

    before_dedup_white = len(white_rules)
    white_rules = deduplicate_rules(white_rules)
    duplicate_count_white = before_dedup_white - len(white_rules)

    return black_rules, white_rules, total_count, unsupported_count, duplicate_count_black, duplicate_count_white


# ==============================================================================
# 4. 规则转换模块
# ==============================================================================
def convert_to_clash(black_rules: List[Tuple[str, str, str]], white_rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """转换为Clash规则格式（使用隐式语法）"""
    clash_block = ["payload:"]
    clash_allow = ["payload:"]

    # 处理黑名单规则
    for rule_type, target, action in black_rules:
        if rule_type == "DOMAIN-SUFFIX":
            if target.startswith('*'):
                # 通配符规则直接使用
                clash_rule = f"  - '{target}'"
            else:
                # 普通域名使用隐式语法
                clash_rule = f"  - '+.{target}'"
            clash_block.append(clash_rule)
        elif rule_type == "DOMAIN-KEYWORD":
            clash_rule = f"  - '{target}'"
            clash_block.append(clash_rule)

    # 处理白名单规则
    for rule_type, target, action in white_rules:
        if rule_type == "DOMAIN-SUFFIX":
            if target.startswith('*'):
                clash_rule = f"  - '{target}'"
            else:
                clash_rule = f"  - '+.{target}'"
            clash_allow.append(clash_rule)
        elif rule_type == "DOMAIN-KEYWORD":
            clash_rule = f"  - '{target}'"
            clash_allow.append(clash_rule)

    # 空规则补默认
    if len(clash_block) == 1:
        clash_block.append("  - '+.example.com'")
    if len(clash_allow) == 1:
        clash_allow.append("  - '+.example.com'")

    return clash_block, clash_allow


def convert_to_surge(black_rules: List[Tuple[str, str, str]], white_rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """转换为Surge规则格式"""
    surge_block = []
    surge_allow = []

    # 处理黑名单规则
    for rule_type, target, action in black_rules:
        if rule_type == "DOMAIN-SUFFIX":
            surge_rule = f"DOMAIN-SUFFIX,{target},REJECT"
            surge_block.append(surge_rule)
        elif rule_type == "DOMAIN-KEYWORD":
            surge_rule = f"DOMAIN-KEYWORD,{target},REJECT"
            surge_block.append(surge_rule)

    # 处理白名单规则
    for rule_type, target, action in white_rules:
        if rule_type == "DOMAIN-SUFFIX":
            surge_rule = f"DOMAIN-SUFFIX,{target},DIRECT"
            surge_allow.append(surge_rule)
        elif rule_type == "DOMAIN-KEYWORD":
            surge_rule = f"DOMAIN-KEYWORD,{target},DIRECT"
            surge_allow.append(surge_rule)

    return surge_block, surge_allow


# ==============================================================================
# 5. 主流程
# ==============================================================================
def main():
    print("=" * 60)
    print("📦 AGH规则→Clash/Surge 转换工具（增强转换率版）")
    print("=" * 60)
    print(f"🔧 功能配置：去重={Config.ENABLE_DEDUPLICATION}")
    print(f"🔧 支持格式：||xxx.com^ | 0.0.0.0 xxx.com | ||xxx.*.com^ | 关键字规则")
    print("=" * 60)

    # 步骤1：解析AGH规则
    print("\n【1/3】解析AGH规则文件...")
    black_rules, white_rules, total_count, unsupported_count, dup_black, dup_white = parse_adguard_rules()

    black_count = len(black_rules)
    white_count = len(white_rules)
    conversion_rate = ((black_count + white_count) / total_count * 100) if total_count > 0 else 0

    # 统计
    print(f"\n📊 解析统计：")
    print(f"  - 总规则数：{total_count} 条")
    print(f"  - 黑名单规则：{black_count} 条")
    print(f"  - 白名单规则：{white_count} 条")
    print(f"  - 总有效规则：{black_count + white_count} 条（转化率：{conversion_rate:.1f}%）")
    print(f"  - 不可支持数：{unsupported_count} 条")
    print(f"  - 黑名单去重：{dup_black} 条")
    print(f"  - 白名单去重：{dup_white} 条")

    if black_count == 0 and white_count == 0:
        print("\n⚠️  无有效规则可转换，程序终止")
        return

    # 步骤2：转换Clash
    print("\n【2/3】转换为Clash规则...")
    clash_block, clash_allow = convert_to_clash(black_rules, white_rules)
    write_file(clash_block, Config.OUTPUT["CLASH_BLOCK"])
    write_file(clash_allow, Config.OUTPUT["CLASH_ALLOW"])
    print(f"✅ Clash规则生成：")
    print(f"  - 拦截规则：{len(clash_block)-1} 条 → {Config.OUTPUT['CLASH_BLOCK']}")
    print(f"  - 放行规则：{len(clash_allow)-1} 条 → {Config.OUTPUT['CLASH_ALLOW']}")

    # 步骤3：转换Surge
    print("\n【3/3】转换为Surge规则...")
    surge_block, surge_allow = convert_to_surge(black_rules, white_rules)
    write_file(surge_block, Config.OUTPUT["SURGE_BLOCK"])
    write_file(surge_allow, Config.OUTPUT["SURGE_ALLOW"])
    print(f"✅ Surge规则生成：")
    print(f"  - 拦截规则：{len(surge_block)} 条 → {Config.OUTPUT['SURGE_BLOCK']}")
    print(f"  - 放行规则：{len(surge_allow)} 条 → {Config.OUTPUT['SURGE_ALLOW']}")

    print("\n" + "=" * 60)
    print("🎉 Clash/Surge转换任务完成！")
    print("📝 Mihomo规则集需要单独处理，请运行mihomo_converter.py")
    print("=" * 60)


if __name__ == "__main__":
    main()