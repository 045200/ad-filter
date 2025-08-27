#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH规则转Clash/Surge/Mihomo工具（修复Hosts+通配符规则支持）
核心修复：1. 支持Hosts格式（0.0.0.0 域名）；2. 支持||xxx.*.com^通配符格式
"""

import os
import re
import subprocess
from typing import List, Tuple, Dict


# ==============================================================================
# 1. 核心配置（修复规则匹配正则）
# ==============================================================================
class Config:
    """全局配置类：统一管理输入输出路径、功能开关"""
    # -------------------------- 路径配置 --------------------------
    BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    INPUT = {
        "BLACKLIST": os.path.join(BASE_DIR, "adblock_adh.txt"),  # 对应REJECT
        "WHITELIST": os.path.join(BASE_DIR, "allow_adh.txt")     # 对应DIRECT
    }
    
    OUTPUT = {
        "CLASH_BLOCK": os.path.join(BASE_DIR, "adblock_clash.yaml"),
        "CLASH_ALLOW": os.path.join(BASE_DIR, "allow_clash.yaml"),
        "SURGE_BLOCK": os.path.join(BASE_DIR, "adblock_surge.conf"),
        "SURGE_ALLOW": os.path.join(BASE_DIR, "allow_surge.conf"),
        "MIHOMO": os.path.join(BASE_DIR, "adb.mrs")
    }
    
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")

    # -------------------------- 功能开关 --------------------------
    ENABLE_DEDUPLICATION = True
    ALLOW_AUTO_ADD_AT = False
    VERBOSE_LOG = False  # 调试时可设为True，查看每条规则匹配情况
    RULE_TYPE = "domain"

    # -------------------------- 规则过滤配置（核心修复点1：新增Hosts正则） --------------------------
    COMPATIBLE_MODIFIERS = {
        "third-party", "script", "image", "stylesheet", "font", "media",
        "xmlhttprequest", "ping", "websocket", "other", "subdocument",
        "document", "popup", "popup-block"
    }
    INCOMPATIBLE_MODIFIERS = {
        "redirect", "cookie", "header", "removeparam", "csp", "dnsrewrite",
        "dnsblock", "dnstype", "dnsrewrite-ip", "dnsrewrite-host"
    }

    UNSUPPORTED_RULE_PATTERNS = [
        re.compile(r'^##|^#@#|^#%#|^#?#'),                  # 元素隐藏/JS注入
        re.compile(r'\$(' + '|'.join(INCOMPATIBLE_MODIFIERS) + r')(?:=|,)'),  # 不可兼容修饰符
        re.compile(r'\$client=|\$server=|\$local=|\$important'),  # AGH定向标记
        re.compile(r'^\/[^/]*\/$'),                          # 无域名纯正则
        re.compile(r'^\|?https?://.*\?.*$'),                 # 含复杂参数URL
        re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$')  # 纯IP/CIDR（排除Hosts）
    ]

    # 核心修复点2：新增HOSTS规则、允许域名含*（适配||xxx.*.com^）
    SUPPORTED_RULE_PATTERNS = {
        "DOMAIN_DOUBLE_PIPE": re.compile(r'^@@?\|\|([a-zA-Z0-9-.*]+?)\^$'),  # 允许* → 匹配||0c4d3f6.*.com^
        "DOMAIN_WILDCARD": re.compile(r'^@@?\|\|*\.([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-]+)\^$'),  # 允许*
        "DOMAIN_PLAIN": re.compile(r'^@@?([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-]+)$'),  # 允许*
        "URL_FULL": re.compile(r'^@@?\|https?://([a-zA-Z0-9-.]*[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)(?::\d+)?/.*$'),
        "DOMAIN_WITH_MODIFIERS": re.compile(r'^@@?\|\|([a-zA-Z0-9-.*]+?)\^\$((?:[a-zA-Z0-9-]+)(?:,[a-zA-Z0-9-]+)*)$'),
        "URL_WITH_MODIFIERS": re.compile(r'^@@?\|https?://([a-zA-Z0-9-.]*[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)(?::\d+)?/.*\$((?:[a-zA-Z0-9-]+)(?:,[a-zA-Z0-9-]+)*)$'),
        "HOSTS_FORMAT": re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9-.*]+\.[a-zA-Z0-9-]+)$')  # 新增：匹配0.0.0.0 1.oadz.com
    }


# ==============================================================================
# 2. 工具函数（核心修复点3：优化域名校验，允许合法*）
# ==============================================================================
def is_valid_domain(domain: str) -> bool:
    """修复：允许域名含*（仅支持*.xxx.com、xxx.*.com格式，排除首尾*）"""
    domain = domain.strip()
    # 排除IP、特殊字符、首尾*、空域名
    if (not domain 
        or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)
        or re.search(r'[:/\\\s#,@]', domain)
        or domain.startswith('*') and not domain.startswith('*.')  # 禁止*xxx.com
        or domain.endswith('*')  # 禁止xxx.com*
        or domain.startswith('.') 
        or domain.endswith('.')):
        return False
    
    # 校验域名分段（允许*在中间，如xxx.*.com）
    parts = domain.split('.')
    if len(parts) < 2 or len(domain) > 253:
        return False
    for part in parts:
        if (not part 
            or len(part) > 63 
            or not re.match(r'^[a-zA-Z0-9-*]+$', part)  # 允许*
            or part.startswith('-') 
            or part.endswith('-')
            or part.count('*') > 1):  # 禁止多*（如xx**xx）
            return False
    
    return True


def is_unsupported_rule(rule: str) -> bool:
    return any(pattern.search(rule) for pattern in Config.UNSUPPORTED_RULE_PATTERNS)


def deduplicate_rules(rules: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    if not Config.ENABLE_DEDUPLICATION:
        return rules
    
    seen = set()
    deduped_rules = []
    for rule_type, target, action in rules:
        rule_key = f"{rule_type}|{target}|{action}"
        if rule_key not in seen:
            seen.add(rule_key)
            deduped_rules.append((rule_type, target, action))
    
    return deduped_rules


def write_file(content: List[str], file_path: str) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


def are_modifiers_compatible(modifier_str: str) -> Tuple[bool, List[str]]:
    modifiers = [m.strip() for m in modifier_str.split(',')]
    incompatible_mods = [m for m in modifiers if m not in Config.COMPATIBLE_MODIFIERS]
    return len(incompatible_mods) == 0, incompatible_mods


# ==============================================================================
# 3. 规则解析模块（无需修改，自动适配新增的正则）
# ==============================================================================
def parse_adguard_rules() -> Tuple[List[Tuple[str, str, str]], int, int, int, int]:
    valid_rules = []
    total_count = 0
    unsupported_count = 0
    compatible_mod_count = 0

    rule_sources = [
        (Config.INPUT["BLACKLIST"], "REJECT", "AGH黑名单"),
        (Config.INPUT["WHITELIST"], "DIRECT", "AGH白名单")
    ]

    for file_path, action, source_name in rule_sources:
        if not os.path.exists(file_path):
            print(f"⚠️  {source_name}文件不存在：{file_path}")
            continue

        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("!")]
            total_count += len(lines)
            print(f"\n📥 读取{source_name}：共{len(lines)}条规则")

            for rule in lines:
                if is_unsupported_rule(rule):
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  跳过不可兼容规则：{rule}")
                    continue

                original_rule = rule
                if action == "DIRECT" and Config.ALLOW_AUTO_ADD_AT and not rule.startswith("@@"):
                    rule = f"@@{rule}"
                    if Config.VERBOSE_LOG:
                        print(f"  ℹ️  补全白名单@@：{original_rule} → {rule}")

                matched = False
                domain = ""
                modifiers = ""
                for pattern_name, pattern in Config.SUPPORTED_RULE_PATTERNS.items():
                    match = pattern.match(rule)
                    if not match:
                        continue

                    # 处理Hosts格式（单独分支，无修饰符）
                    if pattern_name == "HOSTS_FORMAT":
                        domain = match.group(1).strip()
                    # 处理带修饰符的规则
                    elif pattern_name in ["DOMAIN_WITH_MODIFIERS", "URL_WITH_MODIFIERS"]:
                        domain = match.group(1).strip()
                        modifiers = match.group(2).strip()
                        is_compatible, incompatible_mods = are_modifiers_compatible(modifiers)
                        if not is_compatible:
                            unsupported_count += 1
                            if Config.VERBOSE_LOG:
                                print(f"  ⚠️  含不可兼容修饰符（{','.join(incompatible_mods)}）：{rule}")
                            break
                        compatible_mod_count += 1
                    # 处理其他格式
                    else:
                        domain = match.group(1).strip()

                    # 校验域名合法性（已修复支持*）
                    if not is_valid_domain(domain):
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无效域名：{domain}（规则：{rule}）")
                        break

                    # 添加有效规则（Hosts格式也标记为DOMAIN-SUFFIX，Clash支持）
                    valid_rules.append(("DOMAIN-SUFFIX", domain, action))
                    matched = True
                    if Config.VERBOSE_LOG:
                        log_msg = f"  ✅ 解析成功：{rule} → 域名[{domain}]（动作={action}）"
                        if modifiers:
                            log_msg += f"（忽略兼容修饰符[{modifiers}]）"
                        print(log_msg)
                    break

                if not matched:
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  无法提取域名：{rule}")

    # 去重
    before_dedup = len(valid_rules)
    valid_rules = deduplicate_rules(valid_rules)
    duplicate_count = before_dedup - len(valid_rules)
    if duplicate_count > 0:
        print(f"\n🔍 规则去重：移除{duplicate_count}条重复规则")

    return valid_rules, total_count, unsupported_count, duplicate_count, compatible_mod_count


# ==============================================================================
# 4. 规则转换模块（修复Clash通配符规则生成）
# ==============================================================================
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    clash_block = ["payload:"]
    clash_allow = ["payload:"]

    for rule_type, target, action in rules:
        if rule_type == "DOMAIN-SUFFIX":
            # 修复：若域名含*（如0c4d3f6.*.com），直接保留原格式（Clash支持）
            if "*" in target:
                clash_rule = f"  - '{target}'"
            # 普通域名用+.格式
            else:
                clash_rule = f"  - '+.{target}'"
            
            if action == "REJECT":
                clash_block.append(clash_rule)
            elif action == "DIRECT":
                clash_allow.append(clash_rule)

    # 空规则补默认
    if len(clash_block) == 1:
        clash_block.append("  - '+.example.com'")
    if len(clash_allow) == 1:
        clash_allow.append("  - '+.example.com'")

    return clash_block, clash_allow


def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    surge_block = []
    surge_allow = []

    for rule_type, target, action in rules:
        surge_policy = "REJECT" if action == "REJECT" else "DIRECT"
        # Surge支持通配符，直接生成规则
        surge_rule = f"{rule_type},{target},{surge_policy}"
        if action == "REJECT":
            surge_block.append(surge_rule)
        else:
            surge_allow.append(surge_rule)

    return surge_block, surge_allow


def compile_mihomo(clash_block_path: str) -> None:
    if not os.path.exists(Config.MIHOMO_TOOL):
        print(f"\n❌ Mihomo工具不存在：{Config.MIHOMO_TOOL}")
        return

    cmd = [
        Config.MIHOMO_TOOL, 
        "convert-ruleset", 
        Config.RULE_TYPE, 
        "yaml", 
        clash_block_path, 
        Config.OUTPUT["MIHOMO"]
    ]

    try:
        subprocess.run(
            cmd, 
            check=True, 
            capture_output=True, 
            text=True
        )
        mrs_size = os.path.getsize(Config.OUTPUT["MIHOMO"]) / 1024
        print(f"✅ Mihomo编译完成：{Config.OUTPUT['MIHOMO']}（{mrs_size:.2f} KB）")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr.strip()}")


# ==============================================================================
# 5. 主流程
# ==============================================================================
def main():
    print("=" * 60)
    print("📦 AGH规则→Clash/Surge/Mihomo 转换工具（已修复Hosts+通配符）")
    print("=" * 60)
    print(f"🔧 功能配置：去重={Config.ENABLE_DEDUPLICATION} | 白名单补@@={Config.ALLOW_AUTO_ADD_AT}")
    print(f"🔧 支持格式：||xxx.com^ | 0.0.0.0 xxx.com | ||xxx.*.com^")
    print(f"🔧 转换逻辑：AGH黑名单→REJECT | AGH白名单→DIRECT")
    print("=" * 60)

    # 步骤1：解析AGH规则
    print("\n【1/4】解析AGH规则文件...")
    valid_rules, total_count, unsupported_count, duplicate_count, compatible_mod_count = parse_adguard_rules()
    valid_count = len(valid_rules)
    conversion_rate = (valid_count / total_count * 100) if total_count > 0 else 0

    # 统计
    print(f"\n📊 解析统计：")
    print(f"  - 总规则数：{total_count} 条")
    print(f"  - 有效规则数：{valid_count} 条（转化率：{conversion_rate:.1f}%）")
    print(f"  - 不可支持数：{unsupported_count} 条")
    print(f"  - 重复规则数：{duplicate_count} 条")
    print(f"  - 兼容修饰符数：{compatible_mod_count} 条")

    if valid_count == 0:
        print("\n⚠️  无有效规则可转换，程序终止")
        return

    # 步骤2：转换Clash
    print("\n【2/4】转换为Clash规则...")
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT["CLASH_BLOCK"])
    write_file(clash_allow, Config.OUTPUT["CLASH_ALLOW"])
    print(f"✅ Clash规则生成：")
    print(f"  - 拦截规则：{len(clash_block)-1} 条 → {Config.OUTPUT['CLASH_BLOCK']}")
    print(f"  - 放行规则：{len(clash_allow)-1} 条 → {Config.OUTPUT['CLASH_ALLOW']}")

    # 步骤3：转换Surge
    print("\n【3/4】转换为Surge规则...")
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT["SURGE_BLOCK"])
    write_file(surge_allow, Config.OUTPUT["SURGE_ALLOW"])
    print(f"✅ Surge规则生成：")
    print(f"  - 拦截规则：{len(surge_block)} 条 → {Config.OUTPUT['SURGE_BLOCK']}")
    print(f"  - 放行规则：{len(surge_allow)} 条 → {Config.OUTPUT['SURGE_ALLOW']}")

    # 步骤4：编译Mihomo
    print("\n【4/4】编译Mihomo规则...")
    compile_mihomo(Config.OUTPUT["CLASH_BLOCK"])

    print("\n" + "=" * 60)
    print("🎉 所有转换任务完成！")
    print("✅ 已支持：Hosts格式（0.0.0.0 域名）、||xxx.*.com^通配符格式")
    print("=" * 60)


if __name__ == "__main__":
    main()
