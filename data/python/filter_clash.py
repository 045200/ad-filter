#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH规则转Clash/Surge/Mihomo工具
核心特性：
1. Clash产物仅保留payload及规则列表（策略由Clash主体处理）
2. 自动区分：AGH黑名单→REJECT（拦截）、AGH白名单→DIRECT（放行）
3. 规则过滤：剔除不可兼容修饰符/无效域名/重复规则
4. 支持Surge标准格式、Mihomo(.mrs)编译输出
"""

import os
import re
import subprocess
from typing import List, Tuple, Dict


# ==============================================================================
# 1. 核心配置（可按需修改，按功能分组）
# ==============================================================================
class Config:
    """全局配置类：统一管理输入输出路径、功能开关"""
    # -------------------------- 路径配置 --------------------------
    BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())  # 基础路径（兼容GitHub Actions）
    
    # 输入：AGH纯净规则文件（无文件头，黑名单=拦截，白名单=放行）
    INPUT = {
        "BLACKLIST": os.path.join(BASE_DIR, "adblock_adh.txt"),  # 对应REJECT
        "WHITELIST": os.path.join(BASE_DIR, "allow_adh.txt")     # 对应DIRECT
    }
    
    # 输出：各格式规则文件路径
    OUTPUT = {
        "CLASH_BLOCK": os.path.join(BASE_DIR, "adblock_clash.yaml"),  # Clash拦截规则
        "CLASH_ALLOW": os.path.join(BASE_DIR, "allow_clash.yaml"),    # Clash放行规则
        "SURGE_BLOCK": os.path.join(BASE_DIR, "adblock_surge.conf"),  # Surge拦截规则
        "SURGE_ALLOW": os.path.join(BASE_DIR, "allow_surge.conf"),    # Surge放行规则
        "MIHOMO": os.path.join(BASE_DIR, "adb.mrs")                   # Mihomo规则
    }
    
    # Mihomo编译工具路径（需提前下载官方工具）
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")

    # -------------------------- 功能开关 --------------------------
    ENABLE_DEDUPLICATION = True    # 启用规则去重
    ALLOW_AUTO_ADD_AT = False      # 白名单不自动补全@@（依赖AGH原生规则）
    VERBOSE_LOG = False            # 启用详细日志（调试用）
    RULE_TYPE = "domain"           # 规则类型（固定为domain）

    # -------------------------- 规则过滤配置 --------------------------
    # 1.1 可兼容/不可兼容修饰符（AGH→Clash仅保留兼容项）
    COMPATIBLE_MODIFIERS = {
        "third-party", "script", "image", "stylesheet", "font", "media",
        "xmlhttprequest", "ping", "websocket", "other", "subdocument",
        "document", "popup", "popup-block"
    }
    INCOMPATIBLE_MODIFIERS = {
        "redirect", "cookie", "header", "removeparam", "csp", "dnsrewrite",
        "dnsblock", "dnstype", "dnsrewrite-ip", "dnsrewrite-host"
    }

    # 1.2 不可支持规则正则（用于过滤无效规则）
    UNSUPPORTED_RULE_PATTERNS = [
        re.compile(r'^##|^#@#|^#%#|^#?#'),                  # 元素隐藏/JS注入规则
        re.compile(r'\$(' + '|'.join(INCOMPATIBLE_MODIFIERS) + r')(?:=|,)'),  # 不可兼容修饰符
        re.compile(r'\$client=|\$server=|\$local=|\$important'),  # AGH定向/优先级标记
        re.compile(r'^\/[^/]*\/$'),                          # 无域名纯正则规则
        re.compile(r'^\|?https?://.*\?.*$'),                 # 含复杂参数的URL规则
        re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$'),  # IP/CIDR规则
        re.compile(r'^\|\|(?:\d{1,3}\.){3}\d{1,3}\^$')       # IP格式域名规则
    ]

    # 1.3 支持的规则正则（用于提取AGH域名规则）
    SUPPORTED_RULE_PATTERNS = {
        "DOMAIN_DOUBLE_PIPE": re.compile(r'^@@?\|\|([^*]+?)\^$'),          # @@||example.com^
        "DOMAIN_WILDCARD": re.compile(r'^@@?\|\|*\.([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)\^$'),  # @@||*.example.com^
        "DOMAIN_PLAIN": re.compile(r'^@@?([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$'), # @@example.com
        "URL_FULL": re.compile(r'^@@?\|https?://([a-zA-Z0-9-.]+\.[a-zA-Z0-9-]+)(?::\d+)?/.*$'),  # @@|https://sub.example.com/path
        "DOMAIN_WITH_MODIFIERS": re.compile(r'^@@?\|\|([^*]+?)\^\$((?:[a-zA-Z0-9-]+)(?:,[a-zA-Z0-9-]+)*)$'),  # @@||example.com^$third-party
        "URL_WITH_MODIFIERS": re.compile(r'^@@?\|https?://([a-zA-Z0-9-.]+\.[a-zA-Z0-9-]+)(?::\d+)?/.*\$((?:[a-zA-Z0-9-]+)(?:,[a-zA-Z0-9-]+)*)$')  # @@|https://example.com/path$image
    }


# ==============================================================================
# 2. 工具函数（通用辅助功能，按功能独立封装）
# ==============================================================================
def is_valid_domain(domain: str) -> bool:
    """校验域名合法性（符合DNS标准）"""
    domain = domain.strip()
    # 排除IP、含特殊字符、首尾为.的域名
    if (not domain 
        or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)
        or re.search(r'[:/\\\s#,@]', domain)
        or domain.startswith('.') 
        or domain.endswith('.')):
        return False
    
    # 校验域名分段（长度、字符）
    parts = domain.split('.')
    if len(parts) < 2 or len(domain) > 253:
        return False
    for part in parts:
        if (not part 
            or len(part) > 63 
            or not re.match(r'^[a-zA-Z0-9-]+$', part)
            or part.startswith('-') 
            or part.endswith('-')):
            return False
    
    return True


def is_unsupported_rule(rule: str) -> bool:
    """判断规则是否为不可支持类型（匹配UNSUPPORTED_RULE_PATTERNS）"""
    return any(pattern.search(rule) for pattern in Config.UNSUPPORTED_RULE_PATTERNS)


def deduplicate_rules(rules: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """规则去重（按「规则类型|目标域名|动作」生成唯一键）"""
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
    """写入规则到文件（自动创建父目录，UTF-8编码）"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


def are_modifiers_compatible(modifier_str: str) -> Tuple[bool, List[str]]:
    """校验修饰符是否全部兼容（返回：是否兼容、不兼容修饰符列表）"""
    modifiers = [m.strip() for m in modifier_str.split(',')]
    incompatible_mods = [m for m in modifiers if m not in Config.COMPATIBLE_MODIFIERS]
    return len(incompatible_mods) == 0, incompatible_mods


# ==============================================================================
# 3. 规则解析模块（AGH规则→统一格式，区分DIRECT/REJECT）
# ==============================================================================
def parse_adguard_rules() -> Tuple[List[Tuple[str, str, str]], int, int, int, int]:
    """
    解析AGH规则文件
    返回：(有效规则列表, 总规则数, 不可支持数, 重复数, 兼容修饰符数)
    规则格式：(rule_type: str, target: str, action: str) → action=DIRECT/REJECT
    """
    valid_rules = []          # 有效规则列表
    total_count = 0           # 总读取规则数
    unsupported_count = 0     # 不可支持规则数
    compatible_mod_count = 0  # 兼容修饰符规则数

    # 规则源映射：输入文件→动作→来源名称
    rule_sources = [
        (Config.INPUT["BLACKLIST"], "REJECT", "AGH黑名单"),
        (Config.INPUT["WHITELIST"], "DIRECT", "AGH白名单")
    ]

    # 遍历所有规则源
    for file_path, action, source_name in rule_sources:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"⚠️  {source_name}文件不存在：{file_path}（需为无文件头的AGH纯净规则）")
            continue

        # 读取文件（过滤注释和空行）
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("!")]
            total_count += len(lines)
            print(f"\n📥 读取{source_name}：共{len(lines)}条规则")

            # 逐条解析规则
            for rule in lines:
                # 1. 过滤不可支持规则
                if is_unsupported_rule(rule):
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  跳过不可兼容规则：{rule}")
                    continue

                # 2. 处理白名单@@补全（按开关控制）
                original_rule = rule
                if action == "DIRECT" and Config.ALLOW_AUTO_ADD_AT and not rule.startswith("@@"):
                    rule = f"@@{rule}"
                    if Config.VERBOSE_LOG:
                        print(f"  ℹ️  补全白名单@@：{original_rule} → {rule}")

                # 3. 提取域名和修饰符
                matched = False
                domain = ""
                modifiers = ""
                for pattern_name, pattern in Config.SUPPORTED_RULE_PATTERNS.items():
                    match = pattern.match(rule)
                    if not match:
                        continue

                    # 3.1 处理带修饰符的规则
                    if pattern_name in ["DOMAIN_WITH_MODIFIERS", "URL_WITH_MODIFIERS"]:
                        domain = match.group(1).strip()
                        modifiers = match.group(2).strip()
                        
                        # 校验修饰符兼容性
                        is_compatible, incompatible_mods = are_modifiers_compatible(modifiers)
                        if not is_compatible:
                            unsupported_count += 1
                            if Config.VERBOSE_LOG:
                                print(f"  ⚠️  含不可兼容修饰符（{','.join(incompatible_mods)}）：{rule}")
                            break
                        compatible_mod_count += 1

                    # 3.2 处理无修饰符的规则
                    else:
                        domain = match.group(1).strip()

                    # 3.3 校验域名合法性
                    if not is_valid_domain(domain):
                        if Config.VERBOSE_LOG:
                            print(f"  ⚠️  无效域名：{domain}（规则：{rule}）")
                        break

                    # 3.4 添加有效规则
                    valid_rules.append(("DOMAIN-SUFFIX", domain, action))
                    matched = True
                    if Config.VERBOSE_LOG:
                        log_msg = f"  ✅ 解析成功：{rule} → 域名[{domain}]（动作={action}）"
                        if modifiers:
                            log_msg += f"（忽略兼容修饰符[{modifiers}]）"
                        print(log_msg)
                    break

                # 4. 标记未匹配规则
                if not matched:
                    unsupported_count += 1
                    if Config.VERBOSE_LOG:
                        print(f"  ⚠️  无法提取域名：{rule}")

    # 5. 规则去重
    before_dedup = len(valid_rules)
    valid_rules = deduplicate_rules(valid_rules)
    duplicate_count = before_dedup - len(valid_rules)
    if duplicate_count > 0:
        print(f"\n🔍 规则去重：移除{duplicate_count}条重复规则")

    return valid_rules, total_count, unsupported_count, duplicate_count, compatible_mod_count


# ==============================================================================
# 4. 规则转换模块（统一格式→各目标格式，核心适配Clash）
# ==============================================================================
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """
    转换为Clash规则格式（仅保留payload及规则列表）
    返回：(拦截规则列表, 放行规则列表)
    """
    # 初始化Clash规则（仅含payload头部，无策略组信息）
    clash_block = ["payload:"]  # 对应action=REJECT
    clash_allow = ["payload:"]  # 对应action=DIRECT

    # 按动作分类规则（保留Clash隐式语法：+.域名）
    for rule_type, target, action in rules:
        if rule_type == "DOMAIN-SUFFIX":
            clash_rule = f"  - '+.{target}'"
            if action == "REJECT":
                clash_block.append(clash_rule)
            elif action == "DIRECT":
                clash_allow.append(clash_rule)

    # 空规则时补默认项（避免YAML格式错误）
    if len(clash_block) == 1:
        clash_block.append("  - '+.example.com'")
    if len(clash_allow) == 1:
        clash_allow.append("  - '+.example.com'")

    return clash_block, clash_allow


def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """
    转换为Surge规则格式（标准domain-suffix格式）
    返回：(拦截规则列表, 放行规则列表)
    """
    surge_block = []  # 对应action=REJECT
    surge_allow = []  # 对应action=DIRECT

    # 按动作分类规则（Surge格式：DOMAIN-SUFFIX,域名,策略）
    for rule_type, target, action in rules:
        surge_policy = "REJECT" if action == "REJECT" else "DIRECT"
        surge_rule = f"{rule_type},{target},{surge_policy}"
        if action == "REJECT":
            surge_block.append(surge_rule)
        else:
            surge_allow.append(surge_rule)

    return surge_block, surge_allow


def compile_mihomo(clash_block_path: str) -> None:
    """编译Clash规则为Mihomo(.mrs)格式（依赖官方工具）"""
    if not os.path.exists(Config.MIHOMO_TOOL):
        print(f"\n❌ Mihomo工具不存在：{Config.MIHOMO_TOOL}（请下载官方工具）")
        return

    # 执行编译命令
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
        # 输出文件大小信息
        mrs_size = os.path.getsize(Config.OUTPUT["MIHOMO"]) / 1024
        print(f"✅ Mihomo编译完成：{Config.OUTPUT['MIHOMO']}（{mrs_size:.2f} KB）")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr.strip()}")


# ==============================================================================
# 5. 主流程（串联解析→转换→输出全流程）
# ==============================================================================
def main():
    """主函数：执行规则转换全流程"""
    # 打印欢迎信息
    print("=" * 60)
    print("📦 AGH规则→Clash/Surge/Mihomo 转换工具")
    print("=" * 60)
    print(f"🔧 功能配置：去重={Config.ENABLE_DEDUPLICATION} | 白名单补@@={Config.ALLOW_AUTO_ADD_AT}")
    print(f"🔧 Clash格式：仅保留payload列表 | 策略由Clash主体处理")
    print(f"🔧 转换逻辑：AGH黑名单→REJECT | AGH白名单→DIRECT")
    print("=" * 60)

    # 步骤1：解析AGH规则
    print("\n【1/4】解析AGH规则文件...")
    valid_rules, total_count, unsupported_count, duplicate_count, compatible_mod_count = parse_adguard_rules()
    valid_count = len(valid_rules)
    conversion_rate = (valid_count / total_count * 100) if total_count > 0 else 0

    # 打印解析统计
    print(f"\n📊 解析统计：")
    print(f"  - 总规则数：{total_count} 条")
    print(f"  - 有效规则数：{valid_count} 条（转化率：{conversion_rate:.1f}%）")
    print(f"  - 不可支持数：{unsupported_count} 条")
    print(f"  - 重复规则数：{duplicate_count} 条")
    print(f"  - 兼容修饰符数：{compatible_mod_count} 条")

    # 无有效规则时终止
    if valid_count == 0:
        print("\n⚠️  无有效规则可转换，程序终止")
        return

    # 步骤2：转换为Clash格式
    print("\n【2/4】转换为Clash规则...")
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT["CLASH_BLOCK"])
    write_file(clash_allow, Config.OUTPUT["CLASH_ALLOW"])
    print(f"✅ Clash规则生成：")
    print(f"  - 拦截规则：{len(clash_block)-1} 条 → {Config.OUTPUT['CLASH_BLOCK']}")
    print(f"  - 放行规则：{len(clash_allow)-1} 条 → {Config.OUTPUT['CLASH_ALLOW']}")

    # 步骤3：转换为Surge格式
    print("\n【3/4】转换为Surge规则...")
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT["SURGE_BLOCK"])
    write_file(surge_allow, Config.OUTPUT["SURGE_ALLOW"])
    print(f"✅ Surge规则生成：")
    print(f"  - 拦截规则：{len(surge_block)} 条 → {Config.OUTPUT['SURGE_BLOCK']}")
    print(f"  - 放行规则：{len(surge_allow)} 条 → {Config.OUTPUT['SURGE_ALLOW']}")

    # 步骤4：编译为Mihomo格式
    print("\n【4/4】编译Mihomo规则...")
    compile_mihomo(Config.OUTPUT["CLASH_BLOCK"])

    # 打印完成信息
    print("\n" + "=" * 60)
    print("🎉 所有转换任务完成！")
    print("✅ 核心说明：Clash产物仅含payload，策略逻辑由Clash主体配置")
    print("=" * 60)


if __name__ == "__main__":
    main()
