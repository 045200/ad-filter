import os
import re
from typing import List, Tuple, Dict
import subprocess

# -------------------------- 1. 配置参数 --------------------------
BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

class Config:
    # 输入文件（使用更友好的AdGuard Home命名）
    INPUT_BLACKLIST = os.path.join(BASE_DIR, "adblock_adh.txt")
    INPUT_WHITELIST = os.path.join(BASE_DIR, "allow_adh.txt")
    # 输出文件
    OUTPUT_CLASH_BLOCK = os.path.join(BASE_DIR, "adblock_clash.yaml")
    OUTPUT_CLASH_ALLOW = os.path.join(BASE_DIR, "allow_clash.yaml")
    OUTPUT_SURGE_BLOCK = os.path.join(BASE_DIR, "adblock_surge.conf")
    OUTPUT_SURGE_ALLOW = os.path.join(BASE_DIR, "allow_surge.conf")
    # Mihomo配置
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")
    MIHOMO_OUTPUT = os.path.join(BASE_DIR, "adb.mrs")
    # 是否启用去重（输入文件已去重时建议关闭）
    ENABLE_DEDUPLICATION = False
    RULE_TYPE = "domain"


# -------------------------- 2. AdGuard规则解析（增强版） --------------------------
def parse_adguard_rule(rule: str) -> Tuple[str, str, str]:
    """
    增强版AdGuard规则解析，尽可能保留所有域名规则
    """
    rule = rule.strip()

    # 过滤空行和注释
    if not rule or rule.startswith(("!", "#")):
        return ("INVALID", "", "SKIP")

    # 处理例外规则（白名单）
    is_exception = rule.startswith("@@")
    if is_exception:
        rule = rule[2:]  # 移除@@前缀

    # 分离规则主体和修饰符
    rule_parts = rule.split("$", 1)
    rule_body = rule_parts[0].strip()
    
    # 处理修饰符 - 检查是否包含不支持的类型
    if len(rule_parts) > 1:
        modifiers = rule_parts[1]
        unsupported_modifiers = {"dnstype", "dnsrewrite", "redirect", "removeparam", "csp", "replace", "cookie"}
        if any(mod in modifiers for mod in unsupported_modifiers):
            return ("INVALID", "", "SKIP")

    # 处理元素隐藏规则（不支持）
    if rule_body.startswith(("##", "#@#", "#%#", "#?#")):
        return ("INVALID", "", "SKIP")

    # 确定动作
    action = "ALLOW" if is_exception else "REJECT"

    # 1. 处理以||开头的域名规则 (||example.com^)
    if rule_body.startswith("||") and rule_body.endswith("^"):
        domain = rule_body[2:-1]  # 移除||和^
        
        # 处理通配符域名 (||*.example.com^)
        if domain.startswith("*."):
            domain = domain[2:]  # 移除*.
        
        # 检查是否是有效域名
        if "." in domain and not any(c in domain for c in ["/", "*", "^", "|", " "]):
            return ("DOMAIN", domain, action)
    
    # 2. 处理普通域名规则 (example.com)
    elif "." in rule_body and not any(c in rule_body for c in ["/", "*", "^", "|", " "]):
        return ("DOMAIN", rule_body, action)
    
    # 3. 处理URL规则 (|http://example.com| 或 |https://example.com|)
    elif rule_body.startswith("|http"):
        # 提取域名部分
        if "://" in rule_body:
            domain_part = rule_body.split("://")[1]
            if "/" in domain_part:
                domain = domain_part.split("/")[0]
            else:
                domain = domain_part
            
            # 移除可能的端口号
            if ":" in domain:
                domain = domain.split(":")[0]
                
            if "." in domain and not any(c in domain for c in ["/", "*", "^", "|", " "]):
                return ("DOMAIN", domain, action)
    
    # 4. 处理包含^的规则 (example.com^)
    elif rule_body.endswith("^") and "." in rule_body:
        domain = rule_body[:-1]  # 移除^
        if not any(c in domain for c in ["/", "*", "|", " "]):
            return ("DOMAIN", domain, action)
    
    # 5. 处理包含通配符的规则 (*.example.com)
    elif rule_body.startswith("*.") and "." in rule_body[2:]:
        domain = rule_body[2:]  # 移除*.
        if not any(c in domain for c in ["/", "*", "^", "|", " "]):
            return ("DOMAIN", domain, action)
    
    # 6. 处理正则表达式规则 - 尝试提取域名
    elif rule_body.startswith("/") and rule_body.endswith("/"):
        regex_pattern = rule_body[1:-1]
        # 尝试从正则表达式中提取域名
        domain = extract_domain_from_regex(regex_pattern)
        if domain:
            return ("DOMAIN", domain, action)
    
    # 7. 处理包含/ad/等路径的规则
    elif "/" in rule_body and "." in rule_body:
        # 尝试提取域名部分
        domain_part = rule_body.split("/")[0]
        if "." in domain_part and not any(c in domain_part for c in ["*", "^", "|", " "]):
            return ("DOMAIN", domain_part, action)
    
    # 8. 尝试提取任何看起来像域名的部分
    if "." in rule_body:
        # 尝试找到最长的看起来像域名的部分
        domain_match = re.search(r'([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+)', rule_body)
        if domain_match:
            domain = domain_match.group(1)
            # 过滤掉明显不是域名的匹配
            if len(domain) > 4 and not domain.startswith(("www.", "http")) and not any(c in domain for c in ["/", "*", "^", "|", " "]):
                return ("DOMAIN", domain, action)
    
    # 9. 尝试提取关键词规则
    ad_keywords = ["ad", "ads", "advert", "adv", "banner", "track", "analytics", "affiliate", "doubleclick", "googlead", "scorecard"]
    for keyword in ad_keywords:
        if keyword in rule_body.lower():
            # 确保关键词长度合理
            if 3 <= len(keyword) <= 20:
                return ("DOMAIN-KEYWORD", keyword, action)
    
    # 无法识别的规则类型
    return ("INVALID", "", "SKIP")


def extract_domain_from_regex(regex_pattern: str) -> str:
    """
    从正则表达式中尝试提取域名
    """
    # 常见正则模式匹配
    patterns = [
        r'([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+)',  # 标准域名
        r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})',  # 简化的域名
    ]
    
    for pattern in patterns:
        match = re.search(pattern, regex_pattern)
        if match:
            domain = match.group(1)
            # 过滤掉明显不是域名的匹配
            if len(domain) > 4 and not domain.startswith(("www.", "http")) and not any(c in domain for c in ["/", "*", "^", "|", " "]):
                return domain
    
    return ""


def deduplicate_rules(rules: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """
    智能去重规则，保留所有域名层级
    """
    if not Config.ENABLE_DEDUPLICATION:
        return rules
    
    seen = set()
    deduped_rules = []
    
    for rule_type, target, action in rules:
        # 创建规则的唯一标识
        rule_id = f"{rule_type}|{target}|{action}"
        
        # 只有当规则完全相同时才去重
        if rule_id not in seen:
            seen.add(rule_id)
            deduped_rules.append((rule_type, target, action))
    
    return deduped_rules


# -------------------------- 3. 规则转换 --------------------------
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    clash_block = ["payload:"]
    clash_allow = ["payload:"]

    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue

        # Clash规则格式：'+.example.com'（隐式策略）
        if rule_type == "DOMAIN":
            clash_rule = f"  - '+.{target}'"
        elif rule_type == "DOMAIN-KEYWORD":
            clash_rule = f"  - '{target}'"
        else:
            continue  # 跳过其他类型

        if action == "REJECT":
            clash_block.append(clash_rule)
        else:
            clash_allow.append(clash_rule)

    # 避免空文件
    if len(clash_block) == 1:
        clash_block.append("  - '+.example.com'")
    if len(clash_allow) == 1:
        clash_allow.append("  - '+.example.com'")

    return clash_block, clash_allow


def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    surge_block = []  # 黑名单规则
    surge_allow = []  # 白名单规则

    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue

        # Surge规则格式：TYPE,VAL,POLICY（显式策略）
        # 将ALLOW映射为DIRECT，REJECT保持不变
        surge_policy = "DIRECT" if action == "ALLOW" else "REJECT"
        
        if rule_type == "DOMAIN":
            surge_rule = f"DOMAIN-SUFFIX,{target},{surge_policy}"
        elif rule_type == "DOMAIN-KEYWORD":
            surge_rule = f"DOMAIN-KEYWORD,{target},{surge_policy}"
        else:
            continue  # 跳过其他类型

        if action == "REJECT":
            surge_block.append(surge_rule)
        else:
            surge_allow.append(surge_rule)

    return surge_block, surge_allow


# -------------------------- 4. 文件操作 --------------------------
def write_file(content: List[str], file_path: str):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


# -------------------------- 5. 主流程 --------------------------
def main():
    # 1. 读取AdGuard规则
    all_adg_rules = []

    # 读取黑名单
    try:
        with open(Config.INPUT_BLACKLIST, "r", encoding="utf-8") as f:
            all_adg_rules.extend([line.strip() for line in f if line.strip() and not line.startswith("!")])
    except FileNotFoundError:
        print(f"❌ 黑名单文件不存在: {Config.INPUT_BLACKLIST}")
        return

    # 读取白名单（直接读取，不添加@@前缀）
    try:
        with open(Config.INPUT_WHITELIST, "r", encoding="utf-8") as f:
            all_adg_rules.extend([line.strip() for line in f if line.strip() and not line.startswith("!")])
    except FileNotFoundError:
        print(f"❌ 白名单文件不存在: {Config.INPUT_WHITELIST}")
        return

    original_count = len(all_adg_rules)
    print(f"✅ 读取AdGuard规则：共{original_count}条（黑名单+白名单）")

    # 2. 解析有效规则
    valid_rules = []
    invalid_count = 0
    
    for rule in all_adg_rules:
        rule_type, target, action = parse_adguard_rule(rule)
        if rule_type != "INVALID":
            valid_rules.append((rule_type, target, action))
        else:
            invalid_count += 1

    # 3. 智能去重
    if Config.ENABLE_DEDUPLICATION:
        before_dedup = len(valid_rules)
        valid_rules = deduplicate_rules(valid_rules)
        after_dedup = len(valid_rules)
        print(f"✅ 智能去重：{before_dedup}条 → {after_dedup}条（移除{before_dedup-after_dedup}条重复规则）")
    else:
        print(f"✅ 跳过去重：保留所有{len(valid_rules)}条规则")

    # 4. 输出解析统计
    conversion_rate = (len(valid_rules) / original_count * 100) if original_count > 0 else 0
    print(f"✅ 解析有效规则：{len(valid_rules)}条（转化率：{conversion_rate:.1f}%）")
    
    # 简化无效规则输出，只显示数量
    if invalid_count > 0:
        print(f"⚠️  跳过不支持规则：{invalid_count}条")

    # 5. 保存Clash规则
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT_CLASH_BLOCK)
    write_file(clash_allow, Config.OUTPUT_CLASH_ALLOW)
    print(f"\n📁 Clash规则已保存：")
    print(f"  - 黑名单：{Config.OUTPUT_CLASH_BLOCK}（{len(clash_block)-1}条）")
    print(f"  - 白名单：{Config.OUTPUT_CLASH_ALLOW}（{len(clash_allow)-1}条）")

    # 6. 保存Surge规则
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT_SURGE_BLOCK)
    write_file(surge_allow, Config.OUTPUT_SURGE_ALLOW)
    print(f"\n📁 Surge规则已保存：")
    print(f"  - 黑名单：{Config.OUTPUT_SURGE_BLOCK}（{len(surge_block)}条）")
    print(f"  - 白名单：{Config.OUTPUT_SURGE_ALLOW}（{len(surge_allow)}条）")

    # 7. Mihomo编译（移除了--priority参数）
    mihomo_cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        Config.RULE_TYPE,
        "yaml",
        Config.OUTPUT_CLASH_BLOCK,
        Config.MIHOMO_OUTPUT
    ]

    try:
        result = subprocess.run(mihomo_cmd, check=True, capture_output=True, text=True)
        mrs_size = os.path.getsize(Config.MIHOMO_OUTPUT) / 1024  # KB
        print(f"\n🔧 Mihomo编译成功：")
        print(f"  - 文件：{Config.MIHOMO_OUTPUT}")
        print(f"  - 大小：{mrs_size:.2f}KB")
        if result.stdout.strip():
            print(f"  - 输出：{result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr}")
    except FileNotFoundError:
        print(f"\n❌ 未找到Mihomo工具：{Config.MIHOMO_TOOL}")


if __name__ == "__main__":
    main()