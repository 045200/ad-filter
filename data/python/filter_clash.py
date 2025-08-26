import re
import os
from typing import List, Tuple
import subprocess

# -------------------------- 1. 配置参数 --------------------------
BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

class Config:
    # 输入文件
    INPUT_BLACKLIST = os.path.join(BASE_DIR, "adblock_adg.txt")
    INPUT_WHITELIST = os.path.join(BASE_DIR, "allow_adg.txt")
    # 输出文件
    OUTPUT_CLASH_BLOCK = os.path.join(BASE_DIR, "adblock_clash.yaml")
    OUTPUT_CLASH_ALLOW = os.path.join(BASE_DIR, "allow_clash.yaml")
    OUTPUT_SURGE_BLOCK = os.path.join(BASE_DIR, "adblock_surge.conf")
    OUTPUT_SURGE_ALLOW = os.path.join(BASE_DIR, "allow_surge.conf")
    # Mihomo配置
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")
    MIHOMO_OUTPUT = os.path.join(BASE_DIR, "adb.mrs")
    MIHOMO_PRIORITY = 100
    RULE_TYPE = "domain"


# -------------------------- 2. AdGuard规则解析（增强版） --------------------------
def parse_adguard_rule(rule: str) -> Tuple[str, str, str]:
    """
    增强版AdGuard规则解析，基于提供的语法库
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
    modifiers = rule_parts[1] if len(rule_parts) > 1 else ""

    # 处理修饰符 - 检查是否包含不支持的类型
    unsupported_modifiers = {"dnstype", "dnsrewrite", "redirect", "removeparam", "csp", "replace", "cookie"}
    if any(mod in modifiers for mod in unsupported_modifiers):
        return ("INVALID", "", "SKIP")

    # 处理元素隐藏规则（不支持）
    if rule_body.startswith(("##", "#@#", "#%#", "#?#")):
        return ("INVALID", "", "SKIP")

    # 确定动作
    action = "ALLOW" if is_exception else "REJECT"

    # 1. 处理域名规则 (||example.com^)
    domain_match = re.match(r"^\|\|([^*\^]+)\^?$", rule_body)
    if domain_match:
        domain = domain_match.group(1)
        # 检查是否是有效域名
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
            return ("DOMAIN-SUFFIX", domain, action)

    # 2. 处理包含通配符的域名规则 (||*.example.com^)
    wildcard_domain_match = re.match(r"^\|\|(\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))\^?$", rule_body)
    if wildcard_domain_match:
        full_domain = wildcard_domain_match.group(1)
        base_domain = wildcard_domain_match.group(2)
        return ("DOMAIN-SUFFIX", base_domain, action)

    # 3. 处理URL规则 (|http://example.com|)
    url_match = re.match(r"^\|https?://([^/|]+)", rule_body)
    if url_match:
        domain = url_match.group(1)
        return ("DOMAIN", domain, action)

    # 4. 处理正则表达式规则 (/ads[0-9]+/)
    regex_match = re.match(r"^/(.*)/$", rule_body)
    if regex_match:
        # 尝试从正则中提取简单关键字
        regex_pattern = regex_match.group(1)
        simple_keyword = extract_simple_keyword(regex_pattern)
        if simple_keyword:
            return ("DOMAIN-KEYWORD", simple_keyword, action)

    # 5. 处理普通域名规则 (example.com)
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", rule_body):
        return ("DOMAIN-SUFFIX", rule_body, action)

    # 6. 处理IP-CIDR规则
    ip_cidr_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?$", rule_body)
    if ip_cidr_match:
        ip = ip_cidr_match.group(1)
        cidr = ip_cidr_match.group(2) or "32"
        return ("IP-CIDR", f"{ip}/{cidr}", action)

    # 7. 处理包含广告关键词的规则
    ad_keywords = ["ad", "ads", "advert", "adv", "banner", "track", "analytics", "affiliate"]
    if any(keyword in rule_body.lower() for keyword in ad_keywords):
        # 尝试提取域名部分
        domain_part = extract_domain_from_pattern(rule_body)
        if domain_part:
            return ("DOMAIN-KEYWORD", domain_part, action)

    # 无法识别的规则类型
    return ("INVALID", "", "SKIP")


def extract_simple_keyword(regex_pattern: str) -> str:
    """
    从正则表达式中提取简单关键字
    """
    # 处理常见正则模式
    simple_patterns = [
        r"^([a-zA-Z0-9]+)[0-9]*$",  # word123 -> word
        r"^[a-zA-Z0-9]*([a-zA-Z0-9]+)[a-zA-Z0-9]*$",  # 提取中间部分
    ]

    for pattern in simple_patterns:
        match = re.match(pattern, regex_pattern)
        if match and match.group(1):
            return match.group(1)

    return ""


def extract_domain_from_pattern(pattern: str) -> str:
    """
    从复杂模式中尝试提取域名部分
    """
    # 尝试提取可能是域名的部分
    domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", pattern)
    if domain_match:
        return domain_match.group(1)

    # 尝试提取可能是关键词的部分
    keyword_match = re.search(r"([a-zA-Z]{3,})", pattern)
    if keyword_match:
        return keyword_match.group(1)

    return ""


# -------------------------- 3. 规则转换 --------------------------
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    clash_block = ["payload:"]
    clash_allow = ["payload:"]

    # 不使用集合，保留所有规则（包括重复的）
    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue

        clash_rule = f"  - {rule_type},{target},{action}"

        if action == "REJECT":
            clash_block.append(clash_rule)
        else:
            clash_allow.append(clash_rule)

    # 避免空文件
    if len(clash_block) == 1:
        clash_block.append("  - DOMAIN-SUFFIX,example.com,REJECT")
    if len(clash_allow) == 1:
        clash_allow.append("  - DOMAIN-SUFFIX,example.com,ALLOW")

    return clash_block, clash_allow


def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    surge_block = []
    surge_allow = []

    # 不使用集合，保留所有规则（包括重复的）
    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue

        surge_rule = f"{rule_type},{target},{action}"

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

    # 读取白名单（自动添加@@前缀）
    try:
        with open(Config.INPUT_WHITELIST, "r", encoding="utf-8") as f:
            all_adg_rules.extend([f"@@{line.strip()}" for line in f if line.strip() and not line.startswith("!")])
    except FileNotFoundError:
        print(f"❌ 白名单文件不存在: {Config.INPUT_WHITELIST}")
        return

    original_count = len(all_adg_rules)
    print(f"✅ 读取AdGuard规则：共{original_count}条（黑名单+白名单）")

    # 2. 取消去重逻辑，直接使用所有规则
    unique_rules = all_adg_rules  # 不再去重
    dedup_count = len(unique_rules)
    print(f"✅ 取消去重：保留所有{dedup_count}条规则")

    # 3. 解析有效规则
    valid_rules = []
    for rule in unique_rules:
        rule_type, target, action = parse_adguard_rule(rule)
        if rule_type != "INVALID":
            valid_rules.append((rule_type, target, action))

    valid_count = len(valid_rules)
    conversion_rate = (valid_count / dedup_count * 100) if dedup_count > 0 else 0
    print(f"✅ 解析有效规则：{valid_count}条（转化率：{conversion_rate:.1f}%）")

    # 4. 保存Clash规则
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT_CLASH_BLOCK)
    write_file(clash_allow, Config.OUTPUT_CLASH_ALLOW)
    print(f"\n📁 Clash规则已保存：")
    print(f"  - 黑名单：{Config.OUTPUT_CLASH_BLOCK}（{len(clash_block)-1}条）")
    print(f"  - 白名单：{Config.OUTPUT_CLASH_ALLOW}（{len(clash_allow)-1}条）")

    # 5. 保存Surge规则
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT_SURGE_BLOCK)
    write_file(surge_allow, Config.OUTPUT_SURGE_ALLOW)
    print(f"\n📁 Surge规则已保存：")
    print(f"  - 黑名单：{Config.OUTPUT_SURGE_BLOCK}（{len(surge_block)}条）")
    print(f"  - 白名单：{Config.OUTPUT_SURGE_ALLOW}（{len(surge_allow)}条）")

    # 6. Mihomo编译
    mihomo_cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        Config.RULE_TYPE,
        "yaml",
        Config.OUTPUT_CLASH_BLOCK,
        Config.MIHOMO_OUTPUT,
        "--priority", str(Config.MIHOMO_PRIORITY)
    ]

    try:
        result = subprocess.run(mihomo_cmd, check=True, capture_output=True, text=True)
        mrs_size = os.path.getsize(Config.MIHOMO_OUTPUT) / 1024  # KB
        print(f"\n🔧 Mihomo编译成功：")
        print(f"  - 文件：{Config.MIHOMO_OUTPUT}")
        print(f"  - 大小：{mrs_size:.2f}KB")
        print(f"  - 优先级：{Config.MIHOMO_PRIORITY}")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr}")
    except FileNotFoundError:
        print(f"\n❌ 未找到Mihomo工具：{Config.MIHOMO_TOOL}")


if __name__ == "__main__":
    main()