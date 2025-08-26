import re
import os
from typing import List, Tuple
import subprocess

# -------------------------- 1. 配置参数（含Surge黑白名单分文件路径） --------------------------
class Config:
    # 输入：AdGuard原始规则文件
    INPUT_BLACKLIST = "adblock_adg.txt"  # AdGuard黑名单（如||ad.com^）
    INPUT_WHITELIST = "allow_adg.txt"    # AdGuard白名单（如allow.com，无需加@@）
    # 输出：Clash规则（YAML格式，分黑白名单）
    OUTPUT_CLASH_BLOCK = "adblock_clash_block.yaml"  # Clash黑名单（payload结构）
    OUTPUT_CLASH_ALLOW = "adblock_clash_allow.yaml"  # Clash白名单（payload结构）
    # 输出：Surge规则（CONF格式，分黑白名单，便于后续#include引用）
    OUTPUT_SURGE_BLOCK = "surge_blacklist.conf"  # Surge黑名单（仅REJECT规则）
    OUTPUT_SURGE_ALLOW = "surge_whitelist.conf"  # Surge白名单（仅ALLOW规则）
    # Mihomo编译配置（生成MRS规则集）
    MIHOMO_TOOL = "mihomo"               # Mihomo工具路径（环境变量配置则填"mihomo"）
    MIHOMO_OUTPUT = "adb.mrs"  # 输出MRS文件名
    MIHOMO_PRIORITY = 100                # MRS规则优先级（1-255，越高越优先）
    RULE_TYPE = "domain"                 # 规则类型（domain/ipcidr，匹配AdGuard规则类型）


# -------------------------- 2. 核心：AdGuard规则解析（支持域名/关键词/IP-CIDR） --------------------------
def parse_adguard_rule(rule: str) -> Tuple[str, str, str]:
    """
    解析单条AdGuard规则，返回 (规则类型, 目标值, 动作)
    - 规则类型：DOMAIN-SUFFIX/DOMAIN-KEYWORD/IP-CIDR/INVALID
    - 动作：ALLOW（白名单）/ REJECT（黑名单）/ SKIP（无效规则）
    """
    rule = rule.strip()
    # 过滤空行、注释（直接视为无效，不处理）
    if not rule or rule.startswith("!"):
        return ("INVALID", "", "SKIP")
    
    # 1. 判断白/黑名单动作（AdGuard白名单用@@前缀，此处统一处理输入）
    is_whitelist = rule.startswith("@@")
    action = "ALLOW" if is_whitelist else "REJECT"
    rule_body = rule[2:] if is_whitelist else rule  # 移除白名单前缀，统一解析规则体

    # 2. 匹配：AdGuard域名规则（||xxx.com^ 或 xxx.com，转DOMAIN-SUFFIX）
    domain_pattern = r"^(?:\|\|)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\^)?$"
    domain_match = re.match(domain_pattern, rule_body)
    if domain_match:
        return ("DOMAIN-SUFFIX", domain_match.group(1), action)

    # 3. 匹配：AdGuard关键词规则（/xxx/，转DOMAIN-KEYWORD）
    keyword_pattern = r"^/(.*?)/$"
    keyword_match = re.match(keyword_pattern, rule_body)
    if keyword_match:
        return ("DOMAIN-KEYWORD", keyword_match.group(1), action)

    # 4. 匹配：IP-CIDR规则（192.168.1.0/24 或 10.0.0.1，补全默认/32）
    ip_cidr_pattern = r"^((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?$"
    ip_cidr_match = re.match(ip_cidr_pattern, rule_body)
    if ip_cidr_match:
        ip = ip_cidr_match.group(1)
        cidr = ip_cidr_match.group(2) if ip_cidr_match.group(2) else "32"
        return ("IP-CIDR", f"{ip}/{cidr}", action)

    # 5. 不支持的规则类型（如GEOIP、SCRIPT，视为无效）
    return ("INVALID", "", "SKIP")


# -------------------------- 3. 规则转换：AdGuard → Clash/Surge --------------------------
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """转换为Clash YAML格式（含payload头部，符合Clash规则集标准）"""
    clash_block = ["payload:"]  # 黑名单（REJECT动作）
    clash_allow = ["payload:"]  # 白名单（ALLOW动作）
    
    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue
        # Clash规则格式：- 规则类型,目标值,动作
        clash_rule = f"  - {rule_type},{target},{action}"
        if action == "REJECT":
            clash_block.append(clash_rule)
        else:
            clash_allow.append(clash_rule)
    
    # 避免空文件（添加占位规则，可手动删除）
    if len(clash_block) == 1:
        clash_block.append("  - DOMAIN-SUFFIX,example.com,REJECT")
    if len(clash_allow) == 1:
        clash_allow.append("  - DOMAIN-SUFFIX,example.com,ALLOW")
    
    return clash_block, clash_allow


def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    """转换为Surge CONF格式（分黑白名单文件，便于#include引用）"""
    surge_block = []  # 黑名单（仅REJECT规则）
    surge_allow = []  # 白名单（仅ALLOW规则）
    
    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue
        # Surge规则格式：规则类型,目标值,动作（无payload头部）
        surge_rule = f"{rule_type},{target},{action}"
        if action == "REJECT":
            surge_block.append(surge_rule)
        else:
            surge_allow.append(surge_rule)
    
    return surge_block, surge_allow


# -------------------------- 4. 辅助工具：文件写入（自动创建目录） --------------------------
def write_file(content: List[str], file_path: str):
    """将规则列表写入文件，确保父目录存在"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


# -------------------------- 5. 主流程：读取→解析→转换→保存→编译 --------------------------
def main():
    # 1. 读取AdGuard黑白名单规则（合并为列表）
    all_adg_rules = []
    # 读取黑名单（无需手动加@@，脚本默认按REJECT处理）
    with open(Config.INPUT_BLACKLIST, "r", encoding="utf-8") as f:
        all_adg_rules.extend([line.strip() for line in f])
    # 读取白名单（自动添加@@前缀，符合AdGuard白名单语法）
    with open(Config.INPUT_WHITELIST, "r", encoding="utf-8") as f:
        all_adg_rules.extend([f"@@{line.strip()}" for line in f])
    
    original_count = len(all_adg_rules)
    print(f"✅ 读取AdGuard规则：共{original_count}条（黑名单+白名单）")

    # 2. 规则去重（避免重复转换）
    unique_rules = list(set(all_adg_rules))
    dedup_count = len(unique_rules)
    print(f"✅ 规则去重：{original_count}条 → {dedup_count}条")

    # 3. 解析有效规则（跳过无效规则）
    valid_rules = []
    for rule in unique_rules:
        rule_type, target, action = parse_adguard_rule(rule)
        if rule_type != "INVALID":
            valid_rules.append((rule_type, target, action))
    
    valid_count = len(valid_rules)
    conversion_rate = (valid_count / dedup_count * 100) if dedup_count > 0 else 0
    print(f"✅ 解析有效规则：{valid_count}条（转化率：{conversion_rate:.1f}%）")

    # 4. 转换并保存Clash规则
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT_CLASH_BLOCK)
    write_file(clash_allow, Config.OUTPUT_CLASH_ALLOW)
    print(f"\n📁 Clash规则已保存：")
    print(f"  - 黑名单：{Config.OUTPUT_CLASH_BLOCK}（{len(clash_block)-1}条）")
    print(f"  - 白名单：{Config.OUTPUT_CLASH_ALLOW}（{len(clash_allow)-1}条）")

    # 5. 转换并保存Surge规则（分黑白名单文件）
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT_SURGE_BLOCK)
    write_file(surge_allow, Config.OUTPUT_SURGE_ALLOW)
    print(f"\n📁 Surge规则已保存（分文件，需用#include引用）：")
    print(f"  - 黑名单：{Config.OUTPUT_SURGE_BLOCK}（{len(surge_block)}条）")
    print(f"  - 白名单：{Config.OUTPUT_SURGE_ALLOW}（{len(surge_allow)}条）")

    # 6. 用Mihomo编译Clash规则为MRS格式（供Mihomo/Clash Meta使用）
    mihomo_cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        Config.RULE_TYPE,
        "clash",
        Config.OUTPUT_CLASH_BLOCK,
        Config.MIHOMO_OUTPUT,
        "--priority", str(Config.MIHOMO_PRIORITY)
    ]

    try:
        subprocess.run(mihomo_cmd, check=True, capture_output=True, text=True)
        mrs_size = os.path.getsize(Config.MIHOMO_OUTPUT) / 1024  # 转为KB
        print(f"\n🔧 Mihomo编译成功：")
        print(f"  - 文件：{Config.MIHOMO_OUTPUT}")
        print(f"  - 大小：{mrs_size:.2f}KB")
        print(f"  - 优先级：{Config.MIHOMO_PRIORITY}")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr}")
    except FileNotFoundError:
        print(f"\n❌ 未找到Mihomo工具，请检查Config.MIHOMO_TOOL路径是否正确")


if __name__ == "__main__":
    main()
