import re
import os
from typing import List, Tuple
import subprocess

# -------------------------- 1. 配置参数（绑定GitHub工作区，确保输出在根目录） --------------------------
# 获取GitHub工作区根目录（GitHub Actions自动注入，本地运行默认当前目录）
BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

class Config:
    # 输入：AdGuard原始规则文件（根目录）
    INPUT_BLACKLIST = os.path.join(BASE_DIR, "adblock_adg.txt")  # 黑名单（如||ad.com^）
    INPUT_WHITELIST = os.path.join(BASE_DIR, "allow_adg.txt")    # 白名单（如allow.com，无需加@@）
    # 输出：Clash规则（YAML格式，根目录）
    OUTPUT_CLASH_BLOCK = os.path.join(BASE_DIR, "adblock_clash_block.yaml")  # 黑名单（payload结构）
    OUTPUT_CLASH_ALLOW = os.path.join(BASE_DIR, "adblock_clash_allow.yaml")  # 白名单（payload结构）
    # 输出：Surge规则（CONF格式，根目录）
    OUTPUT_SURGE_BLOCK = os.path.join(BASE_DIR, "surge_blacklist.conf")  # 黑名单（仅REJECT）
    OUTPUT_SURGE_ALLOW = os.path.join(BASE_DIR, "surge_whitelist.conf")  # 白名单（仅ALLOW）
    # Mihomo编译配置（关键修正：格式参数为yaml，工具路径/输出均在根目录）
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")  # 根目录/data下的二进制工具
    MIHOMO_OUTPUT = os.path.join(BASE_DIR, "adb.mrs")         # 输出MRS到根目录
    MIHOMO_PRIORITY = 100                                     # 优先级（1-255）
    RULE_TYPE = "domain"                                      # 规则类型（domain/ipcidr）


# -------------------------- 2. 核心：AdGuard规则解析（优化白名单支持，处理参数/通配符） --------------------------
def parse_adguard_rule(rule: str) -> Tuple[str, str, str]:
    """
    解析单条AdGuard规则，返回 (规则类型, 目标值, 动作)
    优化点：1. 支持带$参数的规则（如example.com$script）；2. 支持通配符域名（如*.example.com）
    """
    rule = rule.strip()
    # 过滤空行、注释
    if not rule or rule.startswith("!"):
        return ("INVALID", "", "SKIP")

    # 1. 判断白/黑名单动作（自动处理@@前缀）
    is_whitelist = rule.startswith("@@")
    action = "ALLOW" if is_whitelist else "REJECT"
    rule_body = rule[2:] if is_whitelist else rule  # 移除白名单前缀

    # 2. 关键优化：分割规则体与参数（如$script、$domain=example.org，仅保留域名部分）
    if "$" in rule_body:
        rule_body = rule_body.split("$")[0].strip()  # 提取$前的纯域名/关键词/IP，忽略参数

    # 3. 匹配：域名规则（支持普通域名||xxx.com^、通配符*.xxx.com、纯xxx.com）
    domain_pattern = r"^(?:\|\|)?(\*\.?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\^)?$"
    domain_match = re.match(domain_pattern, rule_body)
    if domain_match:
        return ("DOMAIN-SUFFIX", domain_match.group(1), action)

    # 4. 匹配：关键词规则（/xxx/）
    keyword_pattern = r"^/(.*?)/$"
    keyword_match = re.match(keyword_pattern, rule_body)
    if keyword_match:
        return ("DOMAIN-KEYWORD", keyword_match.group(1), action)

    # 5. 匹配：IP-CIDR规则（支持192.168.1.1或192.168.1.0/24）
    ip_cidr_pattern = r"^((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?$"
    ip_cidr_match = re.match(ip_cidr_pattern, rule_body)
    if ip_cidr_match:
        ip = ip_cidr_match.group(1)
        cidr = ip_cidr_match.group(2) if ip_cidr_match.group(2) else "32"
        return ("IP-CIDR", f"{ip}/{cidr}", action)

    # 不支持的规则类型（如GEOIP、SCRIPT）
    return ("INVALID", "", "SKIP")


# -------------------------- 3. 规则转换：AdGuard → Clash/Surge（逻辑不变，确保输出正确） --------------------------
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    clash_block = ["payload:"]  # 黑名单（REJECT）
    clash_allow = ["payload:"]  # 白名单（ALLOW）

    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue
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
    surge_block = []  # 黑名单（REJECT）
    surge_allow = []  # 白名单（ALLOW）

    for rule_type, target, action in rules:
        if rule_type == "INVALID":
            continue
        surge_rule = f"{rule_type},{target},{action}"
        if action == "REJECT":
            surge_block.append(surge_rule)
        else:
            surge_allow.append(surge_rule)

    return surge_block, surge_allow


# -------------------------- 4. 辅助工具：文件写入（确保根目录输出） --------------------------
def write_file(content: List[str], file_path: str):
    dirname_path = os.path.dirname(file_path)
    if dirname_path:  # 仅当路径含子目录时创建（根目录无需创建）
        os.makedirs(dirname_path, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))


# -------------------------- 5. 主流程：读取→解析→转换→保存→编译（核心修正Mihomo参数） --------------------------
def main():
    # 1. 读取AdGuard黑白名单规则
    all_adg_rules = []
    # 读取黑名单（默认REJECT）
    with open(Config.INPUT_BLACKLIST, "r", encoding="utf-8") as f:
        all_adg_rules.extend([line.strip() for line in f])
    # 读取白名单（自动加@@前缀，符合AdGuard语法）
    with open(Config.INPUT_WHITELIST, "r", encoding="utf-8") as f:
        all_adg_rules.extend([f"@@{line.strip()}" for line in f])

    original_count = len(all_adg_rules)
    print(f"✅ 读取AdGuard规则：共{original_count}条（黑名单+白名单）")
    print(f"   读取路径：{Config.INPUT_BLACKLIST}、{Config.INPUT_WHITELIST}")

    # 2. 规则去重
    unique_rules = list(set(all_adg_rules))
    dedup_count = len(unique_rules)
    print(f"✅ 规则去重：{original_count}条 → {dedup_count}条")

    # 3. 解析有效规则（优化后白名单有效率提升）
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
    print(f"\n📁 Clash规则已保存（根目录）：")
    print(f"  - 黑名单：{Config.OUTPUT_CLASH_BLOCK}（{len(clash_block)-1}条）")
    print(f"  - 白名单：{Config.OUTPUT_CLASH_ALLOW}（{len(clash_allow)-1}条）")

    # 5. 保存Surge规则
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT_SURGE_BLOCK)
    write_file(surge_allow, Config.OUTPUT_SURGE_ALLOW)
    print(f"\n📁 Surge规则已保存（根目录）：")
    print(f"  - 黑名单：{Config.OUTPUT_SURGE_BLOCK}（{len(surge_block)}条）")
    print(f"  - 白名单：{Config.OUTPUT_SURGE_ALLOW}（{len(surge_allow)}条）")

    # 6. Mihomo编译（关键修正：格式参数从clash改为yaml）
    mihomo_cmd = [
        Config.MIHOMO_TOOL,
        "convert-ruleset",
        Config.RULE_TYPE,       # 规则类型（domain）
        "yaml",                 # 输入格式（修正为yaml，匹配Clash YAML规则集）
        Config.OUTPUT_CLASH_BLOCK,  # 输入Clash黑名单文件
        Config.MIHOMO_OUTPUT,       # 输出MRS文件
        "--priority", str(Config.MIHOMO_PRIORITY)  # 优先级
    ]

    try:
        result = subprocess.run(mihomo_cmd, check=True, capture_output=True, text=True)
        mrs_size = os.path.getsize(Config.MIHOMO_OUTPUT) / 1024  # 转为KB
        print(f"\n🔧 Mihomo编译成功（根目录）：")
        print(f"  - 文件：{Config.MIHOMO_OUTPUT}")
        print(f"  - 大小：{mrs_size:.2f}KB")
        print(f"  - 优先级：{Config.MIHOMO_PRIORITY}")
        print(f"  - 编译命令：{' '.join(mihomo_cmd)}")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败（命令：{' '.join(mihomo_cmd)}）")
        print(f"    错误日志：{e.stderr}")
    except FileNotFoundError:
        print(f"\n❌ 未找到Mihomo工具，请确认路径：{Config.MIHOMO_TOOL}")


if __name__ == "__main__":
    main()
