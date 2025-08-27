import os
import re
from typing import List, Tuple, Dict
import subprocess

# -------------------------- 1. 核心配置（新增：白名单@@自动补全开关） --------------------------
UNSUPPORTED_RULE_PATTERNS = [
    re.compile(r'^##|^#@#|^#%#|^#?#'),  # 元素隐藏规则
    re.compile(r'\$redirect|\$dnsrewrite|\$removeparam|\$header|\$csp|\$cookie'),  # 不支持的修饰符
    re.compile(r'^/[^/]*\/$'),  # 无完整域名的纯正则规则
    re.compile(r'^\|?https?://.*\?.*$'),  # 含复杂参数的URL
]

SUPPORTED_RULE_PATTERNS = {
    'DOMAIN_DOUBLE_PIPE': re.compile(r'^@@?\|\|([^*]+?)\^$'),  # @@||example.com^ 或 ||example.com^
    'DOMAIN_WILDCARD': re.compile(r'^@@?\|\|\*\.([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)\^$'),  # @@||*.example.com^
    'DOMAIN_PLAIN': re.compile(r'^@@?([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$'),  # @@example.com 或 example.com
    'URL_FULL': re.compile(r'^@@?\|https?://([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)(?::\d+)?/.*$'),  # @@|https://example.com/path
}

BASE_DIR = os.getenv("GITHUB_WORKSPACE", os.getcwd())

class Config:
    # 输入文件（已验证的纯净AdGuard规则）
    INPUT_BLACKLIST = os.path.join(BASE_DIR, "adblock_adh.txt")  # 纯净黑名单（拦截规则）
    INPUT_WHITELIST = os.path.join(BASE_DIR, "allow_adh.txt")    # 纯净白名单（已含@@）
    # 输出文件
    OUTPUT = {
        "CLASH_BLOCK": os.path.join(BASE_DIR, "adblock_clash.yaml"),
        "CLASH_ALLOW": os.path.join(BASE_DIR, "allow_clash.yaml"),
        "SURGE_BLOCK": os.path.join(BASE_DIR, "adblock_surge.conf"),
        "SURGE_ALLOW": os.path.join(BASE_DIR, "allow_surge.conf"),
        "MIHOMO": os.path.join(BASE_DIR, "adb.mrs")
    }
    # 工具路径
    MIHOMO_TOOL = os.path.join(BASE_DIR, "data/mihomo-tool")
    # 功能开关（重点：针对纯净规则，可设为False关闭@@自动补全）
    ENABLE_DEDUPLICATION = True  # 规则去重（建议保留，避免重复规则）
    ALLOW_AUTO_ADD_AT = False    # 🔴 白名单@@自动补全开关：False=关闭（适配您的纯净规则）
    RULE_TYPE = "domain"

# -------------------------- 2. 工具函数（无改动） --------------------------
def is_valid_domain(domain: str) -> bool:
    domain = domain.strip()
    if not domain or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return False
    if re.search(r'[:/\\\s#,@]', domain) or domain.startswith('.') or domain.endswith('.'):
        return False
    parts = domain.split('.')
    if len(parts) < 2 or len(domain) > 253:
        return False
    for part in parts:
        if not part or len(part) > 63 or not re.match(r'^[a-zA-Z0-9-]+$', part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    return len(parts[-1]) >= 2

def is_unsupported_rule(rule: str) -> bool:
    return any(pattern.search(rule) for pattern in UNSUPPORTED_RULE_PATTERNS)

def deduplicate_rules(rules: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    if not Config.ENABLE_DEDUPLICATION:
        return rules
    seen = set()
    deduped = []
    for rule_type, target, action in rules:
        rule_key = f"{rule_type}|{target}|{action}"
        if rule_key not in seen:
            seen.add(rule_key)
            deduped.append((rule_type, target, action))
    return deduped

def write_file(content: List[str], file_path: str) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(content))

# -------------------------- 3. 规则解析（适配开关：仅当ALLOW_AUTO_ADD_AT=True时补全@@） --------------------------
def parse_adguard_rules() -> Tuple[List[Tuple[str, str, str]], int, int, int]:
    valid_rules = []
    total_count = 0
    unsupported_count = 0
    duplicate_count = 0

    rule_sources = [
        (Config.INPUT_BLACKLIST, "REJECT", "黑名单"),
        (Config.INPUT_WHITELIST, "ALLOW", "白名单")
    ]

    for file_path, action, source_name in rule_sources:
        if not os.path.exists(file_path):
            print(f"⚠️  {source_name}文件不存在：{file_path}")
            continue
        
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith(("!", "#"))]
            total_count += len(lines)
            print(f"\n📥 读取{source_name}（纯净规则）：共{len(lines)}条")

            for rule in lines:
                # 过滤不可转换规则
                if is_unsupported_rule(rule):
                    unsupported_count += 1
                    print(f"⚠️  {source_name}跳过不可转换规则：{rule}")
                    continue

                # 白名单@@处理：仅当开关开启且规则不含@@时才补全（适配您的纯净规则）
                original_rule = rule
                if action == "ALLOW" and Config.ALLOW_AUTO_ADD_AT and not rule.startswith("@@"):
                    rule = f"@@{rule}"
                    print(f"ℹ️  {source_name}自动补全@@：{original_rule} → {rule}")
                elif action == "ALLOW" and not Config.ALLOW_AUTO_ADD_AT:
                    # 开关关闭：直接使用原始规则（您的纯净规则场景）
                    print(f"ℹ️  {source_name}规则已规范（跳过@@补全）：{rule}")

                # 提取完整域名
                matched = False
                for pattern_name, pattern in SUPPORTED_RULE_PATTERNS.items():
                    match = pattern.match(rule)
                    if not match:
                        continue

                    domain = match.group(1).strip()
                    if not is_valid_domain(domain):
                        print(f"⚠️  {source_name}无效域名：{domain}（规则：{rule}）")
                        break

                    rule_type = "DOMAIN-SUFFIX"
                    valid_rules.append((rule_type, domain, action))
                    matched = True
                    print(f"✅  {source_name}解析成功：{rule} → 域名[{domain}]")
                    break

                if not matched:
                    unsupported_count += 1
                    print(f"⚠️  {source_name}无法提取域名：{rule}")

    # 规则去重
    before_dedup = len(valid_rules)
    valid_rules = deduplicate_rules(valid_rules)
    duplicate_count = before_dedup - len(valid_rules)
    if duplicate_count > 0:
        print(f"\n🔍 规则去重：移除{duplicate_count}条重复规则")

    return valid_rules, total_count, unsupported_count, duplicate_count

# -------------------------- 4. 规则转换（严格遵循官方语法，无改动） --------------------------
def convert_to_clash(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    block = ["payload:"]
    allow = ["payload:"]
    for rule_type, target, action in rules:
        if rule_type == "DOMAIN-SUFFIX":
            clash_rule = f"  - '+.{target}'"
        else:
            continue
        if action == "REJECT":
            block.append(clash_rule)
        else:
            allow.append(clash_rule)
    if len(block) == 1:
        block.append("  - '+.example.com'")
    if len(allow) == 1:
        allow.append("  - '+.example.com'")
    return block, allow

def convert_to_surge(rules: List[Tuple[str, str, str]]) -> Tuple[List[str], List[str]]:
    block = []
    allow = []
    for rule_type, target, action in rules:
        # Surge官方语法：放行=DIRECT，拦截=REJECT（无任何自定义改动）
        surge_policy = "REJECT" if action == "REJECT" else "DIRECT"
        surge_rule = f"{rule_type},{target},{surge_policy}"
        if action == "REJECT":
            block.append(surge_rule)
        else:
            allow.append(surge_rule)
    return block, allow

# -------------------------- 5. Mihomo编译与主流程 --------------------------
def compile_mihomo(clash_block_path: str) -> None:
    if not os.path.exists(Config.MIHOMO_TOOL):
        print(f"\n❌ Mihomo工具不存在：{Config.MIHOMO_TOOL}")
        return
    cmd = [Config.MIHOMO_TOOL, "convert-ruleset", Config.RULE_TYPE, "yaml", clash_block_path, Config.OUTPUT["MIHOMO"]]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        mrs_size = os.path.getsize(Config.OUTPUT["MIHOMO"]) / 1024
        print(f"\n✅ Mihomo编译成功：{Config.OUTPUT['MIHOMO']}（{mrs_size:.2f} KB）")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Mihomo编译失败：{e.stderr.strip()}")

def main():
    print("=" * 60)
    print("📦 AdGuard（纯净规则）→ Surge/Clash 转换脚本（V2.1）")
    print("=" * 60)
    print(f"🔧 当前配置：白名单@@自动补全={Config.ALLOW_AUTO_ADD_AT}（已适配纯净规则）")

    # 1. 解析规则
    print("\n【1/4】解析纯净AdGuard规则...")
    valid_rules, total_count, unsupported_count, duplicate_count = parse_adguard_rules()
    valid_count = len(valid_rules)
    conversion_rate = (valid_count / total_count * 100) if total_count > 0 else 0

    print(f"\n📊 解析统计：")
    print(f"  - 总规则数：{total_count} 条（纯净规则）")
    print(f"  - 有效转换数：{valid_count} 条（转化率：{conversion_rate:.1f}%）")
    print(f"  - 不可转换数：{unsupported_count} 条")
    print(f"  - 重复规则数：{duplicate_count} 条")

    if valid_count == 0:
        print("\n⚠️  无有效规则可转换，终止")
        return

    # 2. 转换Clash
    print("\n【2/4】转换为Clash规则...")
    clash_block, clash_allow = convert_to_clash(valid_rules)
    write_file(clash_block, Config.OUTPUT["CLASH_BLOCK"])
    write_file(clash_allow, Config.OUTPUT["CLASH_ALLOW"])
    print(f"✅ Clash规则：拦截（{len(clash_block)-1}条）、放行（{len(clash_allow)-1}条）")

    # 3. 转换Surge
    print("\n【3/4】转换为Surge规则（官方语法）...")
    surge_block, surge_allow = convert_to_surge(valid_rules)
    write_file(surge_block, Config.OUTPUT["SURGE_BLOCK"])
    write_file(surge_allow, Config.OUTPUT["SURGE_ALLOW"])
    print(f"✅ Surge规则示例：")
    print(f"  - 放行：{surge_allow[0] if surge_allow else '无'}（符合Surge官方DIRECT策略）")
    print(f"  - 拦截：{surge_block[0] if surge_block else '无'}（符合Surge官方REJECT策略）")

    # 4. 编译Mihomo
    print("\n【4/4】编译Mihomo规则...")
    compile_mihomo(Config.OUTPUT["CLASH_BLOCK"])

    print("\n" + "=" * 60)
    print("🎉 纯净规则转换完成！")
    print("=" * 60)

if __name__ == "__main__":
    main()
