import re
import sys
from pathlib import Path
from adblock_rs import Rule  # pip install adblock-rs

# 路径配置（全部基于仓库根目录）
def get_root_path():
    """自动定位仓库根目录（脚本所在目录的父目录的父目录）"""
    script_path = Path(__file__).absolute()
    return script_path.parent.parent  # 假设脚本在 /repo-root/data/python/

ROOT_DIR = get_root_path()
INPUT_FILE = ROOT_DIR / 'adblock.txt'  # 输入文件（根目录）
OUTPUT_FILES = {                       # 输出文件（根目录）
    'adb': ROOT_DIR / 'adb.txt',       # AdGuard全规则
    'adw': ROOT_DIR / 'adw.txt',       # 白名单
    'dns': ROOT_DIR / 'add.txt'        # DNS黑名单
}

def load_rules(filepath: Path) -> list[str]:
    """加载规则文件（跳过注释/空行）"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [
                line.strip() for line in f 
                if line.strip() and not line.startswith('!')
            ]
    except UnicodeDecodeError:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return [
                line.strip() for line in f 
                if line.strip() and not line.startswith('!')
            ]

def is_valid_adguard_rule(rule: str) -> bool:
    """验证规则是否被AdGuard原生支持"""
    try:
        Rule(rule)
        return True
    except:
        return False

def is_dns_blacklist_rule(rule: str) -> bool:
    """检查是否是DNS黑名单规则（不含@@和元素隐藏）"""
    return (
        not rule.startswith('@@') and 
        not rule.startswith('##') and
        bool(re.match(r'^\|\|[\w.-]+\^|^\d+\.\d+\.\d+\.\d+', rule))
    )

def classify_rules(rules: list[str]) -> dict:
    """规则分类（严格分离白名单和DNS黑名单）"""
    return {
        'adb': [r for r in rules if is_valid_adguard_rule(r)],
        'adw': [r for r in rules if is_valid_adguard_rule(r) and r.startswith('@@')],
        'dns': [r for r in rules if is_valid_adguard_rule(r) and is_dns_blacklist_rule(r)],
    }

def save_rules(rules: list[str], output_path: Path):
    """保存规则到指定路径"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))

def main():
    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"❌ 错误：输入文件 {INPUT_FILE} 不存在", file=sys.stderr)
        sys.exit(1)

    # 处理规则
    rules = load_rules(INPUT_FILE)
    if not rules:
        print("❌ 错误：输入文件无有效规则", file=sys.stderr)
        sys.exit(1)
        
    classified = classify_rules(rules)
    
    # 保存输出文件
    for key, path in OUTPUT_FILES.items():
        save_rules(classified[key], path)
    
    # 打印结果
    print("✅ 处理完成！输出文件：")
    print(f"- {OUTPUT_FILES['adb']} (全规则: {len(classified['adb'])}条)")
    print(f"- {OUTPUT_FILES['adw']} (白名单: {len(classified['adw'])}条)")
    print(f"- {OUTPUT_FILES['dns']} (DNS黑名单: {len(classified['dns'])}条)")

if __name__ == "__main__":
    main()