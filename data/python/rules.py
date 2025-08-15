import re
import sys
from pathlib import Path
from typing import List, Dict

# 引擎检测
try:
    from adblock import BlockRule
    ADBLOCK_AVAILABLE = True
except ImportError:
    ADBLOCK_AVAILABLE = False

# 路径配置
ROOT_DIR = Path(__file__).absolute().parent.parent.parent
INPUT_FILE = ROOT_DIR / 'adblock.txt'
OUTPUT_FILES = {
    'adb': ROOT_DIR / 'adb.txt',
    'adw': ROOT_DIR / 'adw.txt', 
    'dns': ROOT_DIR / 'add.txt'
}

def load_rules(filepath: Path) -> List[str]:
    """读取规则文件，跳过空行和注释"""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('!')]

def is_valid_rule(rule: str) -> bool:
    """规则有效性验证"""
    if ADBLOCK_AVAILABLE:
        try:
            BlockRule(rule)
            return True
        except (ValueError, AttributeError):
            return False
    return bool(re.match(
        r'^(@@|\|\|[\w.-]+\^|\d+\.\d+\.\d+\.\d+\s|/.*/[\w-]*$|[\w.-]+##|\$[\w-]+)',
        rule
    ))

def is_dns_rule(rule: str) -> bool:
    """DNS规则检测"""
    return (
        not rule.startswith(('@@', '##')) and 
        bool(re.match(r'^\|\|[\w.-]+\^|^\d+\.\d+\.\d+\.\d+\s', rule))
    )

def classify_rules(rules: List[str]) -> Dict[str, List[str]]:
    """规则分类处理"""
    result = {'adb': [], 'adw': [], 'dns': []}
    for rule in rules:
        if not is_valid_rule(rule):
            continue
            
        result['adb'].append(rule)
        if rule.startswith('@@'):
            result['adw'].append(rule)
        elif is_dns_rule(rule):
            result['dns'].append(rule)
    return result

def save_rules(rules: List[str], path: Path):
    """保存规则到文件"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))

def main():
    if not INPUT_FILE.exists():
        print(f"Error: Input file not found: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    rules = load_rules(INPUT_FILE)
    if not rules:
        print("Error: No valid rules in input file", file=sys.stderr)
        sys.exit(1)

    classified = classify_rules(rules)
    for key, path in OUTPUT_FILES.items():
        save_rules(classified[key], path)

    print(f"Total rules: {len(classified['adb'])}")
    print(f"Whitelist: {len(classified['adw'])}")
    print(f"DNS blacklist: {len(classified['dns'])}")

if __name__ == "__main__":
    main()