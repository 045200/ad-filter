import sys
from pathlib import Path
from typing import List, Dict

# 尝试导入 AdGuard 规则解析库
try:
    from pyadguard import AdGuardRule
    ADGUARD_AVAILABLE = True
except ImportError:
    print("Error: Required library 'pyadguard' not found. Install with: pip install pyadguard", file=sys.stderr)
    sys.exit(1)

# 路径配置
ROOT_DIR = Path(__file__).absolute().parent.parent.parent
INPUT_FILE = ROOT_DIR / 'adblock.txt'
OUTPUT_FILES = {
    'adb': ROOT_DIR / 'adb.txt',  # 全部有效规则
    'adw': ROOT_DIR / 'adw.txt',  # 白名单规则
    'dns': ROOT_DIR / 'add.txt'   # DNS相关规则（含重写）
}

def load_rules(filepath: Path) -> List[str]:
    """读取规则文件，跳过空行和注释"""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('!')]

def classify_rules(rules: List[str]) -> Dict[str, List[str]]:
    """使用AdGuard规则引擎进行分类"""
    result = {'adb': [], 'adw': [], 'dns': []}
    
    for rule_text in rules:
        try:
            rule = AdGuardRule(rule_text)
            
            # 1. 所有有效规则存入adb.txt
            result['adb'].append(rule_text)
            
            # 2. 白名单规则存入adw.txt
            if rule.is_exception:
                result['adw'].append(rule_text)
            
            # 3. DNS规则存入add.txt（包括普通DNS规则和重写规则）
            if rule.is_dns_rule or '$dnsrewrite=' in rule_text.lower():
                result['dns'].append(rule_text)
                
        except ValueError as e:
            print(f"Invalid rule skipped: {rule_text} - Error: {e}", file=sys.stderr)
    
    return result

def save_rules(rules: List[str], path: Path):
    """保存规则到指定文件"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))

def main():
    # 检查输入文件是否存在
    if not INPUT_FILE.exists():
        print(f"Error: Input file not found: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    # 加载并分类规则
    rules = load_rules(INPUT_FILE)
    if not rules:
        print("Error: No valid rules found in input file", file=sys.stderr)
        sys.exit(1)

    classified = classify_rules(rules)
    
    # 保存分类结果
    for key, path in OUTPUT_FILES.items():
        save_rules(classified[key], path)
    
    # 输出统计信息
    print(f"Total valid rules: {len(classified['adb'])}")
    print(f"Whitelist rules: {len(classified['adw'])}")
    print(f"DNS-related rules: {len(classified['dns'])}")

if __name__ == "__main__":
    main()