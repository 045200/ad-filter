import os
import glob
import re
from pathlib import Path
from collections import defaultdict

ADGUARD_RULE_PATTERN = re.compile(
    # 基础拦截规则
    r'^(\|\|[\w.-]+[^\/\s]*(?:\$[^$\s]+)?)|'      # 域名规则
    r'(^\/.+\/[ims]*\$(?:~?[\w,;=-]+)?)|'         # 正则规则
    
    # 白名单规则
    r'(^@@\|\|[\w.-]+[^\/\s]*(?:\$[^$\s]+)?)|'    # 域名白名单
    r'(^@@\/.+\/[ims]*\$(?:~?[\w,;=-]+)?)|'       # 正则白名单
    
    # DNS规则（AdGuard Home）
    r'(^\d+\.\d+\.\d+\.\d+\s+[\w.-]+)|'           # Hosts格式
    r'(^\d+\.\d+\.\d+\.\d+\/\d+\s+[\w.-]+)|'      # CIDR格式
    r'(^\|\|[\w.-]+\^\$dnstype=[\w,]+)|'          # DNS类型过滤
    
    # 元素规则
    r'(^##[^#\s]+)|'                              # 元素隐藏
    r'(^#@#[^#\s]+)|'                             # 元素隐藏例外
    r'(^\$\$.+)|'                                 # JS/CSS注入
    r'(^@@\$\$.+)|'                               # JS/CSS注入例外
    
    # 高级修饰符
    r'(^\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?)|' # 文档级拦截
    r'(^@@\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?)|'# 文档级例外
    r'(^\|\|[\w.-]+\^\$popup)|'                   # 弹窗拦截
    r'(^\|\|[\w.-]+\^\$client=~?[\w,.-]+)|'       # 客户端过滤
    r'(^\|\|[\w.-]+\^\$app=~?[\w-]+)|'            # 应用过滤
    
    # 通用规则
    r'(^\*[^$]+\$[^$]+)|'                         # 通用拦截
    r'(^@@\*[^$]+\$[^$]+)'                        # 通用例外
)

def is_block_rule(line):
    return (line.startswith(('||', '|', '/', '*', '##', '$$')) and not line.startswith('@@')

def is_allow_rule(line):
    return line.startswith('@@') or '$dnstype=' in line or '$client=' in line

def clean_rules(content):
    return '\n'.join([line for line in content.splitlines() 
                     if line.strip() and ADGUARD_RULE_PATTERN.match(line.strip())])

def merge_files(output_file, input_pattern):
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in glob.glob(input_pattern):
            try:
                with open(file, 'r', encoding='utf-8', errors='replace') as infile:
                    content = infile.read().strip()
                    if content:
                        outfile.write(clean_rules(content) + '\n')
            except Exception:
                continue

def deduplicate_file(filepath):
    try:
        with open(filepath, 'r+', encoding='utf-8') as f:
            seen = set()
            unique_lines = []
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                norm = re.sub(r'\s+', '', stripped).lower()
                if norm not in seen:
                    seen.add(norm)
                    unique_lines.append(line)
            f.seek(0)
            f.writelines(unique_lines)
            f.truncate()
    except Exception:
        pass

def optimize_rules(rules):
    block_rules = []
    allow_rules = []
    for rule in rules:
        stripped = rule.strip()
        if not stripped:
            continue
        if is_allow_rule(stripped):
            allow_rules.append(rule)
        elif is_block_rule(stripped):
            block_rules.append(rule)
    return block_rules, allow_rules

def main():
    os.chdir('tmp')
    
    # 合并并分类规则
    merge_files('combined.txt', '*.txt')
    with open('combined.txt', 'r', encoding='utf-8') as f:
        rules = f.read().splitlines()
    
    block_rules, allow_rules = optimize_rules(rules)
    
    # 写入优化后的规则文件
    with open('adblock.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(block_rules))
    
    with open('allow.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(allow_rules))
    
    # 去重处理
    deduplicate_file('adblock.txt')
    deduplicate_file('allow.txt')
    
    # 移动文件
    target_dir = Path('../')
    target_dir.mkdir(exist_ok=True)
    Path('adblock.txt').rename(target_dir / 'adblock.txt')
    Path('allow.txt').rename(target_dir / 'allow.txt')

if __name__ == '__main__':
    main()