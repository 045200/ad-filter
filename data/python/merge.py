import os
import glob
import re
from pathlib import Path
from collections import defaultdict

# 全语法规则覆盖（基于第二个脚本增强）
FULL_RULE_PATTERN = re.compile(
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
    r'(^@@\*[^$]+\$[^$]+)|'                       # 通用例外
    
    # 从第一个脚本补充的规则
    r'(^\|\|[\w.-]+\^\$[a-z-]+(?:=[^,\s]+)?)|'    # 高级过滤
    r'(^@@\*[^\s]+\$[^\s]+)'                      # 通用例外增强
)

def is_valid_rule(line):
    """严格验证规则有效性（拒绝任何注释和元信息）"""
    line = line.strip()
    return bool(line) and FULL_RULE_PATTERN.match(line) and not line.startswith(('!', '# ', '//'))

def process_rules(file_pattern, rule_type):
    """独立处理黑名单或白名单规则"""
    rules = set()
    for filepath in glob.glob(file_pattern):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    # 移除行内注释（保留$后的参数）
                    clean_line = re.sub(r'\s*[#!].*$', '', line).strip()
                    if is_valid_rule(clean_line):
                        # 根据rule_type过滤规则
                        if rule_type == 'block' and is_block_rule(clean_line):
                            rules.add(clean_line)
                        elif rule_type == 'allow' and is_allow_rule(clean_line):
                            rules.add(clean_line)
        except Exception as e:
            print(f"跳过文件 {filepath} - 错误: {e}")
    return sorted(rules, key=lambda x: (not x.startswith('@@'), x.lower()))

def is_block_rule(line):
    """判断是否为拦截规则（来自第二个脚本增强）"""
    line = line.strip()
    return (line.startswith(('||', '|', '/', '*', '##', '$$')) and not line.startswith('@@')

def is_allow_rule(line):
    """判断是否为白名单规则（来自第二个脚本增强）"""
    line = line.strip()
    return (line.startswith('@@') or 
            '$dnstype=' in line or 
            '$client=' in line or
            '$app=' in line or
            line.startswith('#@#'))

def deduplicate_rules(rules):
    """增强的去重逻辑（结合两个脚本的优点）"""
    seen = set()
    unique_rules = []
    for rule in rules:
        # 标准化比较（忽略大小写和空白）
        norm = re.sub(r'\s+', '', rule).lower()
        if norm not in seen:
            seen.add(norm)
            unique_rules.append(rule)
    return unique_rules

def main():
    os.chdir('tmp')

    # 独立处理黑名单规则（adblock*.txt → adblock.txt）
    block_rules = process_rules('adblock*.txt', 'block')
    block_rules = deduplicate_rules(block_rules)
    with open('../adblock.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(block_rules))

    # 独立处理白名单规则（allow*.txt → allow.txt）
    allow_rules = process_rules('allow*.txt', 'allow')
    allow_rules = deduplicate_rules(allow_rules)
    with open('../allow.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(allow_rules))

    print("规则处理完成：\n- ../adblock.txt\n- ../allow.txt")

if __name__ == '__main__':
    main()