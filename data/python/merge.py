import os
import glob
import re
from pathlib import Path
from collections import OrderedDict

os.chdir('tmp')

# AdGuard/AdGuard Home 白名单规则正则（仅支持AdGuard语法）
ADG_ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'      # 基础白名单
    r'^@@##.+|'                               # 元素隐藏例外
    r'^@@/[^/]+/[ims]*(?:\$~?[\w,;=-]+)?|'   # 正则白名单
    r'^@@\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+[\w.-]+|'  # IP/CIDR白名单（Hosts格式）
    r'^@@\$\$.+|'                             # JS/CSS注入例外
    r'^@@\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级例外
    r'^@@\|\|[\w.-]+\^\$app=~?[\w-]+|'       # 应用例外
    r'^@@\|\|[\w.-]+\^\$client=~?[\w,.-]+|'  # 客户端例外
    r'^@@\|\|[\w.-]+\^\$dnstype=[\w,]+|'     # DNS类型例外（AdGuard Home特有）
    r'^@@/REGEX/'                             # 正则表达式白名单（AdGuard Home）
)

# AdGuard/AdGuard Home 拦截规则正则（仅支持AdGuard语法）
ADG_BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'        # 基础拦截
    r'^/[\w/-]+/[ims]*(?:\$~?[\w,;=-]+)?|'   # 正则拦截
    r'^##.+|'                                # 元素隐藏
    r'^\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+[\w.-]+|'  # Hosts拦截
    r'^\$\$.+|'                              # JS/CSS注入
    r'^\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级拦截
    r'^\|\|[\w.-]+\^\$popup|'                # 弹窗拦截
    r'^\|\|[\w.-]+\^\$app=~?[\w-]+|'         # 应用拦截
    r'^\|\|[\w.-]+\^\$client=~?[\w,.-]+|'    # 客户端拦截
    r'^\|\|[\w.-]+\^\$dnstype=[\w,]+|'       # DNS类型拦截（AdGuard Home特有）
    r'^/REGEX/'                              # 正则表达式拦截（AdGuard Home）
)

def strict_clean(line):
    """严格清理非规则内容（支持所有注释类型）"""
    line = line.lstrip('\ufeff').strip()
    line = re.sub(r'^\s*[!#].*$', '', line)       # 标准注释
    line = re.sub(r'\s+[!#].*$', '', line)        # 行尾注释
    line = re.sub(r'^\s*//.*$', '', line)         # 双斜线注释
    line = re.sub(r'/\*.*?\*/', '', line)         # 多行注释
    line = re.sub(r'^\s*;.*$', '', line)          # 分号注释
    line = re.sub(r'^\[Adblock.*\]$', '', line)   # 元信息
    return re.sub(r'\s+', ' ', line).strip()

def is_adguard_rule(line):
    """检查是否为AdGuard/AdGuard Home规则"""
    # AdGuard基本语法检查
    if re.match(r'^(\|\||##|@@\|\|)[\w.-]+[\^\s]', line):
        return True
    # AdGuard扩展语法检查
    if re.search(r'\$(app|client|dnstype|document|popup)=', line):
        return True
    # AdGuard Home正则表达式规则
    if re.match(r'^/[\w/-]+/|^@@/[\w/-]+/', line):
        return True
    # Hosts格式规则
    if re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+', line):
        return True
    return False

def advanced_deduplicate(rules):
    """增强去重（标准化+保留顺序）"""
    seen = OrderedDict()
    for rule in rules:
        # 标准化：忽略大小写和多余空格
        norm = re.sub(r'[\s]', '', rule).lower()
        if norm not in seen:
            seen[norm] = rule
    return list(seen.values())

# ▼▼▼ 主处理流程 ▼▼▼
print("合并拦截规则...")
block_content = ''
for file in glob.glob('adblock*.txt'):
    with open(file, 'r', encoding='utf-8-sig', errors='replace') as f:
        block_content += f.read() + '\n'

print("提取白名单规则...")
extracted_allow = []
for line in block_content.splitlines():
    cleaned = strict_clean(line)
    if cleaned.startswith('@@') and ADG_ALLOW_PATTERN.search(cleaned):
        extracted_allow.append(cleaned)

print("筛选AdGuard/AdGuard Home规则...")
adg_block = []
adg_allow = []
for line in block_content.splitlines():
    cleaned = strict_clean(line)
    if not cleaned:
        continue
        
    # 处理拦截规则
    if not cleaned.startswith('@@') and ADG_BLOCK_PATTERN.search(cleaned):
        if is_adguard_rule(cleaned):
            adg_block.append(cleaned)
    
    # 处理白名单规则（已在前面提取）
    if cleaned in extracted_allow and is_adguard_rule(cleaned):
        adg_allow.append(cleaned)

print("生成最终文件...")
with open('../adblock.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(adg_block + adg_allow)))

with open('../allow.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(extracted_allow)))

print("处理完成！输出文件：")
print("- adblock.txt (AdGuard/AdGuard Home全功能规则)")
print("- allow.txt (AdGuard/AdGuard Home白名单规则)")