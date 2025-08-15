import os
import glob
import re
from pathlib import Path
from collections import OrderedDict

os.chdir('tmp')

# 全覆盖规则正则（整合四大拦截器语法）
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^?(\$~?[\w,=-]+)?|'      # 基础白名单（全兼容）
    r'^@@##.+|'                               # 元素隐藏例外（AdGuard/uBO）
    r'^@@/[^/]+/[ims]*(?:\$~?[\w,;=-]+)?|'    # 正则白名单（AdGuard/uBO）
    r'^@@\d+\.\d+\.\d+\.\d+(?:\/\d+)?|'      # IP/CIDR白名单（全兼容）
    r'^@@\$\$.+|'                             # JS/CSS注入例外（AdGuard）
    r'^@@\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级例外（AdGuard/uBO）
    r'^@@\|\|[\w.-]+\^\$app=~?[\w-]+|'       # 应用例外（AdGuard）
    r'^\|\|[\w.-]+\^\$dnstype=[\w,]+|'       # DNS类型例外（AdGuard Home）
    r'^@@\|\|[\w.-]+\^\$client=~?[\w,.-]+'   # 客户端例外（AdGuard）
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'        # 基础拦截（全兼容）
    r'^/[\w/-]+/[ims]*(?:\$~?[\w,;=-]+)?|'   # 正则拦截（AdGuard/uBO）
    r'^##.+|'                                # 元素隐藏（全兼容）
    r'^\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+[\w.-]+|'  # Hosts拦截（全兼容）
    r'^\$\$.+|'                              # JS/CSS注入（AdGuard）
    r'^\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级拦截（AdGuard/uBO）
    r'^\|\|[\w.-]+\^\$popup|'                # 弹窗拦截（AdGuard）
    r'^\|\|[\w.-]+\^\$app=~?[\w-]+|'         # 应用拦截（AdGuard）
    r'^\|\|[\w.-]+\^\$client=~?[\w,.-]+|'    # 客户端拦截（AdGuard）
    r'^#@#.+|'                               # 元素隐藏例外（uBO）
    r'^\*\$[^\s,]+(?:,[^\s]+)*|'             # uBlock通用规则
    r'^\|\|[\w.-]+\^\$important|'            # 重要规则（uBO）
    r'^\.\./[\w/-]+'                         # 路径匹配（Brave/adblock-rust）
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

def categorize_rules(content, pattern):
    """规则分类（ABP/uBO/AdGuard）"""
    abp_rules, ub_rules, adg_rules = [], [], []
    for line in content.splitlines():
        cleaned = strict_clean(line)
        if not cleaned or not pattern.search(cleaned):
            continue
        # ABP兼容规则（基础语法）
        if re.match(r'^(\|\||##|#@#|@@\|\|)[\w.-]+[\^\s]', cleaned):
            abp_rules.append(cleaned)
        # uBO扩展语法
        if re.search(r'\$(document|popup|important|~?\w+=)', cleaned) or \
           re.match(r'^\*\$|\.\./', cleaned):
            ub_rules.append(cleaned)
        # AdGuard扩展语法
        if re.search(r'\$(app|client|dnstype)=|@@\$\$', cleaned):
            adg_rules.append(cleaned)
    return abp_rules, ub_rules, adg_rules

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
    if cleaned.startswith('@@') and ALLOW_PATTERN.search(cleaned):
        extracted_allow.append(cleaned)

print("分类处理规则...")
abp_block, ub_block, adg_block = categorize_rules(block_content, BLOCK_PATTERN)
abp_allow, ub_allow, adg_allow = categorize_rules('\n'.join(extracted_allow), ALLOW_PATTERN)

print("生成最终文件...")
with open('../abp.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(abp_block + abp_allow)))

with open('../ub.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(ub_block + ub_allow)))

with open('../adblock.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(adg_block + adg_allow)))

with open('../allow.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(advanced_deduplicate(extracted_allow)))

print("处理完成！输出文件：")
print("- abp.txt (Adblock Plus兼容规则)")
print("- ub.txt (uBlock Origin优化规则)")
print("- adblock.txt (AdGuard/AdGuardHome全功能规则)")
print("- allow.txt (跨拦截器白名单规则)")