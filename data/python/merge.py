import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 全覆盖规则正则（整合四大拦截器语法）
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^?(\$~?[\w,=-]+)?|'      # 基础白名单
    r'^@@##.+|'                               # 元素隐藏例外
    r'^@@/[^/]+/[ims]*(?:\$~?[\w,;=-]+)?|'    # 正则白名单（支持修饰符）
    r'^@@\d+\.\d+\.\d+\.\d+(?:\/\d+)?|'      # IP/CIDR白名单
    r'^@@\$\$.+|'                             # JS/CSS注入例外
    r'^@@\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级例外
    r'^@@\|\|[\w.-]+\^\$app=~?[\w-]+|'       # 应用例外
    r'^\|\|[\w.-]+\^\$dnstype=[\w,]+|'       # DNS类型例外
    r'^@@\|\|[\w.-]+\^\$client=~?[\w,.-]+'   # 客户端例外
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'        # 基础拦截
    r'^/[\w/-]+/[ims]*(?:\$~?[\w,;=-]+)?|'   # 正则拦截（支持修饰符）
    r'^##.+|'                                # 元素隐藏
    r'^\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+[\w.-]+|'  # Hosts/CIDR拦截
    r'^\$\$.+|'                              # JS/CSS注入
    r'^\|\|[\w.-]+\^\$document(?:,~?[\w,=-]+)?|'  # 文档级拦截
    r'^\|\|[\w.-]+\^\$popup|'                # 弹窗拦截
    r'^\|\|[\w.-]+\^\$app=~?[\w-]+|'         # 应用拦截
    r'^\|\|[\w.-]+\^\$client=~?[\w,.-]+|'    # 客户端拦截
    r'^#@#.+|'                               # 元素隐藏例外
    r'^\*\$[^\s,]+(?:,[^\s]+)*'              # uBlock通用规则
)

def strict_clean(line):
    """严格清理非规则内容（支持所有注释类型）"""
    # 处理BOM头和不可见字符
    line = line.lstrip('\ufeff').strip()
    # 移除所有类型注释
    line = re.sub(r'^\s*[!#].*$', '', line)       # 标准注释
    line = re.sub(r'\s+[!#].*$', '', line)        # 行尾注释
    line = re.sub(r'^\s*//.*$', '', line)         # 双斜线注释
    line = re.sub(r'/\*.*?\*/', '', line)         # 多行注释
    line = re.sub(r'^\s*;.*$', '', line)          # 分号注释
    # 移除元信息标签
    line = re.sub(r'^\[Adblock.*\]$', '', line)   # 元信息
    # 标准化空格
    line = re.sub(r'\s+', ' ', line).strip()
    return line

def clean_rules(content, pattern):
    """增强版规则清理（保持原函数名）"""
    return '\n'.join(
        line for line in (
            strict_clean(line) for line in content.splitlines()
        ) if line and pattern.search(line)
    )

def extract_allow_rules(content):
    """严格提取白名单规则（保留原逻辑）"""
    allow_lines = []
    for line in content.splitlines():
        cleaned = strict_clean(line)
        if cleaned.startswith('@@') and ALLOW_PATTERN.search(cleaned):
            allow_lines.append(cleaned)
    return '\n'.join(allow_lines)

# ▼▼▼▼▼▼▼▼▼▼ 完全保留原脚本处理流程 ▼▼▼▼▼▼▼▼▼▼
print("合并拦截规则...")
with open('combined_adblock.txt', 'w', encoding='utf-8-sig', errors='replace') as outfile:
    for file in glob.glob('adblock*.txt'):
        with open(file, 'r', encoding='utf-8-sig', errors='replace') as infile:
            outfile.write(infile.read() + '\n')

print("提取白名单规则...")
with open('combined_adblock.txt', 'r', encoding='utf-8-sig') as f:
    block_content = f.read()
    extracted_allow = extract_allow_rules(block_content)  # 关键保留
    cleaned_block = clean_rules(block_content, BLOCK_PATTERN)

with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_block)

print("合并白名单规则...")
with open('combined_allow.txt', 'w', encoding='utf-8-sig', errors='replace') as outfile:
    for file in glob.glob('allow*.txt'):
        with open(file, 'r', encoding='utf-8-sig', errors='replace') as infile:
            outfile.write(infile.read() + '\n')

print("生成最终白名单...")
with open('combined_allow.txt', 'r', encoding='utf-8-sig') as f:
    allow_content = f.read()
    if extracted_allow:
        allow_content += '\n' + extracted_allow
    cleaned_allow = clean_rules(allow_content, ALLOW_PATTERN)

with open('allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)

print("生成最终黑名单（含白名单）...")
with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
    f.write('\n' + cleaned_allow)

# ▼▼▼▼▼▼▼▼▼▼ 仅修改输出路径到根目录 ▼▼▼▼▼▼▼▼▼▼
def deduplicate_file(filepath):
    """增强去重（标准化比较）"""
    with open(filepath, 'r+', encoding='utf-8') as f:
        seen = set()
        unique_lines = []
        for line in f:
            norm = re.sub(r'\s+', '', line).lower()  # 标准化比较
            if norm not in seen:
                seen.add(norm)
                unique_lines.append(line)
        f.seek(0)
        f.writelines(unique_lines)
        f.truncate()

Path('cleaned_adblock.txt').rename('../adblock.txt')
Path('allow.txt').rename('../allow.txt')

print("规则去重...")
for file in ['../adblock.txt', '../allow.txt']:
    if Path(file).exists():
        deduplicate_file(file)

print("处理完成！输出文件：")
print("- ../adblock.txt")
print("- ../allow.txt")