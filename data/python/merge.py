import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 增强的规则匹配（全覆盖语法）
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^?(\$~?[\w,=-]+)?|'  # 域名白名单
    r'^@@##.+|'                           # 元素隐藏例外
    r'^@@/[^/]+/[ims]*(?:\$~?[\w,;=-]+)?|' # 增强：支持正则修饰符
    r'^@@\d+\.\d+\.\d+\.\d+(?:\/\d+)?|'   # 增强：支持CIDR
    r'^@@\$\$.+|'                          # JS/CSS例外
    r'^\|\|[\w.-]+\^\$dnstype=[\w,]+'      # 新增：DNS例外
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'     # 域名拦截
    r'^/[\w/-]+/[ims]*(?:\$~?[\w,;=-]+)?|' # 增强：支持正则修饰符
    r'^##.+|'                             # 元素隐藏
    r'^\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s+[\w.-]+|' # 增强：支持CIDR
    r'^\$\$.+|'                           # JS/CSS注入
    r'^\|\|[\w.-]+\^\$popup'              # 新增：弹窗拦截
)

def strict_clean(line):
    """新增：严格清理非规则内容"""
    line = re.sub(r'^\s*[!#].*$', '', line)    # 行首注释
    line = re.sub(r'\s+[!#].*$', '', line)     # 行尾注释
    line = re.sub(r'\[Adblock.*\]', '', line)  # 元信息
    return line.strip()

def clean_rules(content, pattern):
    """原函数增强：严格清理后过滤"""
    content = re.sub(r'^[!#].*$\n', '', content, flags=re.MULTILINE)
    return '\n'.join(
        line for line in (
            strict_clean(line) for line in content.splitlines()
        ) if line and pattern.search(line)
    )

def extract_allow_rules(content):
    """完全保留原提取逻辑（仅增强规则匹配）"""
    return '\n'.join(
        line for line in content.splitlines()
        if strict_clean(line).startswith('@@') 
        and ALLOW_PATTERN.search(strict_clean(line))
    )

# ▼▼▼▼▼▼▼▼▼▼ 完全保留原脚本处理流程 ▼▼▼▼▼▼▼▼▼▼
print("合并拦截规则")
with open('combined_adblock.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('adblock*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

print("提取白名单规则")
with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
    block_content = f.read()
    extracted_allow = extract_allow_rules(block_content)  # 关键保留
    cleaned_block = clean_rules(block_content, BLOCK_PATTERN)

with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_block)

print("合并白名单规则")
with open('combined_allow.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('allow*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

print("生成最终白名单")
with open('combined_allow.txt', 'r', encoding='utf-8') as f:
    allow_content = f.read() + ('\n' + extracted_allow if extracted_allow else '')
    cleaned_allow = clean_rules(allow_content, ALLOW_PATTERN)

with open('allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)

print("生成最终黑名单（含白名单）")
with open('../adblock.txt', 'w', encoding='utf-8') as f:  # 修改输出路径
    with open('cleaned_adblock.txt', 'r', encoding='utf-8') as block_file:
        f.write(block_file.read() + '\n' + cleaned_allow)

Path('allow.txt').rename('../allow.txt')  # 修改输出路径

print("处理完成！输出文件：")
print("- ../adblock.txt")
print("- ../allow.txt")