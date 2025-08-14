import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 折中方案核心匹配规则
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^?(\$~?[\w,=-]+)?|'  # 域名规则+基础修饰符
    r'^@@##.+|'                           # 元素隐藏例外
    r'^@@/[^/]+/|'                        # 正则例外
    r'^@@\d+\.\d+\.\d+\.\d+'              # IP例外
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'     # 域名规则+基础修饰符
    r'^/[\w/-]+/|'                        # 正则规则
    r'^##.+|'                             # 元素隐藏
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+'      # Hosts格式
)

def clean_rules(content, pattern):
    """通用规则清理函数"""
    content = re.sub(r'^[!#].*$\n', '', content, flags=re.MULTILINE)
    return '\n'.join(line for line in content.splitlines() if pattern.search(line))

def extract_allow_rules(content):
    """从黑名单内容中提取白名单规则"""
    # 匹配黑名单中可能存在的例外规则（如@@开头的规则）
    return '\n'.join(line for line in content.splitlines() 
                   if line.startswith('@@') and ALLOW_PATTERN.search(line))

print("合并拦截规则")
with open('combined_adblock.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('adblock*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

# 处理黑名单并提取潜在白名单
with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
    block_content = f.read()
    extracted_allow = extract_allow_rules(block_content)  # 新增提取逻辑
    cleaned_block = clean_rules(block_content, BLOCK_PATTERN)

with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_block)

print("合并白名单规则")
with open('combined_allow.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('allow*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

# 合并提取的白名单规则
with open('combined_allow.txt', 'r', encoding='utf-8') as f:
    allow_content = f.read() + '\n' + extracted_allow  # 合并提取的规则
    cleaned_allow = clean_rules(allow_content, ALLOW_PATTERN)

with open('cleaned_allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)

print("生成最终规则")
with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
    f.write('\n' + cleaned_allow)

# 最终白名单文件（包含从黑名单提取的规则）
with open('allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)  # 直接使用已清理的白名单内容

# 文件移动和去重
target_dir = Path('../')
target_dir.mkdir(exist_ok=True)

def deduplicate_file(filepath):
    """专业去重函数（保留顺序且不区分大小写）"""
    with open(filepath, 'r+', encoding='utf-8') as f:
        seen = set()
        unique_lines = []
        for line in f:
            lower_line = line.lower()
            if lower_line not in seen:
                seen.add(lower_line)
                unique_lines.append(line)
        f.seek(0)
        f.writelines(unique_lines)
        f.truncate()

Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

print("规则去重")
for file in [target_dir / 'adblock.txt', target_dir / 'allow.txt']:
    if file.exists():
        deduplicate_file(file)

print("处理完成")