import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 增强版AdGuard/AdGuard Home规则匹配模式
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'  # 基础域名例外
    r'^@@##.+|'                          # 元素隐藏例外
    r'^@@\|\|[\w.-]+\^\$[a-z]+|'        # 各种修饰符例外
    r'^@@\d+\.\d+\.\d+\.\d+|'           # IP例外
    r'^@@/[^/]+/|'                       # 正则例外
    r'^@@\|https?://|'                   # URL例外
    r'^@@\|\*\.|'                        # 通配符例外
    r'^@@\|\|[\w.-]+$|'                  # 简单域名例外(无^结尾)
    r'^@@[\w.-]+\^|'                     # 简化的域名例外
    r'^@@\|\|[\w.-]+\^\$[a-z]+=[\w.-]+|' # 带值的修饰符
    r'^@@\|\|[\w.-]+\*?\^|'              # 带通配符的域名
    r'^@@\|\|[\w.-]+\.\*\|'              # 子域名通配
    r'^@@\|\|[\w*.-]+\^?[\w*.-]*'        # 更宽松的匹配
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'   # 基础域名规则
    r'^\|\|[\w.-]+\^\$[a-z]+|'          # 各种修饰符
    r'^##.+|'                            # 元素隐藏
    r'^#\?#.+|'                          # 扩展CSS选择器
    r'^#@#.+|'                           # 旧版元素隐藏例外
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+|'   # Hosts格式
    r'^/[\w/-]+/|'                       # 正则规则
    r'^\|\|[\w.-]+\^\$[a-z]+=\w+|'       # 带值的修饰符
    r'^\|\|\*\.'                         # 通配符规则
    r'^\|\|[\w.-]+\^?\*|'                # 通配符变体
    r'^\|\|[\w.-]+\.\*|'                 # 另一种通配符
    r'^\|\|[\w.-]+$'                     # 简单域名规则
)

def normalize_rules(content):
    """规则标准化处理"""
    # 统一域名大小写
    content = re.sub(r'(\|\|[\w.-]+\^)', lambda m: m.group(1).lower(), content)
    # 标准化修饰符格式
    content = re.sub(r'\$(~?domain)=([\w.-]+)', 
                    lambda m: f'${m.group(1)}={m.group(2).lower()}', content)
    return content

def clean_rules(content, pattern):
    """增强版规则清理函数"""
    lines = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # 保留注释和空行
        if line.startswith('!') or pattern.search(line):
            lines.append(line)
    return '\n'.join(lines)

def extract_allow_rules(content):
    """精确提取白名单规则"""
    return '\n'.join(line for line in content.splitlines() 
                   if line.startswith('@@') and ALLOW_PATTERN.search(line))

print("合并拦截规则...")
with open('combined_adblock.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('adblock*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            content = infile.read()
            outfile.write(normalize_rules(content) + '\n')

print("处理黑名单规则...")
with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
    block_content = f.read()
    extracted_allow = extract_allow_rules(block_content)
    cleaned_block = clean_rules(block_content, BLOCK_PATTERN)

with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_block)

print("合并白名单规则...")
with open('combined_allow.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('allow*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            content = infile.read()
            outfile.write(normalize_rules(content) + '\n')

print("处理白名单规则...")
with open('combined_allow.txt', 'r', encoding='utf-8') as f:
    allow_content = f.read() + '\n' + extracted_allow
    cleaned_allow = clean_rules(allow_content, ALLOW_PATTERN)

with open('cleaned_allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)

print("生成最终规则集...")
with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
    f.write('\n' + cleaned_allow)

with open('allow.txt', 'w', encoding='utf-8') as f:
    f.write(cleaned_allow)

# 文件处理
target_dir = Path('../')
target_dir.mkdir(exist_ok=True)

def deduplicate_file(filepath):
    """增强版去重函数（保留顺序+注释）"""
    with open(filepath, 'r+', encoding='utf-8') as f:
        seen = set()
        unique_lines = []
        for line in f:
            norm_line = line.lower().strip() if not line.startswith('!') else line
            if norm_line not in seen:
                seen.add(norm_line)
                unique_lines.append(line)
        f.seek(0)
        f.writelines(unique_lines)
        f.truncate()

Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

print("规则去重处理...")
for file in [target_dir / 'adblock.txt', target_dir / 'allow.txt']:
    if file.exists():
        deduplicate_file(file)

print("验证规则有效性...")
def validate_rules(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith('!'):
                if filepath.name == 'adblock.txt':
                    if not line.startswith('@@') and not BLOCK_PATTERN.search(line):
                        print(f"警告：第{i}行可能无效 - {line[:50]}...")
                elif filepath.name == 'allow.txt':
                    if not line.startswith('@@'):
                        print(f"警告：第{i}行不是白名单规则 - {line[:50]}...")
                    elif not ALLOW_PATTERN.search(line):
                        # 对白名单规则验证更宽松
                        if not re.match(r'^@@\|\|?[\w*.-]+[\^*]?', line):
                            print(f"警告：第{i}行可能无效 - {line[:50]}...")

for file in [target_dir / 'adblock.txt', target_dir / 'allow.txt']:
    validate_rules(file)

print("处理完成！生成文件：")
print(f"- {target_dir / 'adblock.txt'}")
print(f"- {target_dir / 'allow.txt'}")