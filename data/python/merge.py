import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# AdGuard/AdGuard Home完整语法规则（2024最新版）
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'  # 基础域名例外
    r'^@@##.+|'                          # 元素隐藏例外
    r'^@@\|\|[\w.-]+\^\$document|'       # 文档级例外
    r'^@@\|\|[\w.-]+\^\$generichide|'    # 通用隐藏例外
    r'^@@\|\|[\w.-]+\^\$elemhide|'       # 元素隐藏例外
    r'^@@\d+\.\d+\.\d+\.\d+|'            # IP例外
    r'^@@/[^/]+/\$important|'            # 重要正则例外
    r'^@@\|\|[\w.-]+\^\$ctag|'           # 内容类型例外
    r'^@@\|\|[\w.-]+\^\$client=\S+|'     # 客户端白名单
    r'^@@\|\|[\w.-]+\^\$app=\w+|'        # 应用例外
    r'^@@\|\|[\w.-]+\^\$denyallow|'      # 部分放行
    r'^@@\|\|[\w.-]+\^\$redirect=nooptext|'  # 重定向例外
    r'^@@\|\|[\w.-]+\^\$removeparam=\w+' # 参数保留
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'    # 基础域名规则
    r'^\|\|[\w.-]+\^\$document|'         # 文档级拦截
    r'^\|\|[\w.-]+\^\$generichide|'      # 通用隐藏
    r'^\|\|[\w.-]+\^\$elemhide|'         # 元素隐藏
    r'^##.+|'                            # 基础元素隐藏
    r'^#\?#.+|'                          # 扩展CSS选择器
    r'^#@#.+|'                           # 旧版元素隐藏例外
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+|'   # Hosts格式
    r'^\|\|[\w.-]+\^\$important|'        # 重要规则
    r'^\|\|[\w.-]+\^\$badfilter|'        # 坏过滤器
    r'^\|\|[\w.-]+\^\$ctag|'             # 内容类型过滤
    r'^/[\w/-]+/|'                       # 正则规则
    r'^\|\|[\w.-]+\^\$client=\S+|'       # 客户端限定
    r'^\|\|[\w.-]+\^\$app=\w+|'          # 应用限定
    r'^\|\|[\w.-]+\^\$redirect=\w+|'     # 重定向规则
    r'^\|\|[\w.-]+\^\$removeparam=\w+|'  # 参数移除
    r'^\|\|[\w.-]+\^\$all|'              # 全协议规则
    r'^\|\|[\w.-]+\^\$cookie|'           # Cookie规则
    r'^\|\|[\w.-]+\^\$csp|'              # CSP规则
    r'^\|\|[\w.-]+\^\$replace=\w+|'      # 内容替换
    r'^\|\|[\w.-]+\^\$hls'               # HLS规则
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
    # 保留AdGuard配置注释（!开头）和有效规则
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
                if filepath.name == 'adblock.txt' and not BLOCK_PATTERN.search(line):
                    print(f"警告：第{i}行可能无效 - {line[:50]}...")
                elif filepath.name == 'allow.txt' and not ALLOW_PATTERN.search(line):
                    print(f"警告：第{i}行可能无效 - {line[:50]}...")

for file in [target_dir / 'adblock.txt', target_dir / 'allow.txt']:
    validate_rules(file)

print("处理完成！生成文件：")
print(f"- {target_dir / 'adblock.txt'}")
print(f"- {target_dir / 'allow.txt'}")