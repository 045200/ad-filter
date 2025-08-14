import os
import glob
import re
from pathlib import Path

# 支持四大拦截器的完整规则正则（严格模式）
STRICT_RULE_PATTERN = re.compile(
    r'^(\|\|[\w.-]+\^[^\s]*)|'                  # 基础域名规则: ||example.com^
    r'(^\/.+\/[ims]*\$[^\s]*)|'                 # 正则规则: /ads/*$script
    r'(^@@\|\|[\w.-]+\^[^\s]*)|'                # 白名单: @@||example.com^
    r'(^\d+\.\d+\.\d+\.\d+\s+[\w.-]+)|'        # Hosts规则: 0.0.0.0 example.com
    r'(^\|\|[\w.-]+\^\$[a-z-]+(?:=[^,\s]+)?)|'  # 高级过滤: ||example.com^$dnstype=A
    r'(^##[^#\s]+)|'                            # 元素隐藏: ##div.ad
    r'(^#@#[^#\s]+)|'                           # 元素隐藏例外: #@#div.ad
    r'(^\$\$[^\s]+)|'                           # JS/CSS注入: $$script.js
    r'(^@@\$\$[^\s]+)|'                         # JS/CSS注入例外: @@$$script.js
    r'(^\*[^\s]+\$[^\s]+)|'                     # 通用规则: *$3p
    r'(^@@\*[^\s]+\$[^\s]+)'                    # 通用例外: @@*$3p
)

def is_valid_rule(line):
    """严格验证规则有效性（拒绝任何注释和元信息）"""
    line = line.strip()
    return bool(line) and STRICT_RULE_PATTERN.match(line) and not line.startswith(('!', '# ', '//'))

def process_rules(file_pattern):
    """处理规则文件：读取+清洗+去重"""
    rules = set()
    for filepath in glob.glob(file_pattern):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    # 移除行内注释（保留$后的参数）
                    clean_line = re.sub(r'\s*[#!].*$', '', line).strip()
                    if is_valid_rule(clean_line):
                        rules.add(clean_line)
        except Exception as e:
            print(f"跳过文件 {filepath} - 错误: {e}")
    return sorted(rules, key=lambda x: (not x.startswith('@@'), x.lower()))

def main():
    os.chdir('tmp')

    # 处理拦截规则（adblock*.txt → adblock.txt）
    with open('../adblock.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(process_rules('adblock*.txt')))

    # 处理白名单规则（allow*.txt → allow.txt）
    with open('../allow.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(process_rules('allow*.txt')))

    print("规则处理完成：\n- ../adblock.txt\n- ../allow.txt")

if __name__ == '__main__':
    main()