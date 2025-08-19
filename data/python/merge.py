import os
import glob
import re
import time

# 路径设置
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())
TEMP_DIR = os.path.join(WORKSPACE, "tmp")
OUTPUT_DIR = WORKSPACE

# 预编译正则式 - 分别区分黑名单和白名单语法
# 黑名单规则：不带@@前缀的拦截规则
BLACKLIST_SYNTAX = re.compile(
    r'^(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'          # 基础域名拦截规则
    r'^/[\w\W]+/$|'                              # 正则拦截规则
    r'^##.+$|'                                   # 元素隐藏拦截规则
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$|'           # Hosts格式拦截规则
    r'^\|\|[\w.-]+\^\$dnstype=\w+$|'             # DNS类型拦截规则
    r'^\|\|[\w.-]+\^\$dnsrewrite=\w+$'           # DNS重写拦截规则
)

# 白名单规则：带@@前缀的允许规则
WHITELIST_SYNTAX = re.compile(
    r'^@@(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'        # 基础域名允许规则
    r'^@@/[\w\W]+/$|'                            # 正则允许规则
    r'^@@##.+$|'                                 # 元素隐藏允许规则
    r'^@@\|\|[\w.-]+\^\$dnstype=\w+$|'           # DNS类型允许规则
    r'^@@\|\|[\w.-]+\^\$dnsrewrite=NOERROR$'     # DNS重写允许规则
)

def clean_rules(content, syntax):
    """根据指定语法清理规则（黑名单/白名单）"""
    cleaned_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and syntax.match(stripped):
            cleaned_lines.append(stripped)
    return '\n'.join(cleaned_lines)

def merge_files(pattern, output_file, rule_syntax):
    """合并文件并应用对应规则语法过滤"""
    seen = set()  # 内存去重
    output_path = os.path.join(OUTPUT_DIR, output_file)

    with open(output_path, 'w', encoding='utf-8') as out:
        for file_path in glob.glob(os.path.join(TEMP_DIR, pattern)):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # 跳过空文件
                    if not content.strip():
                        continue

                    # 使用对应语法清理规则
                    cleaned = clean_rules(content, rule_syntax)

                    # 逐行去重写入
                    for line in cleaned.splitlines():
                        lower_line = line.lower()
                        if lower_line not in seen:
                            seen.add(lower_line)
                            out.write(line + '\n')
            except Exception as e:
                print(f"处理文件 {file_path} 时出错: {e}")
                continue

def main():
    print("🚀 启动规则合并引擎")
    start_time = time.time()

    # 确保目录存在
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 处理黑名单（使用黑名单语法）
    print("⏳ 处理拦截规则...")
    merge_files('adblock*.txt', 'adblock.txt', BLACKLIST_SYNTAX)

    # 处理白名单（使用白名单语法）
    print("⏳ 处理白名单规则...")
    merge_files('allow*.txt', 'allow.txt', WHITELIST_SYNTAX)

    # 输出结果统计
    elapsed = time.time() - start_time
    ad_size = os.path.getsize(os.path.join(OUTPUT_DIR, 'adblock.txt'))
    allow_size = os.path.getsize(os.path.join(OUTPUT_DIR, 'allow.txt'))

    print(f"✅ 合并完成! | 耗时: {elapsed:.1f}s")
    print(f"📊 拦截规则: {ad_size//1024}KB | 白名单: {allow_size//1024}KB")

if __name__ == "__main__":
    main()
