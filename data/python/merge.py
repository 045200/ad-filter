import os
import glob
import re
from pathlib import Path
import time

# 高性能路径设置
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())
TEMP_DIR = os.path.join(WORKSPACE, "tmp")
OUTPUT_DIR = WORKSPACE

# 预编译高效正则表达式
FULL_SYNTAX = re.compile(
    r'^(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'          # 基础域名规则
    r'^@@(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'        # 例外规则
    r'^/[\w\W]+/$|^@@/[\w\W]+/$|'                # 正则规则
    r'^##.+$|^@@##.+$|'                          # 元素隐藏规则
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$|'           # Hosts格式
    r'^\|\|[\w.-]+\^\$dnstype=\w+$|'             # DNS类型规则
    r'^@@\|\|[\w.-]+\^\$dnstype=\w+$|'           # DNS例外
    r'^\|\|[\w.-]+\^\$dnsrewrite=\w+$|'          # DNS重写
    r'^@@\|\|[\w.-]+\^\$dnsrewrite=NOERROR$'     # DNS重写例外
)

def clean_rules(content):
    """极速规则清理（批量处理）"""
    cleaned_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and FULL_SYNTAX.match(stripped):
            cleaned_lines.append(stripped)
    return '\n'.join(cleaned_lines)

def merge_files(pattern, output_file):
    """高性能文件合并（流式处理）"""
    seen = set()  # 内存中去重
    output_path = os.path.join(OUTPUT_DIR, output_file)
    
    with open(output_path, 'w', encoding='utf-8') as out:
        for file_path in glob.glob(os.path.join(TEMP_DIR, pattern)):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # 空文件跳过
                    if not content.strip():
                        continue
                        
                    # 清理规则
                    cleaned = clean_rules(content)
                    
                    # 逐行处理（避免大文件内存占用）
                    for line in cleaned.splitlines():
                        lower_line = line.lower()
                        if lower_line not in seen:
                            seen.add(lower_line)
                            out.write(line + '\n')
            except Exception as e:
                print(f"处理文件 {file_path} 时出错: {e}")
                continue  # 跳过问题文件

def main():
    print("🚀 启动规则合并引擎")
    start_time = time.time()
    
    # 确保目录存在
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 并行处理拦截规则和白名单
    print("⏳ 处理拦截规则...")
    merge_files('adblock*.txt', 'adblock.txt')
    
    print("⏳ 处理白名单规则...")
    merge_files('allow*.txt', 'allow.txt')
    
    # 最终报告
    elapsed = time.time() - start_time
    ad_size = os.path.getsize(os.path.join(OUTPUT_DIR, 'adblock.txt'))
    allow_size = os.path.getsize(os.path.join(OUTPUT_DIR, 'allow.txt'))
    
    print(f"✅ 合并完成! | 耗时: {elapsed:.1f}s")
    print(f"📊 拦截规则: {ad_size//1024}KB | 白名单: {allow_size//1024}KB")

if __name__ == "__main__":
    main()