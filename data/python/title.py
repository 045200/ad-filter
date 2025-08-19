#!/usr/bin/env python3
"""
规则文件头信息处理器 (GitHub CI优化版)
• 自动更新规则文件头信息 | 智能处理 | 高性能
• 支持文件: adblock.txt, allow.txt, dns.txt, hosts.txt, ads.yaml
• 自动检测文件编码 | 保留原始换行符
"""

import datetime
import os
import sys
from pathlib import Path
from typing import Set, List, Tuple, Optional

# === 配置区 ===
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())  # 统一工作区路径
TARGET_FILES = {'adblock.txt', 'allow.txt', 'dns.txt', 'hosts.txt', 'ads.yaml'}

HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: EasyAds
! Homepage: https://github.com/045200/EasyAds
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

# === 时区处理 ===
try:
    from zoneinfo import ZoneInfo
    beijing_tz = ZoneInfo("Asia/Shanghai")
except ImportError:
    import pytz
    beijing_tz = pytz.timezone("Asia/Shanghai")

def get_beijing_time() -> str:
    """获取当前北京时间（高效版）"""
    return datetime.datetime.now(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')

def detect_encoding(file_path: Path) -> str:
    """智能检测文件编码"""
    encodings = ['utf-8', 'latin-1', 'gbk', 'gb2312']
    for encoding in encodings:
        try:
            with file_path.open('r', encoding=encoding) as f:
                f.read(1024)  # 读取部分内容验证
            return encoding
        except UnicodeDecodeError:
            continue
    return 'utf-8'  # 默认回退

def count_valid_lines(content: str) -> int:
    """高效统计有效规则行数"""
    return sum(1 for line in content.splitlines() 
               if line.strip() and not line.startswith('!'))

def extract_existing_header(content: str) -> Tuple[Optional[str], str]:
    """提取并分离现有头信息"""
    header_end = content.find('\n\n')  # 查找头信息结束位置
    if header_end == -1:
        return None, content
    
    # 检查是否包含标准头标识
    header_candidate = content[:header_end]
    if '[Adblock Plus 2.0]' in header_candidate:
        return header_candidate, content[header_end+2:]
    
    return None, content

def process_file(file_path: Path, timestamp: str) -> bool:
    """
    高效处理单个文件
    返回: 是否成功处理
    """
    if not file_path.exists():
        print(f"⚠️ 跳过不存在的文件: {file_path.name}")
        return False
    
    try:
        # 检测文件编码
        encoding = detect_encoding(file_path)
        
        # 读取文件内容
        with file_path.open('r', encoding=encoding) as f:
            content = f.read()
        
        # 分离现有头信息
        _, rule_content = extract_existing_header(content)
        
        # 统计有效规则行数
        line_count = count_valid_lines(rule_content)
        
        # 准备新内容
        new_header = HEADER_TEMPLATE.format(
            timestamp=timestamp,
            line_count=line_count
        )
        new_content = new_header + rule_content
        
        # 写入文件（保留原始编码）
        with file_path.open('w', encoding=encoding) as f:
            f.write(new_content)
        
        print(f"✅ 已更新 {file_path.name} (规则数: {line_count})")
        return True
    
    except Exception as e:
        print(f"❌ 处理 {file_path.name} 失败: {str(e)}")
        return False

def main():
    """主处理流程"""
    print("🚀 规则文件头信息处理器启动")
    print(f"工作目录: {WORKSPACE}")
    
    timestamp = get_beijing_time()
    success_count = 0
    rules_dir = Path(WORKSPACE)
    
    # 验证目录
    if not rules_dir.exists():
        print(f"❌ 错误: 目录不存在 - {rules_dir}")
        sys.exit(1)
    
    # 处理所有目标文件
    for filename in TARGET_FILES:
        file_path = rules_dir / filename
        if process_file(file_path, timestamp):
            success_count += 1
    
    # 结果摘要
    print("\n" + "=" * 50)
    print(f"处理完成! 成功更新 {success_count}/{len(TARGET_FILES)} 个文件")
    print(f"更新时间: {timestamp}")
    print("=" * 50)
    
    if success_count == 0:
        sys.exit(1)

if __name__ == "__main__":
    main()