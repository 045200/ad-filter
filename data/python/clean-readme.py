#!/usr/bin/env python3
"""
README更新器 (GitHub CI优化版)
• 自动更新规则计数和时间戳 | 高性能 | 安全写入
• 支持文件: adblock.txt, dns.txt, allow.txt, hosts.txt, adb.yaml
• 自动处理时区 | 智能计数 | 错误恢复
"""

import re
import os
import sys
import datetime
from pathlib import Path
from typing import Dict, Optional

# === 配置区 ===
WORKSPACE = os.getenv('WORKSPACE', os.getcwd())  # 统一工作区路径
RULE_FILES = {
    'adblock': 'adblock.txt',
    'dns': 'dns.txt',
    'allow': 'allow.txt',
    'hosts': 'hosts.txt',
    'clash': 'adb.yaml'
}
README_FILE = 'README.md'

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

def count_valid_lines(file_path: Path) -> int:
    """高效统计有效规则行数"""
    count = 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith(('#', '!')):
                    count += 1
    except Exception as e:
        print(f"⚠️ 统计 {file_path.name} 失败: {str(e)}")
        return -1
    return count

def get_rule_counts(rules_dir: Path) -> Dict[str, int]:
    """获取所有规则文件的有效行数"""
    counts = {}
    for name, filename in RULE_FILES.items():
        file_path = rules_dir / filename
        if file_path.exists():
            counts[name] = count_valid_lines(file_path)
        else:
            print(f"⚠️ 规则文件不存在: {filename}")
            counts[name] = -1
    return counts

def update_readme(readme_path: Path, counts: Dict[str, int], timestamp: str) -> bool:
    """安全更新README.md文件"""
    if not readme_path.exists():
        print(f"❌ README文件不存在: {readme_path}")
        return False
    
    # 定义替换模式
    replacements = {
        r'更新时间:.*': f'更新时间: {timestamp}（北京时间）',
        r'拦截规则数量:.*': f'拦截规则数量: {counts["adblock"]}',
        r'DNS拦截规则数量:.*': f'DNS拦截规则数量: {counts["dns"]}',
        r'白名单规则数量:.*': f'白名单规则数量: {counts["allow"]}',
        r'hosts规则数量:.*': f'Hosts规则数量: {counts["hosts"]}',
        r'clash规则数量:.*': f'Clash规则数量: {counts["clash"]}'
    }
    
    try:
        # 使用临时文件安全写入
        temp_path = readme_path.with_suffix('.tmp')
        
        # 读取并更新内容
        with open(readme_path, 'r', encoding='utf-8') as src, \
             open(temp_path, 'w', encoding='utf-8') as dest:
            
            for line in src:
                updated = False
                for pattern, repl in replacements.items():
                    if re.match(pattern, line.strip()):
                        dest.write(repl + '\n')
                        updated = True
                        break
                if not updated:
                    dest.write(line)
        
        # 替换原始文件
        temp_path.replace(readme_path)
        return True
    
    except Exception as e:
        print(f"❌ 更新README失败: {str(e)}")
        if temp_path.exists():
            temp_path.unlink()
        return False

def main():
    """主处理流程"""
    print("🚀 README更新器启动")
    print(f"工作目录: {WORKSPACE}")
    
    # 获取路径
    rules_dir = Path(WORKSPACE)
    readme_path = rules_dir / README_FILE
    
    # 验证目录
    if not rules_dir.exists():
        print(f"❌ 错误: 目录不存在 - {rules_dir}")
        sys.exit(1)
    
    # 获取规则计数
    timestamp = get_beijing_time()
    counts = get_rule_counts(rules_dir)
    
    # 更新README
    if update_readme(readme_path, counts, timestamp):
        print(f"✅ 成功更新 {README_FILE}")
        print("=" * 50)
        print(f"更新时间: {timestamp}")
        for name, count in counts.items():
            print(f"{name.capitalize()}规则: {count}")
        print("=" * 50)
        sys.exit(0)
    else:
        print("❌ 更新失败")
        sys.exit(1)

if __name__ == "__main__":
    main()