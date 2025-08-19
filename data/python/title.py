#!/usr/bin/env python3
"""
规则文件与README更新器 (GitHub CI优化版)
• 自动更新规则文件头信息 & README计数和时间戳
• 支持文件: adblock.txt, dns.txt, allow.txt, hosts.txt, adb.yaml
• 智能处理不同格式 | 高性能 | 错误恢复
"""

import re
import os
import sys
import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

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

# === 头信息模板 ===
HEADER_TEMPLATES = {
    'adblock': """[Adblock Plus 2.0]
! Title: EasyAds
! Homepage: https://github.com/045200/EasyAds
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
""",
    
    'dns': """[Adblock Plus 2.0]
! Title: EasyAds (DNS)
! Homepage: https://github.com/045200/EasyAds
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: DNS级广告拦截规则，适用于AdGuard Home等DNS过滤器
! Total count: {line_count}
""",
    
    'allow': """[Adblock Plus 2.0]
! Title: EasyAds Allowlist
! Homepage: https://github.com/045200/EasyAds
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 广告拦截例外规则，避免误杀正常内容
! Total count: {line_count}
""",
    
    'hosts': """# Title: EasyAds Hosts
# Homepage: https://github.com/045200/EasyAds
# Expires: 12 Hours
# Version: {timestamp}（北京时间）
# Description: 系统级Hosts广告拦截规则，适用于所有平台
# Total count: {line_count}
#
# 注意：此文件适用于AdGuard、AdGuard Home及系统hosts文件
""",
    
    'clash': """# Title: EasyAds Clash Rules
# Homepage: https://github.com/045200/EasyAds
# Expires: 12 Hours
# Version: {timestamp}（北京时间）
# Description: Clash规则集，专为Clash系列代理工具优化
# Total count: {line_count}
#
# 支持: Clash, Clash Premium, Clash.Meta等
"""
}

def get_beijing_time() -> str:
    """获取当前北京时间（高效版）"""
    return datetime.datetime.now(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')

def count_valid_lines(file_path: Path) -> int:
    """高效统计有效规则行数（根据文件类型适配）"""
    count = 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                
                # 根据文件类型确定注释符号
                if file_path.name == 'hosts.txt':
                    if not stripped.startswith('#'):
                        count += 1
                elif file_path.name == 'adb.yaml':
                    if not stripped.startswith('#'):
                        count += 1
                else:  # Adblock格式文件
                    if not stripped.startswith(('!', '#')):
                        count += 1
    except Exception as e:
        print(f"⚠️ 统计 {file_path.name} 失败: {str(e)}")
        return -1
    return count

def get_rule_counts(rules_dir: Path) -> Dict[str, int]:
    """获取所有规则文件的有效行数并缓存结果"""
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
        updated = False

        # 读取并更新内容
        with open(readme_path, 'r', encoding='utf-8') as src, \
             open(temp_path, 'w', encoding='utf-8') as dest:

            for line in src:
                line_stripped = line.strip()
                matched = False
                
                for pattern, repl in replacements.items():
                    if re.match(pattern, line_stripped):
                        dest.write(repl + '\n')
                        matched = True
                        updated = True
                        break
                
                if not matched:
                    dest.write(line)

        # 替换原始文件
        if updated:
            temp_path.replace(readme_path)
            return True
        else:
            print("⚠️ README内容未更新，可能模式不匹配")
            temp_path.unlink()
            return False

    except Exception as e:
        print(f"❌ 更新README失败: {str(e)}")
        if temp_path.exists():
            temp_path.unlink()
        return False

def detect_encoding(file_path: Path) -> str:
    """智能检测文件编码"""
    encodings = ['utf-8', 'utf-16', 'latin-1', 'gbk', 'gb2312']
    for encoding in encodings:
        try:
            with file_path.open('r', encoding=encoding) as f:
                f.read(1024)
            return encoding
        except UnicodeDecodeError:
            continue
    return 'utf-8'  # 默认回退

def update_rule_headers(rules_dir: Path, counts: Dict[str, int], timestamp: str) -> int:
    """更新所有规则文件的头部信息（使用缓存的计数）"""
    success_count = 0
    
    for rule_type, filename in RULE_FILES.items():
        file_path = rules_dir / filename
        if not file_path.exists():
            print(f"⚠️ 跳过不存在的规则文件: {filename}")
            continue
        
        try:
            # 获取对应模板
            template = HEADER_TEMPLATES.get(rule_type, "")
            if not template:
                print(f"⚠️ 无可用模板: {rule_type}")
                continue
                
            # 获取缓存的计数
            line_count = counts.get(rule_type, -1)
            if line_count < 0:
                print(f"⚠️ 无效计数: {rule_type}")
                continue
                
            # 生成新头部
            new_header = template.format(
                timestamp=timestamp,
                line_count=line_count
            )
            
            # 检测文件编码
            encoding = detect_encoding(file_path)
            
            # 读取文件内容（跳过旧头部）
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            
            # 移除现有头部
            clean_content = content
            for marker in ['[Adblock Plus 2.0]', '# Title:', '! Title:']:
                if marker in content:
                    parts = content.split(marker, 1)
                    if len(parts) > 1:
                        clean_content = parts[1].split('\n', 1)[1] if '\n' in parts[1] else ""
                    break
            
            # 写入新内容
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(new_header + clean_content.strip() + '\n')
            
            print(f"✅ 已更新 {filename} 头部 (规则数: {line_count})")
            success_count += 1
            
        except Exception as e:
            print(f"❌ 更新 {filename} 头部失败: {str(e)}")
    
    return success_count

def main():
    """主处理流程"""
    print("🚀 规则文件与README更新器启动")
    print(f"工作目录: {WORKSPACE}")
    
    # 获取路径
    rules_dir = Path(WORKSPACE)
    readme_path = rules_dir / README_FILE
    
    # 验证目录
    if not rules_dir.exists():
        print(f"❌ 错误: 目录不存在 - {rules_dir}")
        sys.exit(1)
    
    # 获取当前时间
    timestamp = get_beijing_time()
    
    # 统计规则计数（缓存结果）
    counts = get_rule_counts(rules_dir)
    
    # 更新README
    readme_success = update_readme(readme_path, counts, timestamp)
    
    # 更新规则文件头部
    headers_success = update_rule_headers(rules_dir, counts, timestamp)
    
    # 结果摘要
    print("\n" + "=" * 50)
    print(f"更新时间: {timestamp}")
    print("规则统计:")
    for name, count in counts.items():
        print(f"  {name.capitalize():<8}: {count}")
    
    print("\n操作结果:")
    print(f"  README更新: {'成功' if readme_success else '失败'}")
    print(f"  规则头部更新: {headers_success}/{len(RULE_FILES)} 个文件")
    print("=" * 50)
    
    # 退出状态
    if readme_success and headers_success >= len(RULE_FILES) // 2:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()