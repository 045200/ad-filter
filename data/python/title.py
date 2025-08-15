import datetime
import pytz
from pathlib import Path
from typing import Dict, List, Pattern
import re

HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: ad-filter
! Homepage: https://github.com/045200/ad-filter
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

# 通用规则模式
COMMON_PATTERNS = {
    'comment': re.compile(r'^!'),
    'empty': re.compile(r'^\s*$'),
    'basic': re.compile(r'^[^/*|@"!]+$'),
    'regex': re.compile(r'^/.*/$'),
    'hosts': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+'),
    'domain': re.compile(r'^\|\|([^*^|^~^@^/]+)\^?$')
}

# 白名单特有规则模式
ALLOWLIST_PATTERNS = {
    'exception': re.compile(r'^@@'),
    'element_unhide': re.compile(r'^#@#'),
    'scriptlet_exception': re.compile(r'#@%#'),
    'content_exception': re.compile(r'^@@\|\|'),
    'document_exception': re.compile(r'^@@\$\$'),
    'extension_exception': re.compile(r'^@@\$\$extension'),
    'specific_exception': re.compile(r'^@@\|\|[^*]+\^([^*]*\*[^*]*)*$'),
    'wildcard_exception': re.compile(r'^@@\|\|[^*]+\*[^*]+\^$')
}

# 广告拦截规则模式
BLOCKLIST_PATTERNS = {
    'element_hiding': re.compile(r'^##'),
    'network': re.compile(r'^\|\|'),
    'scriptlet': re.compile(r'#%#'),
    'redirect': re.compile(r'\$redirect(-rule)?='),
    'removeparam': re.compile(r'\$removeparam=')
}

def get_beijing_time() -> str:
    """获取当前北京时间"""
    utc_time = datetime.datetime.now(pytz.timezone('UTC'))
    return utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

def is_allowlist_rule(line: str) -> bool:
    """专门处理白名单规则识别"""
    line = line.strip()
    
    # 检查白名单特有规则
    for pattern in ALLOWLIST_PATTERNS.values():
        if pattern.search(line):
            return True
    
    # 检查通用有效规则
    if (COMMON_PATTERNS['basic'].match(line) or 
        COMMON_PATTERNS['regex'].match(line) or 
        COMMON_PATTERNS['hosts'].match(line)):
        return True
    
    return False

def is_blocklist_rule(line: str) -> bool:
    """广告拦截规则识别"""
    line = line.strip()
    
    # 检查拦截规则
    for pattern in BLOCKLIST_PATTERNS.values():
        if pattern.search(line):
            return True
    
    # 检查通用有效规则
    if (COMMON_PATTERNS['basic'].match(line) or 
        COMMON_PATTERNS['regex'].match(line) or 
        COMMON_PATTERNS['domain'].match(line)):
        return True
    
    return False

def is_dns_rule(line: str) -> bool:
    """DNS规则识别"""
    line = line.strip()
    return (COMMON_PATTERNS['hosts'].match(line) or 
            COMMON_PATTERNS['domain'].match(line))

def process_rule_files(target_files: Dict[str, str], base_dir: Path) -> None:
    """处理规则文件，添加标准头信息（增强版）"""
    beijing_time = get_beijing_time()

    for file_name, file_type in target_files.items():
        file_path = base_dir / file_name

        if not file_path.exists():
            print(f"⚠️ 文件不存在，跳过处理: {file_name}")
            continue

        try:
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                
                # 根据文件类型选择验证函数
                if file_type == 'allow':
                    line_count = sum(1 for line in lines if is_allowlist_rule(line))
                elif file_type == 'dns':
                    line_count = sum(1 for line in lines if is_dns_rule(line))
                else:
                    line_count = sum(1 for line in lines if is_blocklist_rule(line))

                original_content = ''.join(lines)

            # 生成新内容
            new_content = HEADER_TEMPLATE.format(
                timestamp=beijing_time,
                line_count=line_count
            ) + original_content.lstrip('\ufeff')

            # 写回文件
            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)

            print(f"✅ 已处理 {file_name} | 规则总数: {line_count} | 文件类型: {file_type}")

        except Exception as e:
            print(f"❌ 处理 {file_name} 出错: {str(e)}")

if __name__ == "__main__":
    # 文件配置（文件名: 文件类型）
    TARGET_FILES = {
        'adblock.txt': 'adblock',
        'allow.txt': 'allow',
        'dns.txt': 'dns',
        'adb.txt': 'adb',
        'adw.txt': 'adw',
        'add.txt': 'add'
    }

    # 路径配置
    script_dir = Path(__file__).parent
    base_dir = script_dir.parent.parent  # 假设脚本在 /data/python/ 目录下

    # 调试信息
    print("="*50)
    print(f"📁 仓库根目录: {base_dir.absolute()}")
    print(f"🔍 正在处理以下文件: {', '.join(TARGET_FILES.keys())}")
    print("="*50)

    try:
        process_rule_files(TARGET_FILES, base_dir)
        print("✨ 所有文件处理完成")
    except Exception as e:
        print(f"🛑 主流程错误: {str(e)}")