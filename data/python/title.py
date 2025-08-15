import datetime
import pytz
from pathlib import Path
from typing import Dict

HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: ad-filter
! Homepage: https://github.com/045200/ad-filter
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

def get_beijing_time() -> str:
    """获取当前北京时间"""
    utc_time = datetime.datetime.now(pytz.timezone('UTC'))
    return utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

def count_valid_lines(lines: list) -> int:
    """统计有效行数（非空且非注释行）"""
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('!'):
            count += 1
    return count

def process_rule_files(target_files: Dict[str, str], base_dir: Path) -> None:
    """处理规则文件，添加标准头信息（简化版）"""
    beijing_time = get_beijing_time()

    for file_name in target_files:
        file_path = base_dir / file_name

        if not file_path.exists():
            print(f"⚠️ 文件不存在，跳过处理: {file_name}")
            continue

        try:
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                line_count = count_valid_lines(lines)
                original_content = ''.join(lines)

            # 生成新内容
            new_content = HEADER_TEMPLATE.format(
                timestamp=beijing_time,
                line_count=line_count
            ) + original_content.lstrip('\ufeff')

            # 写回文件
            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)

            print(f"✅ 已处理 {file_name} | 规则总数: {line_count}")

        except Exception as e:
            print(f"❌ 处理 {file_name} 出错: {str(e)}")

if __name__ == "__main__":
    # 文件配置（文件名: 文件类型）
    TARGET_FILES = {
        'adblock.txt': 'adblock',
        'allow.txt': 'allow',
        'dns.txt': 'dns'
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