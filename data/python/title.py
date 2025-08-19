import datetime
import pytz
import os
from pathlib import Path
from typing import Dict, List
import re

# 头信息模板（保持不变）
ADBLOCK_HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: {title}
! Homepage: https://github.com/045200/ad-filter
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于{adblocker}的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

ALLOW_HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: {title}
! Homepage: https://github.com/045200/ad-filter
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: {adblocker}白名单规则，用于防止误杀正常网站
! Total count: {line_count}
"""

HOSTS_HEADER_TEMPLATE = """# Title: {title}
# Homepage: https://github.com/045200/ad-filter
# Expires: 12 Hours
# Version: {timestamp}（北京时间）
# Description: {description}
# Total count: {line_count}
#
# 注意：此文件为Hosts规则，适用于任何支持Hosts广告过滤的软件
"""

# 广告拦截器配置（保持不变）
ADBLOCKERS = {
    "adp": {"name": "Adblock Plus", "desc": "Adblock Plus"},
    "ubo": {"name": "uBlock Origin", "desc": "uBlock Origin"},
    "adg": {"name": "AdGuard", "desc": "AdGuard"},
    "adh": {"name": "AdGuard Home", "desc": "AdGuard Home"},
    "clash": {"name": "Clash", "desc": "Clash"},
    "surge": {"name": "Surge", "desc": "Surge"},
    "pihole": {"name": "Pi-hole", "desc": "Pi-hole"}
}

def get_beijing_time() -> str:
    """获取当前北京时间"""
    utc_time = datetime.datetime.now(pytz.timezone('UTC'))
    return utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

def count_valid_lines(lines: list, comment_char: str = '!') -> int:
    """统计有效行数（非空且非注释行）"""
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith(comment_char):
            count += 1
    return count

def get_target_files(base_dir: Path) -> Dict[str, List[str]]:
    """获取目标文件列表（仅保留adblock_xxx.txt、allow_xxx.txt、hosts.txt，删除adblock.txt等）"""
    adblock_files = []
    allow_files = []
    hosts_files = []

    for file_path in base_dir.glob("*.txt"):
        file_name = file_path.name

        # 仅保留带拦截器标识的黑名单文件（如adblock_ubo.txt）
        if file_name.startswith("adblock_") and any(
            file_name == f"adblock_{ab}.txt" for ab in ADBLOCKERS
        ):
            adblock_files.append(file_name)

        # 仅保留带拦截器标识的白名单文件（如allow_ubo.txt）
        elif file_name.startswith("allow_") and any(
            file_name == f"allow_{ab}.txt" for ab in ADBLOCKERS
        ):
            allow_files.append(file_name)
            
        # 保留hosts文件
        elif file_name == "hosts.txt":
            hosts_files.append(file_name)

    return {
        "adblock": adblock_files,
        "allow": allow_files,
        "hosts": hosts_files
    }

def process_rule_files(target_files: Dict[str, List[str]], base_dir: Path) -> None:
    """处理规则文件，添加标准头信息（逻辑不变，仅处理筛选后的文件）"""
    beijing_time = get_beijing_time()
    processed_count = 0

    # 处理黑名单文件
    for file_name in target_files["adblock"]:
        file_path = base_dir / file_name
        ab_key = file_name.replace("adblock_", "").replace(".txt", "")

        if not file_path.exists():
            print(f"⚠️ 黑名单文件不存在，跳过处理: {file_name}")
            continue

        try:
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                line_count = count_valid_lines(lines)
                original_content = ''.join(lines)

            ab_info = ADBLOCKERS.get(ab_key, {"name": ab_key, "desc": ab_key})
            new_content = ADBLOCK_HEADER_TEMPLATE.format(
                title=f"{ab_info['name']} 去广告规则",
                timestamp=beijing_time,
                adblocker=ab_info["desc"],
                line_count=line_count
            ) + original_content.lstrip('\ufeff')

            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)

            print(f"✅ 已处理黑名单: {file_name} | 规则总数: {line_count}")
            processed_count += 1

        except Exception as e:
            print(f"❌ 处理 {file_name} 出错: {str(e)}")

    # 处理白名单文件
    for file_name in target_files["allow"]:
        file_path = base_dir / file_name
        ab_key = file_name.replace("allow_", "").replace(".txt", "")

        if not file_path.exists():
            print(f"⚠️ 白名单文件不存在，跳过处理: {file_name}")
            continue

        try:
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                line_count = count_valid_lines(lines)
                original_content = ''.join(lines)

            ab_info = ADBLOCKERS.get(ab_key, {"name": ab_key, "desc": ab_key})
            new_content = ALLOW_HEADER_TEMPLATE.format(
                title=f"{ab_info['name']} 白名单规则",
                timestamp=beijing_time,
                adblocker=ab_info["desc"],
                line_count=line_count
            ) + original_content.lstrip('\ufeff')

            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)

            print(f"✅ 已处理白名单: {file_name} | 规则总数: {line_count}")
            processed_count += 1

        except Exception as e:
            print(f"❌ 处理 {file_name} 出错: {str(e)}")
            
    # 处理hosts文件
    for file_name in target_files["hosts"]:
        file_path = base_dir / file_name

        if not file_path.exists():
            print(f"⚠️ hosts文件不存在，跳过处理: {file_name}")
            continue

        try:
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                line_count = count_valid_lines(lines, comment_char='#')
                original_content = ''.join(lines)

            new_content = HOSTS_HEADER_TEMPLATE.format(
                title="广告拦截 Hosts 规则",
                timestamp=beijing_time,
                description="适用于任何支持Hosts广告过滤的软件",
                line_count=line_count
            ) + original_content.lstrip('\ufeff')

            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)

            print(f"✅ 已处理 hosts: {file_name} | 规则总数: {line_count}")
            processed_count += 1

        except Exception as e:
            print(f"❌ 处理 {file_name} 出错: {str(e)}")

    return processed_count

def update_readme(base_dir: Path) -> bool:
    """更新README.md，新增各拦截器的规则统计"""
    try:
        # 1. 收集所有拦截器的规则计数
        stats = {}
        # 初始化所有拦截器的统计（默认为0）
        for ab_key, ab_info in ADBLOCKERS.items():
            stats[ab_key] = {
                "name": ab_info["name"],
                "adblock_count": 0,  # 拦截规则数量
                "allow_count": 0     # 白名单规则数量
            }

        # 2. 读取拦截规则文件的计数
        for ab_key in ADBLOCKERS:
            adblock_file = base_dir / f"adblock_{ab_key}.txt"
            if adblock_file.exists():
                with open(adblock_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("! Total count:"):
                            count = line.split(":")[1].strip()
                            stats[ab_key]["adblock_count"] = count
                            break

        # 3. 读取白名单规则文件的计数
        for ab_key in ADBLOCKERS:
            allow_file = base_dir / f"allow_{ab_key}.txt"
            if allow_file.exists():
                with open(allow_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("! Total count:"):
                            count = line.split(":")[1].strip()
                            stats[ab_key]["allow_count"] = count
                            break

        # 4. 读取hosts文件的计数
        hosts_count = 0
        hosts_file = base_dir / "hosts.txt"
        if hosts_file.exists():
            with open(hosts_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("# Total count:"):
                        hosts_count = line.split(":")[1].strip()
                        break

        # 5. 准备替换内容
        beijing_time = get_beijing_time()
        readme_path = base_dir / 'README.md'
        if not readme_path.exists():
            raise FileNotFoundError("README.md not found")

        with open(readme_path, 'r+', encoding='utf-8') as f:
            content = f.read()

            # 替换更新时间
            content = re.sub(
                r'更新时间:.*', 
                f'更新时间: {beijing_time} （北京时间）', 
                content, 
                flags=re.MULTILINE
            )

            # 替换Hosts规则数量
            content = re.sub(
                r'Hosts规则数量.*', 
                f'Hosts规则数量: {hosts_count}', 
                content, 
                flags=re.MULTILINE
            )

            # 新增各拦截器的规则统计（按ADBLOCKERS顺序）
            for ab_key, ab_stats in stats.items():
                # 替换拦截规则数量（假设README中有类似 `Adblock Plus 拦截规则数量: ...` 的占位符）
                content = re.sub(
                    rf'{ab_stats["name"]} 拦截规则数量:.*',
                    f'{ab_stats["name"]} 拦截规则数量: {ab_stats["adblock_count"]}',
                    content,
                    flags=re.MULTILINE
                )
                # 替换白名单规则数量（假设README中有类似 `Adblock Plus 白名单规则数量: ...` 的占位符）
                content = re.sub(
                    rf'{ab_stats["name"]} 白名单规则数量:.*',
                    f'{ab_stats["name"]} 白名单规则数量: {ab_stats["allow_count"]}',
                    content,
                    flags=re.MULTILINE
                )

            # 写回更新后的内容
            f.seek(0)
            f.truncate()
            f.write(content)

        print("✨ 已成功更新README.md中的各拦截器规则统计")
        return True

    except Exception as e:
        print(f"❌ 更新README失败: {str(e)}")
        return False

if __name__ == "__main__":
    github_workspace = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    base_dir = Path(github_workspace)

    print("="*50)
    print(f"📁 工作空间目录: {base_dir.absolute()}")
    print(f"🔍 支持的广告拦截器: {', '.join(ADBLOCKERS.keys())}")
    print("="*50)

    target_files = get_target_files(base_dir)

    print("检测到的黑名单文件:")
    for file in target_files["adblock"]:
        print(f" - {file}")

    print("\n检测到的白名单文件:")
    for file in target_files["allow"]:
        print(f" - {file}")
        
    print("\n检测到的hosts文件:")
    for file in target_files["hosts"]:
        print(f" - {file}")

    print("\n" + "="*50)

    try:
        processed_count = process_rule_files(target_files, base_dir)
        print(f"\n✨ 规则头信息处理完成! 共更新 {processed_count} 个文件")
        
        print("\n" + "="*50)
        print("🔄 开始更新README.md文件...")
        if update_readme(base_dir):
            print("✨ README.md更新成功!")
        else:
            print("❌ README.md更新失败")
    except Exception as e:
        print(f"🛑 主流程错误: {str(e)}")
