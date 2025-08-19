import os
import re
from pathlib import Path
from typing import Dict, List
import datetime
import pytz  # 注意：GitHub Actions 中需在 workflow 里用 pip install pytz


# 拦截器配置（保持不变，与 README 匹配）
ADBLOCKERS: Dict[str, Dict[str, str]] = {
    "adp": {"name": "Adblock Plus", "suffix": ".txt", "comment": "!", "has_allow": True},
    "ubo": {"name": "uBlock Origin", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adg": {"name": "AdGuard", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adh": {"name": "AdGuard Home", "suffix": ".txt", "comment": "#", "has_allow": True},
    "clash": {"name": "Clash", "suffix": ".yaml", "comment": "#", "has_allow": False},
    "surge": {"name": "Surge", "suffix": ".conf", "comment": "#", "has_allow": False},
    "pihole": {"name": "Pi-hole", "suffix": ".txt", "comment": "#", "has_allow": True}
}

# 头信息模板（保持不变）
ADBLOCK_HEADER = """{comment} Title: {title}
{comment} Homepage: https://github.com/045200/ad-filter
{comment} Expires: 12 Hours
{comment} Version: {timestamp}（北京时间）
{comment} Description: 适用于{adblocker}的拦截规则
{comment} Total count: {line_count}
"""

ALLOW_HEADER = """{comment} Title: {title}
{comment} Homepage: https://github.com/045200/ad-filter
{comment} Expires: 12 Hours
{comment} Version: {timestamp}（北京时间）
{comment} Description: {adblocker}专用白名单规则
{comment} Total count: {line_count}
"""

HOSTS_HEADER = """# Title: 广告拦截 Hosts 规则
# Homepage: https://github.com/045200/ad-filter
# Expires: 12 Hours
# Version: {timestamp}（北京时间）
# Description: 适用于任何支持Hosts过滤的软件
# Total count: {line_count}
"""


def get_beijing_time() -> str:
    """获取北京时间（兼容 GitHub Actions 环境）"""
    try:
        # GitHub Actions 时区为 UTC，需转换为北京时间
        return datetime.datetime.now(pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    except (ImportError, pytz.UnknownTimeZoneError):
        # 若 pytz 未安装，直接用 UTC+8 计算
        utc_now = datetime.datetime.utcnow()
        beijing_time = utc_now + datetime.timedelta(hours=8)
        return beijing_time.strftime("%Y-%m-%d %H:%M:%S")


def count_valid_lines(lines: List[str], comment_char: str) -> int:
    """统计有效行数（排除空行和注释行）"""
    return sum(1 for line in lines if line.strip() and not line.strip().startswith(comment_char))


def detect_files(base_dir: Path) -> Dict[str, Dict[str, Path]]:
    """检测根目录下的所有规则文件（所有文件均在根目录）"""
    detected = {
        "adblock": {},   # 主规则：{ab_key: Path}
        "allow": {},     # 白名单：{ab_key: Path}
        "hosts": None    # hosts文件路径
    }

    # 检测拦截器规则文件（根目录直接查找）
    for ab_key, ab_info in ADBLOCKERS.items():
        # 主规则文件：adblock_{ab_key}{suffix}（如 adblock_adp.txt）
        adblock_filename = f"adblock_{ab_key}{ab_info['suffix']}"
        adblock_path = base_dir / adblock_filename
        if adblock_path.exists() and adblock_path.is_file():
            detected["adblock"][ab_key] = adblock_path
        
        # 白名单文件（仅对has_allow=True）：allow_{ab_key}{suffix}
        if ab_info["has_allow"]:
            allow_filename = f"allow_{ab_key}{ab_info['suffix']}"
            allow_path = base_dir / allow_filename
            if allow_path.exists() and allow_path.is_file():
                detected["allow"][ab_key] = allow_path

    # 检测hosts文件（根目录，优先 hosts.txt，其次 hosts.conf）
    for suffix in (".txt", ".conf"):
        hosts_path = base_dir / f"hosts{suffix}"
        if hosts_path.exists() and hosts_path.is_file():
            detected["hosts"] = hosts_path
            break

    return detected


def process_rule_files(detected: Dict[str, Dict[str, Path]], timestamp: str) -> Dict[str, int]:
    """处理根目录下的规则文件，更新头信息并返回统计"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 处理主规则文件
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        try:
            with open(path, "r+", encoding="utf-8") as f:
                lines = f.readlines()
                valid_lines = count_valid_lines(lines, ab_info["comment"])
                header = ADBLOCK_HEADER.format(
                    comment=ab_info["comment"],
                    title=f"{ab_info['name']} 拦截规则",
                    timestamp=timestamp,
                    adblocker=ab_info["name"],
                    line_count=valid_lines
                )
                f.seek(0)
                f.write(header)
                f.writelines(lines)
                f.truncate()  # 截断旧内容，避免残留

            stats[ab_key]["rules"] = valid_lines
            print(f"✅ 处理 {ab_info['name']} 拦截规则：{valid_lines} 行")
        except Exception as e:
            print(f"❌ 处理 {ab_info['name']} 拦截规则失败：{str(e)}", flush=True)

    # 处理白名单文件
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        try:
            with open(path, "r+", encoding="utf-8") as f:
                lines = f.readlines()
                valid_lines = count_valid_lines(lines, ab_info["comment"])
                header = ALLOW_HEADER.format(
                    comment=ab_info["comment"],
                    title=f"{ab_info['name']} 白名单",
                    timestamp=timestamp,
                    adblocker=ab_info["name"],
                    line_count=valid_lines
                )
                f.seek(0)
                f.write(header)
                f.writelines(lines)
                f.truncate()

            stats[ab_key]["allow"] = valid_lines
            print(f"✅ 处理 {ab_info['name']} 白名单：{valid_lines} 行")
        except Exception as e:
            print(f"❌ 处理 {ab_info['name']} 白名单失败：{str(e)}", flush=True)

    # 处理hosts文件
    if detected["hosts"]:
        try:
            with open(detected["hosts"], "r+", encoding="utf-8") as f:
                lines = f.readlines()
                valid_lines = count_valid_lines(lines, "#")
                header = HOSTS_HEADER.format(
                    timestamp=timestamp,
                    line_count=valid_lines
                )
                f.seek(0)
                f.write(header)
                f.writelines(lines)
                f.truncate()

            stats["hosts"] = valid_lines
            print(f"✅ 处理 Hosts 文件：{valid_lines} 行")
        except Exception as e:
            print(f"❌ 处理 Hosts 文件失败：{str(e)}", flush=True)

    return stats


def update_readme(base_dir: Path, stats: Dict[str, int], timestamp: str) -> bool:
    """更新根目录下的 README.md 统计信息"""
    readme_path = base_dir / "README.md"  # README 在根目录
    if not readme_path.exists() or not readme_path.is_file():
        print("❌ README.md 不在根目录，跳过更新")
        return False

    try:
        with open(readme_path, "r+", encoding="utf-8") as f:
            content = f.read()

            # 替换更新时间（精确匹配格式）
            content = re.sub(
                r"更新时间: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} （北京时间）",
                f"更新时间: {timestamp} （北京时间）",
                content
            )

            # 替换 Hosts 规则数量
            content = re.sub(
                r"Hosts规则数量: \d+",
                f"Hosts规则数量: {stats['hosts']}",
                content
            )

            # 替换各拦截器数量
            for ab_key, ab_info in ADBLOCKERS.items():
                if ab_info["has_allow"]:
                    # 替换拦截规则数量
                    content = re.sub(
                        rf"{ab_info['name']} 拦截规则数量: \d+",
                        f"{ab_info['name']} 拦截规则数量: {stats[ab_key]['rules']}",
                        content
                    )
                    # 替换白名单规则数量
                    content = re.sub(
                        rf"{ab_info['name']} 白名单规则数量: \d+",
                        f"{ab_info['name']} 白名单规则数量: {stats[ab_key]['allow']}",
                        content
                    )
                else:
                    # 替换混合规则数量
                    content = re.sub(
                        rf"{ab_info['name']} 混合规则数量: \d+",
                        f"{ab_info['name']} 混合规则数量: {stats[ab_key]['rules']}",
                        content
                    )

            # 写回更新后的内容
            f.seek(0)
            f.write(content)
            f.truncate()

        print("✅ 根目录 README.md 统计已更新")
        return True
    except Exception as e:
        print(f"❌ 更新 README 失败：{str(e)}", flush=True)
        return False


def main():
    try:
        # 定位 GitHub 根目录（优先使用 GITHUB_WORKSPACE，确保在根目录）
        github_workspace = os.getenv("GITHUB_WORKSPACE")
        if github_workspace:
            base_dir = Path(github_workspace).resolve()
        else:
            # 本地调试时使用当前目录（默认根目录）
            base_dir = Path(os.getcwd()).resolve()
        
        print(f"已定位根目录：{base_dir}")
        if not base_dir.exists():
            raise FileNotFoundError(f"根目录不存在：{base_dir}")

        # 1. 检测根目录下的规则文件
        detected = detect_files(base_dir)
        print("\n检测到的文件：")
        print(f"主规则：{[ADBLOCKERS[k]['name'] for k in detected['adblock']]}")
        print(f"白名单：{[ADBLOCKERS[k]['name'] for k in detected['allow']]}")
        print(f"Hosts：{'存在' if detected['hosts'] else '不存在'}")

        # 2. 生成北京时间戳（复用）
        timestamp = get_beijing_time()
        print(f"\n当前北京时间：{timestamp}")

        # 3. 处理文件并收集统计
        stats = process_rule_files(detected, timestamp)

        # 4. 更新根目录 README
        update_readme(base_dir, stats, timestamp)

    except Exception as e:
        print(f"\n❌ 脚本执行失败：{str(e)}", flush=True)
        exit(1)  # GitHub Actions 识别非0退出码为失败


if __name__ == "__main__":
    main()
