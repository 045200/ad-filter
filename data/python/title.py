import os
import re
from pathlib import Path
from typing import Dict, List
import datetime
import pytz


# 拦截器配置（含通用规则hybrid）
ADBLOCKERS: Dict[str, Dict[str, str]] = {
    "adp": {"name": "Adblock Plus", "suffix": ".txt", "comment": "!", "has_allow": False},
    "ubo": {"name": "uBlock Origin", "suffix": ".txt", "comment": "!", "has_allow": False},
    "adg": {"name": "AdGuard", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adh": {"name": "AdGuard Home", "suffix": ".txt", "comment": "#", "has_allow": True},
    "clash": {"name": "Clash", "suffix": ".yaml", "comment": "#", "has_allow": False},
    "surge": {"name": "Surge", "suffix": ".conf", "comment": "#", "has_allow": False},
    "pihole": {"name": "Pi-hole", "suffix": ".txt", "comment": "#", "has_allow": True}
}

# 头信息模板（整合通用规则配置，通过变量动态适配）
ADBLOCK_HEADER = """{comment} Title: {title}
{comment} Homepage: https://github.com/045200/ad-filter
{comment} Expires: 12 Hours
{comment} Version: {timestamp}（北京时间）
{comment} Description: {description}
{comment} Total count: {line_count}
"""

ALLOW_HEADER = """{comment} Title: {title}
{comment} Homepage: https://github.com/045200/ad-filter
{comment} Expires: 12 Hours
{comment} Version: {timestamp}（北京时间）
{comment} Description: {description}
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
    """获取北京时间（兼容GitHub Actions环境）"""
    try:
        return datetime.datetime.now(pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    except (ImportError, pytz.UnknownTimeZoneError):
        utc_now = datetime.datetime.utcnow()
        beijing_time = utc_now + datetime.timedelta(hours=8)
        return beijing_time.strftime("%Y-%m-%d %H:%M:%S")


def count_valid_lines(lines: List[str], comment_char: str) -> int:
    """统计有效行数（排除空行和注释行）"""
    return sum(1 for line in lines if line.strip() and not line.strip().startswith(comment_char))


def detect_files(base_dir: Path) -> Dict[str, Dict[str, Path]]:
    """检测根目录下的所有规则文件（含通用规则）"""
    detected = {"adblock": {}, "allow": {}, "hosts": None}

    for ab_key, ab_info in ADBLOCKERS.items():
        # 主规则文件（如 adblock_hybrid.txt）
        adblock_path = base_dir / f"adblock_{ab_key}{ab_info['suffix']}"
        if adblock_path.is_file():
            detected["adblock"][ab_key] = adblock_path

        # 白名单文件（如 allow_hybrid.txt，仅支持has_allow的拦截器）
        if ab_info["has_allow"]:
            allow_path = base_dir / f"allow_{ab_key}{ab_info['suffix']}"
            if allow_path.is_file():
                detected["allow"][ab_key] = allow_path

    # 检测hosts文件
    for suffix in (".txt", ".conf"):
        hosts_path = base_dir / f"hosts{suffix}"
        if hosts_path.is_file():
            detected["hosts"] = hosts_path
            break

    return detected


def process_file(path: Path, ab_info: Dict[str, str], is_allow: bool, timestamp: str) -> int:
    """通用文件处理函数（处理主规则或白名单）"""
    try:
        with open(path, "r+", encoding="utf-8") as f:
            lines = f.readlines()
            valid_lines = count_valid_lines(lines, ab_info["comment"])

            # 区分主规则和白名单的标题、描述、模板
            if is_allow:
                title = ab_info.get("title_allow", f"{ab_info['name']} 白名单")
                header_template = ALLOW_HEADER
            else:
                title = ab_info.get("title_rule", f"{ab_info['name']} 拦截规则")
                header_template = ADBLOCK_HEADER

            # 生成头信息并写入
            header = header_template.format(
                comment=ab_info["comment"],
                title=title,
                timestamp=timestamp,
                description=description,
                line_count=valid_lines
            )
            f.seek(0)
            f.write(header)
            f.writelines(lines)
            f.truncate()

        # 输出日志（区分主规则和白名单）
        file_type = "白名单" if is_allow else "拦截规则"
        print(f"✅ 处理 {ab_info['name']} {file_type}：{valid_lines} 行")
        return valid_lines
    except Exception as e:
        file_type = "白名单" if is_allow else "拦截规则"
        print(f"❌ 处理 {ab_info['name']} {file_type} 失败：{str(e)}", flush=True)
        return 0


def process_rule_files(detected: Dict[str, Dict[str, Path]], timestamp: str) -> Dict[str, int]:
    """处理规则文件（含通用规则），使用模板动态生成头信息"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 处理主规则文件（含通用规则）
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        valid_lines = process_file(path, ab_info, is_allow=False, timestamp=timestamp)
        stats[ab_key]["rules"] = valid_lines

    # 处理白名单文件（含通用规则）
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        valid_lines = process_file(path, ab_info, is_allow=True, timestamp=timestamp)
        stats[ab_key]["allow"] = valid_lines

    # 处理hosts文件
    if detected["hosts"]:
        try:
            with open(detected["hosts"], "r+", encoding="utf-8") as f:
                lines = f.readlines()
                valid_lines = count_valid_lines(lines, "#")
                header = HOSTS_HEADER.format(timestamp=timestamp, line_count=valid_lines)
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
    """更新README，包含通用规则统计"""
    readme_path = base_dir / "README.md"
    if not readme_path.is_file():
        print("❌ README.md 不存在，跳过更新")
        return False

    try:
        with open(readme_path, "r+", encoding="utf-8") as f:
            content = f.read()

            # 更新时间
            content = re.sub(
                r"更新时间: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} （北京时间）",
                f"更新时间: {timestamp} （北京时间）",
                content
            )

            # Hosts规则数量
            content = re.sub(
                r"Hosts规则数量: \d+",
                f"Hosts规则数量: {stats['hosts']}",
                content
            )

            # 各拦截器规则数量（含通用规则）
            for ab_key, ab_info in ADBLOCKERS.items():
                if ab_info["has_allow"]:
                    # 拦截规则
                    content = re.sub(
                        rf"{ab_info['name']} 拦截规则数量: \d+",
                        f"{ab_info['name']} 拦截规则数量: {stats[ab_key]['rules']}",
                        content
                    )
                    # 白名单规则
                    content = re.sub(
                        rf"{ab_info['name']} 白名单规则数量: \d+",
                        f"{ab_info['name']} 白名单规则数量: {stats[ab_key]['allow']}",
                        content
                    )
                else:
                    # 混合规则（无白名单）
                    content = re.sub(
                        rf"{ab_info['name']} 混合规则数量: \d+",
                        f"{ab_info['name']} 混合规则数量: {stats[ab_key]['rules']}",
                        content
                    )

            f.seek(0)
            f.write(content)
            f.truncate()

        print("✅ README.md 统计信息已更新（含通用规则）")
        return True
    except Exception as e:
        print(f"❌ 更新README失败：{str(e)}", flush=True)
        return False


def main():
    try:
        # 定位根目录
        base_dir = Path(os.getenv("GITHUB_WORKSPACE", os.getcwd())).resolve()
        print(f"根目录：{base_dir}")
        if not base_dir.exists():
            raise FileNotFoundError(f"根目录不存在：{base_dir}")

        # 检测文件
        detected = detect_files(base_dir)
        print("\n检测到的文件：")
        print(f"主规则：{[ADBLOCKERS[k]['name'] for k in detected['adblock']]}")
        print(f"白名单：{[ADBLOCKERS[k]['name'] for k in detected['allow']]}")
        print(f"Hosts：{'存在' if detected['hosts'] else '不存在'}")

        # 生成时间戳
        timestamp = get_beijing_time()
        print(f"\n当前北京时间：{timestamp}")

        # 处理文件并统计
        stats = process_rule_files(detected, timestamp)

        # 更新README
        update_readme(base_dir, stats, timestamp)

    except Exception as e:
        print(f"\n❌ 脚本执行失败：{str(e)}", flush=True)
        exit(1)


if __name__ == "__main__":
    main()
