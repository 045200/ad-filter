import os
import re
from pathlib import Path
from typing import Dict, List
import datetime
import pytz

# 拦截器配置（保留原有开关has_allow，用于动态控制统计项）
ADBLOCKERS: Dict[str, Dict[str, str]] = {
    "abp": {"name": "Adblock Plus", "suffix": ".txt", "comment": "!", "has_allow": True},
    "ubo": {"name": "uBlock Origin", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adg": {"name": "AdGuard", "suffix": ".txt", "comment": "!", "has_allow": True},
    "clash": {"name": "Clash", "suffix": ".yaml", "comment": "#", "has_allow": True},
    "surge": {"name": "Surge", "suffix": ".yaml", "comment": "#", "has_allow": True},
    "pihole": {"name": "Pi-hole", "suffix": ".list", "comment": "#", "has_allow": False}
}

# 通用头信息模板（统一主规则描述，无“混合”表述）
HEADER_TEMPLATE = """{comment} Title: {title}
{comment} Homepage: https://github.com/045200/ad-filter
{comment} Expires: 12 Hours
{comment} Version: {timestamp}（北京时间）
{comment} Description: {description}
{comment} Total count: {line_count}
"""


def get_beijing_time() -> str:
    """获取北京时间"""
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
    """检测根目录下的所有规则文件（修复Hosts检测的元组语法错误）"""
    detected = {"adblock": {}, "allow": {}, "hosts": None}

    for ab_key, ab_info in ADBLOCKERS.items():
        # 主规则文件检测
        adblock_path = base_dir / f"adblock_{ab_key}{ab_info['suffix']}"
        if adblock_path.is_file():
            detected["adblock"][ab_key] = adblock_path

        # 白名单文件检测（仅支持has_allow=True的拦截器）
        if ab_info["has_allow"]:
            allow_path = base_dir / f"allow_{ab_key}{ab_info['suffix']}"
            if allow_path.is_file():
                detected["allow"][ab_key] = allow_path

    # 修复：单个元素元组加逗号，确保正确遍历（仅检测hosts.txt）
    for suffix in (".txt",):
        hosts_path = base_dir / f"hosts{suffix}"
        if hosts_path.is_file():
            detected["hosts"] = hosts_path
            break

    return detected


def update_file_header(
    path: Path,
    comment_char: str,
    title: str,
    description: str,
    timestamp: str
) -> int:
    """更新文件头信息并返回有效行数（统一主规则标题/描述）"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            valid_lines = count_valid_lines(lines, comment_char)

        # 生成头信息
        header = HEADER_TEMPLATE.format(
            comment=comment_char,
            title=title,
            timestamp=timestamp,
            description=description,
            line_count=valid_lines
        )

        # 写入头信息和内容
        with open(path, "w", encoding="utf-8") as f:
            f.write(header)
            f.writelines(lines)

        print(f"✅ 更新 {title} 头信息：{valid_lines} 行")
        return valid_lines
    except Exception as e:
        print(f"❌ 更新 {title} 头信息失败：{str(e)}", flush=True)
        return 0


def extract_count_from_header(path: Path, comment_char: str) -> int:
    """从文件头中提取Total count数值"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

            # 查找Total count行
            pattern = rf"{re.escape(comment_char)}\s*Total count:\s*(\d+)"
            match = re.search(pattern, content)

            if match:
                return int(match.group(1))
            else:
                print(f"⚠️  在 {path.name} 中未找到Total count信息")
                return 0
    except Exception as e:
        print(f"❌ 从 {path.name} 提取Total count失败：{str(e)}", flush=True)
        return 0


def process_rule_files(detected: Dict[str, Dict[str, Path]], timestamp: str) -> Dict[str, int]:
    """处理所有规则文件并返回统计信息（统一主规则表述）"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 处理主规则文件（所有拦截器统一叫“拦截规则”，无“混合”）
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 拦截规则"
        description = f"适用于 {ab_info['name']} 的广告拦截规则"
        stats[ab_key]["rules"] = update_file_header(
            path, ab_info["comment"], title, description, timestamp
        )

    # 处理白名单文件（仅has_allow=True的拦截器会执行）
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 白名单"
        description = f"适用于 {ab_info['name']} 的白名单规则"
        stats[ab_key]["allow"] = update_file_header(
            path, ab_info["comment"], title, description, timestamp
        )

    # 处理hosts文件
    if detected["hosts"]:
        stats["hosts"] = update_file_header(
            detected["hosts"], "#", "广告拦截 Hosts 规则", 
            "适用于任何支持Hosts过滤的软件", timestamp
        )

    return stats


def get_stats_from_headers(detected: Dict[str, Dict[str, Path]]) -> Dict[str, int]:
    """从文件头中提取统计信息"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 提取主规则统计
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        stats[ab_key]["rules"] = extract_count_from_header(path, ab_info["comment"])

    # 提取白名单统计（仅has_allow=True的拦截器会执行）
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        stats[ab_key]["allow"] = extract_count_from_header(path, ab_info["comment"])

    # 提取hosts统计
    if detected["hosts"]:
        stats["hosts"] = extract_count_from_header(detected["hosts"], "#")

    return stats


def update_readme(base_dir: Path, stats: Dict[str, int], timestamp: str) -> bool:
    """更新README.md（核心改进：根据has_allow动态生成统计行，取消混合逻辑）"""
    readme_path = base_dir / "README.md"
    if not readme_path.is_file():
        print("❌ README.md 不存在，跳过更新")
        return False

    try:
        with open(readme_path, "r+", encoding="utf-8") as f:
            content = f.read()

            # 1. 更新最后更新时间
            content = re.sub(
                r"最后更新时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                f"最后更新时间：{timestamp}",
                content
            )

            # 2. 更新Hosts规则数量
            content = re.sub(
                r"Hosts规则数量：\d+",
                f"Hosts规则数量：{stats['hosts']}",
                content
            )

            # 3. 动态更新各拦截器统计（根据has_allow开关自动适配）
            for ab_key, ab_info in ADBLOCKERS.items():
                # 基础统计：拦截规则数量
                stats_text = f"{ab_info['name']} 拦截规则数量：{stats[ab_key]['rules']}"
                # 若开启白名单（has_allow=True），追加白名单统计
                if ab_info["has_allow"]:
                    stats_text += f" | 白名单数量：{stats[ab_key]['allow']}"
                # 正则匹配并替换（覆盖原有统计行）
                content = re.sub(
                    rf"{re.escape(ab_info['name'])}\s+拦截规则数量：\d+.*",
                    stats_text,
                    content
                )

            f.seek(0)
            f.write(content)
            f.truncate()

        print("✅ README.md 统计信息已更新")
        return True
    except Exception as e:
        print(f"❌ 更新README失败：{str(e)}", flush=True)
        return False


def main():
    try:
        # 获取脚本运行根目录（适配GitHub Workspace和本地环境）
        base_dir = Path(os.getenv("GITHUB_WORKSPACE", os.getcwd())).resolve()
        print(f"根目录：{base_dir}")
        if not base_dir.exists():
            raise FileNotFoundError(f"根目录不存在：{base_dir}")

        # 检测规则文件（含修复后的Hosts检测）
        detected = detect_files(base_dir)
        print("\n检测到的文件：")
        print(f"主规则：{[ADBLOCKERS[k]['name'] for k in detected['adblock']]}")
        print(f"白名单：{[ADBLOCKERS[k]['name'] for k in detected['allow']]}")
        print(f"Hosts：{detected['hosts'].name if detected['hosts'] else '不存在'}")

        # 生成北京时间戳
        timestamp = get_beijing_time()
        print(f"\n当前北京时间：{timestamp}")

        # 更新所有文件头
        process_rule_files(detected, timestamp)

        # 提取统计信息
        stats = get_stats_from_headers(detected)

        # 更新README统计
        update_readme(base_dir, stats, timestamp)

    except Exception as e:
        print(f"\n❌ 脚本执行失败：{str(e)}", flush=True)
        exit(1)


if __name__ == "__main__":
    main()
