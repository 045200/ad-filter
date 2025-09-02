import os
from pathlib import Path
from typing import Dict, List
import datetime
import pytz


# 拦截器配置
ADBLOCKERS: Dict[str, Dict[str, str]] = {
    "abp": {"name": "Adblock Plus", "suffix": ".txt", "comment": "!", "has_allow": True},
    "ubo": {"name": "uBlock Origin", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adg": {"name": "AdGuard", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adh": {"name": "AdGuard Home", "suffix": ".txt", "comment": "#", "has_allow": True},
    "clash": {"name": "Clash", "suffix": ".yaml", "comment": "#", "has_allow": True},
    "surge": {"name": "Surge", "suffix": ".conf", "comment": "#", "has_allow": True},
    "pihole": {"name": "Pi-hole", "suffix": ".txt", "comment": "#", "has_allow": True}
}

# 通用头信息模板
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


def count_valid_lines(lines: List[str]) -> int:
    """统计有效行数（仅跳过空行，因输入为纯净规则文件，无注释需处理）"""
    return sum(1 for line in lines if line.strip())  # 仅判断“非空行”


def detect_files(base_dir: Path) -> Dict[str, Dict[str, Path]]:
    """检测根目录下的所有规则文件"""
    detected = {"adblock": {}, "allow": {}, "hosts": None}

    # 检测拦截器规则文件
    for ab_key, ab_info in ADBLOCKERS.items():
        # 主规则文件
        adblock_path = base_dir / f"adblock_{ab_key}{ab_info['suffix']}"
        if adblock_path.is_file():
            detected["adblock"][ab_key] = adblock_path

        # 白名单文件（仅支持has_allow的拦截器）
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


def process_file(
    path: Path,
    comment_char: str,
    title: str,
    description: str,
    timestamp: str
) -> int:
    """通用文件处理函数（使用通用头信息模板）"""
    try:
        with open(path, "r+", encoding="utf-8") as f:
            lines = f.readlines()
            valid_lines = count_valid_lines(lines)  # 调用修改后的统计函数，无需传comment_char

            # 生成头信息（仍保留comment_char，用于头信息的注释符号）
            header = HEADER_TEMPLATE.format(
                comment=comment_char,
                title=title,
                timestamp=timestamp,
                description=description,
                line_count=valid_lines
            )

            # 写入头信息和内容
            f.seek(0)
            f.write(header)
            f.writelines(lines)
            f.truncate()

        print(f"✅ 处理 {title}：{valid_lines} 行")
        return valid_lines
    except Exception as e:
        print(f"❌ 处理 {title} 失败：{str(e)}", flush=True)
        return 0


def process_rule_files(detected: Dict[str, Dict[str, Path]], timestamp: str) -> Dict[str, int]:
    """处理所有规则文件"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 处理主规则文件
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 拦截规则"
        description = f"适用于 {ab_info['name']} 的广告拦截规则"
        valid_lines = process_file(
            path,
            ab_info["comment"],
            title,
            description,
            timestamp
        )
        stats[ab_key]["rules"] = valid_lines

    # 处理白名单文件
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 白名单"
        description = f"适用于 {ab_info['name']} 的白名单规则"
        valid_lines = process_file(
            path,
            ab_info["comment"],
            title,
            description,
            timestamp
        )
        stats[ab_key]["allow"] = valid_lines

    # 处理hosts文件
    if detected["hosts"]:
        valid_lines = process_file(
            detected["hosts"],
            "#",
            "广告拦截 Hosts 规则",
            "适用于任何支持Hosts过滤的软件",
            timestamp
        )
        stats["hosts"] = valid_lines

    return stats


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
        process_rule_files(detected, timestamp)

    except Exception as e:
        print(f"\n❌ 脚本执行失败：{str(e)}", flush=True)
        exit(1)


if __name__ == "__main__":
    main()
