import os
import re
from pathlib import Path
from typing import Dict, List
import datetime
import pytz


# 拦截器配置
ADBLOCKERS: Dict[str, Dict[str, str]] = {
    "abp": {"name": "Adblock Plus", "suffix": ".txt", "comment": "!", "has_allow": False},
    "ubo": {"name": "uBlock Origin", "suffix": ".txt", "comment": "!", "has_allow": False},
    "adg": {"name": "AdGuard", "suffix": ".txt", "comment": "!", "has_allow": True},
    "adh": {"name": "AdGuard Home", "suffix": ".txt", "comment": "#", "has_allow": True},
    "clash": {"name": "Clash", "suffix": ".yaml", "comment": "#", "has_allow": False},
    "surge": {"name": "Surge", "suffix": ".conf", "comment": "#", "has_allow": False},
    "pihole": {"name": "Pi-hole", "suffix": ".txt", "comment": "#", "has_allow": True}
}


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
    """检测根目录下的所有规则文件"""
    detected = {"adblock": {}, "allow": {}, "hosts": None}

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
    title: str
) -> int:
    """统计文件有效行数"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            valid_lines = count_valid_lines(lines, comment_char)

        print(f"✅ 统计 {title}：{valid_lines} 行")
        return valid_lines
    except Exception as e:
        print(f"❌ 统计 {title} 失败：{str(e)}", flush=True)
        return 0


def process_rule_files(detected: Dict[str, Dict[str, Path]]) -> Dict[str, int]:
    """处理所有规则文件并统计行数"""
    stats = {ab_key: {"rules": 0, "allow": 0} for ab_key in ADBLOCKERS}
    stats["hosts"] = 0

    # 主规则
    for ab_key, path in detected["adblock"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 拦截规则"
        stats[ab_key]["rules"] = process_file(path, ab_info["comment"], title)

    # 白名单
    for ab_key, path in detected["allow"].items():
        ab_info = ADBLOCKERS[ab_key]
        title = f"{ab_info['name']} 白名单"
        stats[ab_key]["allow"] = process_file(path, ab_info["comment"], title)

    # Hosts
    if detected["hosts"]:
        stats["hosts"] = process_file(detected["hosts"], "#", "广告拦截 Hosts 规则")

    return stats


def update_readme(base_dir: Path, stats: Dict[str, int], timestamp: str) -> bool:
    """将统计信息更新到README.md"""
    readme_path = base_dir / "README.md"
    if not readme_path.is_file():
        print("❌ README.md 不存在，跳过更新")
        return False

    try:
        with open(readme_path, "r+", encoding="utf-8") as f:
            content = f.read()

            # 更新最后更新时间
            content = re.sub(
                r"最后更新时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
                f"最后更新时间：{timestamp}",
                content
            )

            # 更新Hosts规则数量
            content = re.sub(
                r"Hosts规则数量：\d+",
                f"Hosts规则数量：{stats['hosts']}",
                content
            )

            # 更新各拦截器规则数量
            for ab_key, ab_info in ADBLOCKERS.items():
                # 有白名单的拦截器（显示“拦截规则”和“白名单”）
                if ab_info["has_allow"]:
                    content = re.sub(
                        rf"{ab_info['name']} 拦截规则数量：\d+",
                        f"{ab_info['name']} 拦截规则数量：{stats[ab_key]['rules']}",
                        content
                    )
                    content = re.sub(
                        rf"{ab_info['name']} 白名单数量：\d+",
                        f"{ab_info['name']} 白名单数量：{stats[ab_key]['allow']}",
                        content
                    )
                # 无白名单的拦截器（显示“混合规则”）
                else:
                    content = re.sub(
                        rf"{ab_info['name']} 混合规则数量：\d+",
                        f"{ab_info['name']} 混合规则数量：{stats[ab_key]['rules']}",
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

        # 统计行数
        stats = process_rule_files(detected)

        # 更新README
        update_readme(base_dir, stats, timestamp)

    except Exception as e:
        print(f"\n❌ 脚本执行失败：{str(e)}", flush=True)
        exit(1)


if __name__ == "__main__":
    main()
