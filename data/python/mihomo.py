#!/usr/bin/env python3
import os
import re
import sys
import gzip
import shutil
import urllib.request
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def is_valid_rule(line, is_allow=False):
    """
    强化规则验证（严格匹配AdBlock/Hosts格式）
    """
    line = line.strip()
    if not line or line.startswith(('!', '#', '@@|', '===')):
        return False

    # 精确匹配AdBlock规则（||domain^ 或 ||domain^$modifier）
    if re.match(r'^\|\|[\w.-]+\^(?:\$[\w,=-]+)?$', line):
        return True

    # 精确匹配放行规则（@@||domain^）
    if is_allow and re.match(r'^@@\|\|[\w.-]+\^$', line):
        return True

    # 匹配Hosts规则（0.0.0.0 domain）
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[\w.-]+$', line):
        return True

    return False

def convert_rule(line, is_allow=False):
    """
    强化规则转换（保持与Mihomo策略组兼容）
    """
    line = line.strip()
    policy = "DIRECT" if is_allow else "REJECT"

    # 处理AdBlock规则（||domain^）
    if line.startswith("||") and '^' in line:
        domain = line[2:].split('^')[0]
        return f"DOMAIN-SUFFIX,{domain},{policy}"

    # 处理Hosts规则（0.0.0.0 domain）
    if match := re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$', line):
        return f"DOMAIN,{match.group(2)},{policy}"

    return None

def process_rules(input_path, output_path, is_allow=False):
    """
    优化规则处理流程（自动处理编码问题）
    """
    try:
        processed = 0
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f_in, \
             open(output_path, 'a' if output_path.exists() else 'w', encoding='utf-8') as f_out:

            for line in f_in:
                if not is_valid_rule(line, is_allow):
                    continue

                if converted := convert_rule(line, is_allow):
                    f_out.write(converted + '\n')
                    processed += 1

        log(f"Processed {processed} {'allow' if is_allow else 'block'} rules from {input_path.name}")
        return True

    except Exception as e:
        error(f"Failed to process {input_path.name}: {str(e)}")
        return False

def download_mihomo_tool(tool_dir):
    """
    优化工具下载（增加重试机制）
    """
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        # 获取最新版本
        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        for _ in range(3):  # 重试3次
            try:
                with urllib.request.urlopen(version_url, timeout=10) as resp:
                    version = resp.read().decode('utf-8').strip()
                    break
            except Exception:
                continue
        else:
            raise Exception("Failed to fetch version after 3 retries")

        # 下载工具
        tool_name = f"mihomo-linux-amd64-{version}"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        tool_path = tool_dir / tool_name

        log(f"Downloading {tool_name}...")
        urllib.request.urlretrieve(tool_url, f"{tool_path}.gz")

        # 解压工具
        with gzip.open(f"{tool_path}.gz", 'rb') as f_in:
            with open(tool_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        tool_path.chmod(0o755)
        os.remove(f"{tool_path}.gz")
        return tool_path

    except Exception as e:
        error(f"Tool download failed: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, tool_path):
    """
    规则集转换（增加超时处理）
    """
    try:
        subprocess.run(
            [str(tool_path), "convert-ruleset", "domain", "text",
             str(input_file), str(output_file)],
            check=True,
            timeout=30
        )
        return True
    except subprocess.TimeoutExpired:
        error("Conversion timed out after 30 seconds")
        return False
    except subprocess.CalledProcessError as e:
        error(f"Conversion failed with code {e.returncode}")
        return False

def main():
    try:
        # 配置路径（兼容原脚本结构）
        base_dir = Path(__file__).parent.parent.parent
        config = {
            "input_files": {
                "block": base_dir / "adblock.txt",
                "allow": base_dir / "allow.txt"
            },
            "temp_files": {
                "merged": Path(tempfile.gettempdir()) / "merged_rules.tmp"
            },
            "output": base_dir / "adb.mrs",
            "tool_dir": base_dir / "mihomo_tools"
        }

        # 初始化临时文件
        config["temp_files"]["merged"].unlink(missing_ok=True)

        # 处理规则（优先放行规则）
        if config["input_files"]["allow"].exists():
            if not process_rules(config["input_files"]["allow"], config["temp_files"]["merged"], is_allow=True):
                sys.exit(1)
        else:
            log("No allow rules found, skipping")

        if not process_rules(config["input_files"]["block"], config["temp_files"]["merged"]):
            sys.exit(1)

        # 转换为Mihomo格式
        if not (tool := download_mihomo_tool(config["tool_dir"])):
            sys.exit(1)

        if not convert_to_mrs(config["temp_files"]["merged"], config["output"], tool):
            sys.exit(1)

        log(f"Successfully generated: {config['output'].name}")
        log(f"Output size: {os.path.getsize(config['output']) / 1024:.2f} KB")
        return 0

    except Exception as e:
        error(f"Fatal error: {str(e)}")
        return 1
    finally:
        # 增强的清理逻辑
        config["temp_files"]["merged"].unlink(missing_ok=True)
        if 'tool' in locals():
            shutil.rmtree(config["tool_dir"], ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())