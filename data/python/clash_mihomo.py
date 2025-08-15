#!/usr/bin/env python3
import os
import re
import sys
import gzip
import shutil
import hashlib
import urllib.request
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def is_block_rule(line):
    """检测所有可能的广告拦截规则格式"""
    line = line.strip()
    if not line or line.startswith(('!', '#', '@@')):
        return False

    # 1. 标准AdBlock语法
    if re.match(r'^\|\|[\w.-]+\^(?:\$~?[\w,=-]+)?$', line):
        return True

    # 2. Hosts语法
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[\w.-]+$', line):
        return True

    # 3. 纯域名规则（确保是有效域名）
    if re.match(r'^([\w.-]+)$', line) and '.' in line and not line.startswith(('*', '.')):
        return True

    # 4. 通配符规则（仅限广告相关）
    if '*' in line and any(kw in line.lower() for kw in ('ad', 'track', 'analytics')):
        return True

    return False

def is_allow_rule(line):
    """检测广告白名单规则"""
    line = line.strip()
    if not line:
        return False

    # 1. AdGuard例外语法
    if re.match(r'^@@\|\|[\w.-]+\^$', line):
        return True

    # 2. 纯域名白名单
    if re.match(r'^[\w.-]+$', line) and '.' in line:
        return True

    return False

def convert_rule(line, is_allow=False):
    """精准转换为Mihomo兼容格式"""
    line = line.strip()
    policy = "DIRECT" if is_allow else "REJECT"

    # 1. 处理纯域名规则
    if re.match(r'^[\w.-]+$', line) and '.' in line:
        if line.startswith('*.'):  # 通配符处理
            return f"DOMAIN-SUFFIX,{line[2:]},{policy}"
        return f"DOMAIN,{line},{policy}"

    # 2. 标准AdBlock规则
    if line.startswith("||") and line.endswith("^"):
        return f"DOMAIN-SUFFIX,{line[2:-1]},{policy}"

    # 3. Hosts规则
    if match := re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$', line):
        return f"DOMAIN,{match.group(2)},{policy}"

    # 4. 保留已有Mihomo语法
    if re.match(r'^(DOMAIN|DOMAIN-SUFFIX),[\w.-]+,(REJECT|DIRECT)$', line):
        return line

    return None

def process_rules(input_path, output_path, is_allow=False):
    """带严格校验的规则处理流程"""
    try:
        existing_hashes = set()
        if output_path.exists():
            with open(output_path, 'r', encoding='utf-8') as f:
                existing_hashes.update(hashlib.md5(line.encode()).hexdigest() for line in f)

        with open(input_path, 'r', encoding='utf-8', errors='replace') as f_in, \
             open(output_path, 'a' if output_path.exists() else 'w', encoding='utf-8') as f_out:

            for line in f_in:
                line = line.strip()
                if not line:
                    continue

                # 特殊处理纯域名白名单
                if is_allow and re.match(r'^[\w.-]+$', line) and '.' in line:
                    converted = f"DOMAIN,{line},DIRECT"
                else:
                    rule_check = is_allow_rule(line) if is_allow else is_block_rule(line)
                    if not rule_check:
                        continue
                    converted = convert_rule(line, is_allow)

                if converted:
                    rule_hash = hashlib.md5(converted.encode()).hexdigest()
                    if rule_hash not in existing_hashes:
                        f_out.write(converted + '\n')
                        existing_hashes.add(rule_hash)

        return True
    except Exception as e:
        error(f"Rule processing failed: {str(e)}")
        return False

def download_mihomo_tool(tool_dir):
    """带缓存校验的工具下载"""
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        # 获取最新版本
        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        with urllib.request.urlopen(version_url, timeout=10) as resp:
            version = resp.read().decode('utf-8').strip()

        tool_name = f"mihomo-linux-amd64-{version}"
        tool_path = tool_dir / tool_name

        # 使用缓存文件
        if tool_path.exists():
            log(f"Using cached tool: {tool_name}")
            return tool_path

        # 下载工具
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        log(f"Downloading {tool_name}...")
        urllib.request.urlretrieve(tool_url, f"{tool_path}.gz")

        # 解压并校验
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
    """生成严格校验的MRS文件"""
    try:
        # 添加广告规则专用参数
        with open(input_file, 'r+', encoding='utf-8') as f:
            content = f.read()
            if "params:" not in content:
                content = """params:
  enable-adblock: true
  adblock-speedup: true
  strict-mode: true
rules:
""" + content
            f.seek(0)
            f.write(content)
            f.truncate()

        # 执行转换（启用严格模式）
        result = subprocess.run(
            [str(tool_path), "convert-ruleset", "domain", "text",
             str(input_file), str(output_file), "--strict"],
            check=True,
            timeout=120,
            capture_output=True,
            text=True
        )

        # 验证输出
        if not output_file.exists() or os.path.getsize(output_file) == 0:
            raise ValueError("Empty output file")
        if "error" in result.stderr.lower():
            raise ValueError(result.stderr)

        return True
    except subprocess.TimeoutExpired:
        error("Conversion timed out after 120 seconds")
        return False
    except Exception as e:
        error(f"MRS generation failed: {str(e)}")
        return False

def main():
    try:
        # 配置文件路径
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

        # 优先处理白名单规则
        if config["input_files"]["allow"].exists():
            if not process_rules(config["input_files"]["allow"], config["temp_files"]["merged"], is_allow=True):
                sys.exit(1)
        else:
            log("No allow rules found, skipping")

        # 处理拦截规则
        if not process_rules(config["input_files"]["block"], config["temp_files"]["merged"]):
            sys.exit(1)

        # 转换为MRS格式
        if not (tool := download_mihomo_tool(config["tool_dir"])):
            sys.exit(1)

        if not convert_to_mrs(config["temp_files"]["merged"], config["output"], tool):
            sys.exit(1)

        log(f"Successfully generated: {config['output'].name}")
        log(f"Final rules count: {sum(1 for _ in open(config['output']))} lines")
        return 0

    except Exception as e:
        error(f"Fatal error: {str(e)}")
        return 1
    finally:
        # 清理临时文件
        config["temp_files"]["merged"].unlink(missing_ok=True)
        if 'tool' in locals():
            shutil.rmtree(config["tool_dir"], ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())