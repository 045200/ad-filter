#!/usr/bin/env python3
import re
import sys
from pathlib import Path
from datetime import datetime
import tempfile
import urllib.request
import gzip
import shutil
import subprocess

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def is_valid_rule(line, is_allow=False):
    """
    严格匹配新脚本的规则格式：
    - add.txt: 仅包含 ||domain^ 或 ||domain^$modifier 格式
    - adw.txt: 仅包含 @@||domain^ 或 @@||domain^$modifier 格式
    """
    line = line.strip()
    if not line or line.startswith('!'):
        return False
    
    if is_allow:
        # 白名单规则必须严格以 @@|| 开头 ^ 结尾
        return bool(re.match(r'^@@\|\|[\w.-]+\^(?:\$[\w,=-]+)?$', line))
    else:
        # 黑名单规则必须严格以 || 开头 ^ 结尾
        return bool(re.match(r'^\|\|[\w.-]+\^(?:\$[\w,=-]+)?$', line))

def convert_rule(line, is_allow=False):
    """
    专用转换逻辑（仅处理新脚本的标准格式）：
    - 将 ||domain^ 转换为 DOMAIN-SUFFIX,domain,REJECT
    - 将 @@||domain^ 转换为 DOMAIN-SUFFIX,domain,DIRECT
    - 自动忽略修饰符（$modifier部分）
    """
    line = line.strip()
    policy = "DIRECT" if is_allow else "REJECT"
    
    # 提取基础域名（忽略修饰符）
    domain = line.split('||')[1].split('^')[0]
    return f"DOMAIN-SUFFIX,{domain},{policy}"

def process_rules(input_path, output_path, is_allow=False):
    """处理规则文件并严格验证格式"""
    try:
        processed = 0
        with open(input_path, 'r', encoding='utf-8') as f_in, \
             open(output_path, 'w', encoding='utf-8') as f_out:

            for line in f_in:
                if not is_valid_rule(line, is_allow):
                    continue

                converted = convert_rule(line, is_allow)
                f_out.write(converted + '\n')
                processed += 1

        log(f"Processed {processed} rules from {input_path.name}")
        return True

    except Exception as e:
        error(f"Failed to process {input_path.name}: {str(e)}")
        return False

def download_mihomo_tool(tool_dir):
    """下载Mihomo转换工具（保持不变）"""
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        with urllib.request.urlopen(version_url) as response:
            version = response.read().decode('utf-8').strip()

        tool_name = f"mihomo-linux-amd64-{version}"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        tool_path = tool_dir / tool_name

        log(f"Downloading {tool_name}...")
        with urllib.request.urlopen(tool_url) as response:
            with gzip.GzipFile(fileobj=response) as f_in:
                with open(tool_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        tool_path.chmod(0o755)
        return tool_path

    except Exception as e:
        error(f"Tool download failed: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, tool_path):
    """转换为Mihomo规则集（保持不变）"""
    try:
        subprocess.run(
            [str(tool_path), "convert-ruleset", "domain", "text", 
             str(input_file), str(output_file)],
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        error(f"Conversion failed: {str(e)}")
        return False

def main():
    # 配置路径（严格使用新脚本的输出文件）
    base_dir = Path(__file__).parent.parent.parent
    config = {
        "input_files": {
            "block": base_dir / "add.txt",  # 来自新脚本的黑名单
            "allow": base_dir / "adw.txt"   # 来自新脚本的白名单
        },
        "temp_files": {
            "block": Path(tempfile.gettempdir()) / "block.tmp",
            "allow": Path(tempfile.gettempdir()) / "allow.tmp"
        },
        "output": base_dir / "mihomo_rules.mrs",
        "tool_dir": base_dir / "temp_tools"
    }

    try:
        # 必须存在add.txt
        if not config["input_files"]["block"].exists():
            error(f"Missing required file: {config['input_files']['block']}")
            sys.exit(1)

        # 处理黑名单（add.txt）
        if not process_rules(config["input_files"]["block"], config["temp_files"]["block"]):
            sys.exit(1)

        # 处理白名单（adw.txt，可选）
        if config["input_files"]["allow"].exists():
            if not process_rules(config["input_files"]["allow"], config["temp_files"]["allow"], is_allow=True):
                sys.exit(1)
        else:
            log("No adw.txt found, proceeding without allow rules")

        # 合并规则（白名单优先）
        with open(config["output"], 'w', encoding='utf-8') as f_out:
            if config["input_files"]["allow"].exists():
                with open(config["temp_files"]["allow"], 'r') as f_in:
                    f_out.write(f_in.read())
            
            with open(config["temp_files"]["block"], 'r') as f_in:
                f_out.write(f_in.read())

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