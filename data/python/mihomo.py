#!/usr/bin/env python3
import os
import sys
import re
import urllib.request
import gzip
import shutil
from pathlib import Path
import subprocess
from datetime import datetime
import tempfile

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def is_valid_rule(line, is_allow=False):
    """
    检查是否为有效规则（支持拦截和放行规则）
    """
    line = line.strip()
    
    # 跳过空行和注释
    if not line or line.startswith(('!', '#', '@', '/', '[', '=====')):
        return False
    
    # 匹配AdBlock规则
    if re.match(r'^(\|\|?[\w.-]+\^?|/{2}.*?/|\|https?://)', line):
        return True
    
    # 匹配Hosts规则
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[\w.-]+', line) and not is_allow:
        return True
    
    # 匹配放行规则（特殊语法）
    if is_allow and re.match(r'^@@\|\|[\w.-]+\^$', line):
        return True
    
    # 匹配纯域名规则
    if re.match(r'^[\w.-]+\.[\w.-]+$', line):
        return True
    
    return False

def convert_rule(line, is_allow=False):
    """
    增强的语法转换逻辑（支持拦截和放行规则）
    """
    line = line.strip()
    policy = "DIRECT" if is_allow else "REJECT"
    
    # 1. AdBlock拦截规则转换
    if line.startswith("||") and line.endswith("^"):
        domain = line[2:-1]
        return f"DOMAIN-SUFFIX,{domain},{policy}"
    
    # 2. AdBlock放行规则转换（@@||domain^）
    if is_allow and line.startswith("@@||") and line.endswith("^"):
        domain = line[4:-1]
        return f"DOMAIN-SUFFIX,{domain},DIRECT"
    
    # 3. Hosts规则转换
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)', line):
        domain = line.split()[1]
        return f"DOMAIN,{domain},{policy}"
    
    # 4. 纯域名规则转换
    if re.match(r'^[\w.-]+\.[\w.-]+$', line):
        return f"DOMAIN-SUFFIX,{line},{policy}"
    
    # 5. 其他格式原样保留
    return line

def process_rules(input_path, output_path, is_allow=False):
    """
    处理规则文件并转换格式
    """
    try:
        processed = 0
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(output_path, 'w', encoding='utf-8') as f_out:

            for line in f_in:
                if not is_valid_rule(line, is_allow):
                    continue
                
                converted = convert_rule(line, is_allow)
                f_out.write(converted + '\n')
                processed += 1

        log(f"Processed {processed} {'allow' if is_allow else 'block'} rules: {input_path} → {output_path}")
        return True

    except Exception as e:
        error(f"Rule processing failed: {str(e)}")
        return False

def download_mihomo_tool(tool_dir):
    """下载Mihomo转换工具"""
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        version_file = tool_dir / "version.txt"

        log(f"Fetching latest Mihomo version...")
        urllib.request.urlretrieve(version_url, version_file)

        with open(version_file, 'r') as f:
            version = f.read().strip()

        tool_name = f"mihomo-linux-amd64-{version}"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        tool_gz_path = tool_dir / f"{tool_name}.gz"

        log(f"Downloading Mihomo tool v{version}...")
        urllib.request.urlretrieve(tool_url, tool_gz_path)

        tool_path = tool_dir / tool_name
        with gzip.open(tool_gz_path, 'rb') as f_in:
            with open(tool_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        tool_path.chmod(0o755)
        version_file.unlink(missing_ok=True)
        tool_gz_path.unlink(missing_ok=True)

        return tool_path

    except Exception as e:
        error(f"Tool download failed: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, tool_path):
    """转换为Mihomo规则集"""
    try:
        cmd = [
            str(tool_path),
            "convert-ruleset",
            "domain",
            "text",
            str(input_file),
            str(output_file)
        ]
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        error(f"Conversion failed: {str(e)}")
        return False

def main():
    try:
        # 路径配置（输入输出都在根目录）
        base_dir = Path(__file__).parent.parent.parent  # 仓库根目录
        config = {
            "input_block": base_dir / "adblock.txt",  # 拦截规则
            "input_allow": base_dir / "allow.txt",    # 新增：放行规则
            "temp_block": Path(tempfile.gettempdir()) / "block.tmp",
            "temp_allow": Path(tempfile.gettempdir()) / "allow.tmp",
            "output": base_dir / "final.mrs",        # 最终合并输出
            "tool_dir": Path(tempfile.gettempdir()) / "mihomo_tools"
        }

        # 处理拦截规则
        if not process_rules(config["input_block"], config["temp_block"]):
            sys.exit(1)

        # 处理放行规则（如果存在）
        if config["input_allow"].exists():
            if not process_rules(config["input_allow"], config["temp_allow"], is_allow=True):
                sys.exit(1)
        else:
            log("No allow.txt found, skipping allow rules processing")

        # 合并规则文件
        with open(config["output"], 'w', encoding='utf-8') as f_out:
            # 先写入放行规则（优先级更高）
            if config["input_allow"].exists():
                with open(config["temp_allow"], 'r') as f_in:
                    f_out.write(f_in.read())
            
            # 再写入拦截规则
            with open(config["temp_block"], 'r') as f_in:
                f_out.write(f_in.read())

        # 转换为Mihomo格式
        tool = download_mihomo_tool(config["tool_dir"])
        if not tool:
            sys.exit(1)

        if not convert_to_mrs(config["output"], config["output"], tool):
            sys.exit(1)

        # 清理临时文件
        try:
            config["temp_block"].unlink(missing_ok=True)
            if config["input_allow"].exists():
                config["temp_allow"].unlink(missing_ok=True)
            shutil.rmtree(config["tool_dir"], ignore_errors=True)
            log("Temporary files cleaned up")
        except Exception as e:
            error(f"Error cleaning temp files: {str(e)}")

        log("="*50)
        log("Rule conversion complete!")
        log(f"Final output: {config['output']}")
        log("="*50)

    except Exception as e:
        error(f"Main process failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()