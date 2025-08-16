#!/usr/bin/env python3
"""
Clash/Mihomo 广告规则转换工具 (最终版)
功能：将文本规则转换为.mrs二进制规则集
改进点：
1. 可配置behavior参数（domain/classical）
2. 增强严格模式过滤
3. 优化mihomo-tool调用参数验证
4. 支持GEOSITE规则类型
5. 改进的下载逻辑（自动获取最新版本）
"""

import os
import re
import sys
import argparse
import urllib.request
import subprocess
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
import atexit
import gzip

# ==================== 配置项 ====================
DEFAULT_STRICT_MODE = True          # 默认严格模式
DEFAULT_BEHAVIOR_MODE = "domain"    # 默认行为模式（domain/classical）

WORK_DIR = Path(tempfile.mkdtemp(prefix="clash_rule_"))
TOOL_DIR = WORK_DIR / "tools"
TOOL_NAME = "mihomo-tool"

# ==================== 日志系统 ====================
def log(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

def error(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] {message}", file=sys.stderr)

# ==================== Clash规则处理器 ====================
class ClashRuleConverter:
    SUPPORTED_RULES = {
        'DOMAIN': (r'^\|\|([\w.-]+)\^?$', 'DOMAIN,{},REJECT'),
        'DOMAIN-SUFFIX': (r'^\|\|(\*\.[\w.-]+)\^?$', 'DOMAIN-SUFFIX,{},REJECT'),
        'DOMAIN-KEYWORD': (r'^\$([a-z-]+)$', 'DOMAIN-KEYWORD,{},REJECT'),
        'IP-CIDR': (r'^block:\/\/(\d+\.\d+\.\d+\.\d+)$', 'IP-CIDR,{}/32,REJECT'),
        'IP-CIDR6': (r'^block:\/\/([\da-fA-F:]+)$', 'IP-CIDR6,{}/128,REJECT'),
        'GEOSITE': (r'^geosite:([\w-]+)$', 'GEOSITE,{},REJECT'),
        'WHITELIST': (r'^@@\|\|([\w.-]+)\^?$', 'DOMAIN,{},DIRECT')
    }

    @classmethod
    def convert_rule(cls, line):
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None
        for rule_type, (pattern, template) in cls.SUPPORTED_RULES.items():
            if match := re.match(pattern, line):
                content = match.group(1)
                if rule_type == 'DOMAIN-SUFFIX' and content.startswith('*.'):
                    content = content[2:]
                return template.format(content)
        return None

    @classmethod
    def is_supported(cls, line):
        line = line.strip()
        return any(re.match(pattern, line) for _, (pattern, _) in cls.SUPPORTED_RULES.items())

# ==================== 文件处理器 ====================
class FileProcessor:
    @staticmethod
    def read_lines(file_path):
        encodings = ['utf-8', 'gbk', 'latin-1']
        for enc in encodings:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    return [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                continue
        raise ValueError(f"无法解码文件: {file_path}")

    @staticmethod
    def write_temp(output_path, lines):
        temp_path = output_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            temp_path.replace(output_path)
            return True
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            raise e

# ==================== Mihomo工具 (改进下载逻辑) ====================
class MihomoTool:
    def __init__(self, work_dir):
        self.tool_dir = TOOL_DIR
        self.tool_path = TOOL_DIR / TOOL_NAME
        self._setup()

    def _setup(self):
        if not self.tool_path.exists():
            self._download_tool()
        
        # 验证工具可用性
        try:
            result = subprocess.run([str(self.tool_path), "--version"], 
                                  capture_output=True, 
                                  text=True,
                                  check=True)
            log(f"工具版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"工具验证失败: {e.stderr}")

    def _download_tool(self):
        try:
            self.tool_dir.mkdir(parents=True, exist_ok=True)
            version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
            version_file = self.tool_dir / "version.txt"

            log(f"获取 Mihomo 最新版本 ({version_url})...")
            urllib.request.urlretrieve(version_url, version_file)

            with open(version_file, 'r') as f:
                version = f.read().strip()

            tool_name = f"mihomo-linux-amd64-{version}"
            tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
            tool_gz_path = self.tool_dir / f"{tool_name}.gz"

            log(f"下载 Mihomo 工具 v{version} ({tool_url})...")
            urllib.request.urlretrieve(tool_url, tool_gz_path)

            # 解压.gz文件
            with gzip.open(tool_gz_path, 'rb') as f_in:
                with open(self.tool_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # 设置可执行权限
            self.tool_path.chmod(0o755)
            
            # 清理临时文件
            tool_gz_path.unlink(missing_ok=True)
            version_file.unlink(missing_ok=True)
            
        except Exception as e:
            error(f"下载工具失败: {str(e)}")
            raise RuntimeError("无法下载mihomo-tool")

    def generate_mrs(self, input_file, output_file, behavior_mode):
        cmd = [
            str(self.tool_path), "rule-set",
            "--strict" if STRICT_MODE else "",
            "--behavior", behavior_mode,
            "--out-format", "binary",
            "--output", str(output_file),
            str(input_file)
        ]
        cmd = [arg for arg in cmd if arg]  # 移除空参数
        
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            error(f"命令执行失败: {' '.join(cmd)}")
            error(f"错误输出: {e.stderr}")
            raise

# ==================== 主流程 ====================
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", 
                       action="store_true",
                       default=DEFAULT_STRICT_MODE,
                       help=f"严格模式 (默认: {DEFAULT_STRICT_MODE})")
    parser.add_argument("--behavior",
                       choices=["domain", "classical"],
                       default=DEFAULT_BEHAVIOR_MODE,
                       help=f"行为模式 (默认: {DEFAULT_BEHAVIOR_MODE})")
    return parser.parse_args()

def main():
    args = parse_args()
    global STRICT_MODE
    STRICT_MODE = args.strict

    atexit.register(lambda: shutil.rmtree(WORK_DIR, ignore_errors=True))
    log(f"工作目录: {WORK_DIR}")
    log(f"当前模式: strict={STRICT_MODE}, behavior={args.behavior}")

    try:
        script_dir = Path(__file__).parent
        repo_root = script_dir.parent.parent
        input_files = {
            'block': repo_root / 'adblock.txt',
            'allow': repo_root / 'allow.txt'
        }
        output_mrs = repo_root / 'adb.mrs'

        tool = MihomoTool(WORK_DIR)

        merged_rules = []
        for name, path in input_files.items():
            if path.exists():
                log(f"处理文件: {path.name}")
                lines = FileProcessor.read_lines(path)
                converted = filter(None, [
                    ClashRuleConverter.convert_rule(line)
                    for line in lines
                    if not STRICT_MODE or ClashRuleConverter.is_supported(line)
                ])
                merged_rules.extend(converted)

        merged_path = WORK_DIR / 'merged.txt'
        FileProcessor.write_temp(merged_path, merged_rules)

        log(f"生成.mrs文件 (behavior={args.behavior})...")
        tool.generate_mrs(merged_path, output_mrs, args.behavior)

        log(f"✅ 处理完成，生成文件: {output_mrs}")
        log(f"规则总数: {len(merged_rules)}条")
        return 0

    except Exception as e:
        error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())