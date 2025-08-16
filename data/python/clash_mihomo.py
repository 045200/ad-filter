#!/usr/bin/env python3
"""
Clash/Mihomo 广告规则转换工具 (最终版)
功能：将文本规则转换为.mrs二进制规则集
改进点：
1. 可配置behavior参数（domain/classical）
2. 增强严格模式过滤
3. 优化mihomo-tool调用参数验证
4. 支持GEOSITE规则类型
"""

import os
import re
import sys
import argparse  # [新增] 用于命令行参数解析
import urllib.request
import subprocess
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
import atexit

# ==================== 配置项 ====================
# [新增] 可通过命令行覆盖这些配置
DEFAULT_STRICT_MODE = True          # 默认严格模式
DEFAULT_BEHAVIOR_MODE = "domain"    # 默认行为模式（domain/classical）

# 其他配置保持不变
WORK_DIR = Path(tempfile.mkdtemp(prefix="clash_rule_"))
MIHOMO_TOOL_VERSION = "v1.18.0"   
PLATFORM = "linux-amd64"          
TOOL_URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_TOOL_VERSION}/mihomo-tool-{PLATFORM}"

# ==================== 日志系统 (不变) ====================
def log(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

def error(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] {message}", file=sys.stderr)

# ==================== Clash规则处理器 (仅添加GEOSITE支持) ====================
class ClashRuleConverter:
    SUPPORTED_RULES = {
        # 原始规则类型保持不变
        'DOMAIN': (r'^\|\|([\w.-]+)\^?$', 'DOMAIN,{},REJECT'),
        'DOMAIN-SUFFIX': (r'^\|\|(\*\.[\w.-]+)\^?$', 'DOMAIN-SUFFIX,{},REJECT'),
        'DOMAIN-KEYWORD': (r'^\$([a-z-]+)$', 'DOMAIN-KEYWORD,{},REJECT'),
        'IP-CIDR': (r'^block:\/\/(\d+\.\d+\.\d+\.\d+)$', 'IP-CIDR,{}/32,REJECT'),
        'IP-CIDR6': (r'^block:\/\/([\da-fA-F:]+)$', 'IP-CIDR6,{}/128,REJECT'),
        
        # [新增] GEOSITE支持
        'GEOSITE': (r'^geosite:([\w-]+)$', 'GEOSITE,{},REJECT'),
        
        # 原始白名单规则保持不变
        'WHITELIST': (r'^@@\|\|([\w.-]+)\^?$', 'DOMAIN,{},DIRECT')
    }

    # 保持原始方法不变
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

# ==================== 文件处理器 (不变) ====================
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

# ==================== Mihomo工具 (关键改进点) ====================
class MihomoTool:
    def __init__(self, work_dir):
        self.tool_path = work_dir / "mihomo-tool"
        self._setup()

    def _setup(self):
        if not self.tool_path.exists():
            log(f"下载mihomo-tool {MIHOMO_TOOL_VERSION}...")
            urllib.request.urlretrieve(TOOL_URL, str(self.tool_path))
            self.tool_path.chmod(0o755)
        result = subprocess.run([str(self.tool_path), "--version"], capture_output=True, text=True)
        if MIHOMO_TOOL_VERSION not in result.stdout:
            raise RuntimeError("工具版本不匹配")

    def generate_mrs(self, input_file, output_file, behavior_mode):
        """[改进] 添加behavior_mode参数控制"""
        cmd = [
            str(self.tool_path), "rule-set",
            "--strict" if STRICT_MODE else "",
            "--behavior", behavior_mode,  # [核心改进] 动态传入行为模式
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
            raise

# ==================== 主流程 (添加命令行参数) ====================
def parse_args():
    """[新增] 命令行参数解析"""
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
    args = parse_args()  # [新增] 获取命令行参数
    global STRICT_MODE
    STRICT_MODE = args.strict  # [新增] 覆盖配置
    
    atexit.register(lambda: shutil.rmtree(WORK_DIR, ignore_errors=True))
    log(f"工作目录: {WORK_DIR}")
    log(f"当前模式: strict={STRICT_MODE}, behavior={args.behavior}")  # [新增] 显示当前配置

    try:
        # 文件定位逻辑不变
        script_dir = Path(__file__).parent
        repo_root = script_dir.parent.parent
        input_files = {
            'block': repo_root / 'adblock.txt',
            'allow': repo_root / 'allow.txt'
        }
        output_mrs = repo_root / 'adb.mrs'

        tool = MihomoTool(WORK_DIR)

        # 规则处理逻辑不变
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

        log(f"生成.mrs文件 (behavior={args.behavior})...")  # [改进] 显示当前行为模式
        tool.generate_mrs(merged_path, output_mrs, args.behavior)  # [改进] 传入behavior参数

        log(f"✅ 处理完成，生成文件: {output_mrs}")
        log(f"规则总数: {len(merged_rules)}条")
        return 0

    except Exception as e:
        error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())