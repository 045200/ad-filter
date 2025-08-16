#!/usr/bin/env python3
"""
Clash/Mihomo 广告规则转换工具 (优化版)
功能：使用 mihomo-tool 将文本规则转换为二进制规则集(.mrs)
特点：
1. 内置 strict 模式过滤
2. 支持 behavior 模式参数
3. 自动下载最新版 mihomo-tool
"""

import argparse
import atexit
import gzip
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ==================== 全局配置 ====================
DEFAULT_BEHAVIOR_MODE = "domain"
INTERNAL_STRICT_MODE = True  # 内部严格模式开关
MIHOMO_RELEASE_URL = "https://github.com/MetaCubeX/mihomo/releases/latest/download/"

class Logger:
    @staticmethod
    def info(message: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: {message}")

    @staticmethod
    def error(message: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {message}", file=sys.stderr)

    @staticmethod
    def debug(message: str) -> None:
        if os.getenv("DEBUG"):
            print(f"[{datetime.now().strftime('%H:%M:%S')}] DEBUG: {message}")

class FileHandler:
    @staticmethod
    def read_lines(file_path: Path) -> List[str]:
        encodings = ['utf-8', 'gbk', 'latin-1']
        for enc in encodings:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    return [line.strip() for line in f if line.strip()]
            except UnicodeDecodeError:
                continue
        raise ValueError(f"无法解码文件: {file_path}")

    @staticmethod
    def safe_write(output_path: Path, content: str) -> bool:
        temp_path = output_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(content)
            temp_path.replace(output_path)
            return True
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            raise RuntimeError(f"文件写入失败: {str(e)}")

class RuleConverter:
    RULE_PATTERNS = {
        'DOMAIN': (r'^\|\|([\w.-]+)\^?$', 'DOMAIN,{},REJECT'),
        'DOMAIN-SUFFIX': (r'^\|\|(\*\.[\w.-]+)\^?$', 'DOMAIN-SUFFIX,{},REJECT'),
        'DOMAIN-KEYWORD': (r'^\$([a-z-]+)$', 'DOMAIN-KEYWORD,{},REJECT'),
        'IP-CIDR': (r'^block:\/\/(\d+\.\d+\.\d+\.\d+)$', 'IP-CIDR,{}/32,REJECT'),
        'IP-CIDR6': (r'^block:\/\/([\da-fA-F:]+)$', 'IP-CIDR6,{}/128,REJECT'),
        'GEOSITE': (r'^geosite:([\w-]+)$', 'GEOSITE,{},REJECT'),
        'WHITELIST': (r'^@@\|\|([\w.-]+)\^?$', 'DOMAIN,{},DIRECT')
    }

    @classmethod
    def convert_line(cls, line: str, strict: bool = INTERNAL_STRICT_MODE) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None
            
        if strict and not cls.is_supported_rule(line):
            Logger.debug(f"跳过不支持的规则（严格模式）: {line}")
            return None
            
        for rule_type, (pattern, template) in cls.RULE_PATTERNS.items():
            if match := re.match(pattern, line):
                content = match.group(1)
                if rule_type == 'DOMAIN-SUFFIX' and content.startswith('*.'):
                    content = content[2:]
                return template.format(content)
        return None

    @classmethod
    def is_supported_rule(cls, line: str) -> bool:
        line = line.strip()
        return any(re.match(pattern, line) for _, (pattern, _) in cls.RULE_PATTERNS.items())

class MihomoToolManager:
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.tool_dir = work_dir / "tools"
        self.tool_path = self.tool_dir / "mihomo-tool"
        self._setup()

    def _setup(self) -> None:
        self.tool_dir.mkdir(parents=True, exist_ok=True)
        if not self.tool_path.exists():
            self._download_tool()
        self._validate_tool()

    def _download_tool(self) -> None:
        try:
            version_file = self.tool_dir / "version.txt"
            urllib.request.urlretrieve(f"{MIHOMO_RELEASE_URL}version.txt", version_file)
            
            with open(version_file, 'r') as f:
                version = f.read().strip()

            tool_name = f"mihomo-linux-amd64-{version}"
            tool_gz_path = self.tool_dir / f"{tool_name}.gz"
            
            Logger.info(f"下载 mihomo-tool v{version}...")
            urllib.request.urlretrieve(f"{MIHOMO_RELEASE_URL}{tool_name}.gz", tool_gz_path)

            with gzip.open(tool_gz_path, 'rb') as f_in:
                with open(self.tool_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self.tool_path.chmod(0o755)

            version_file.unlink(missing_ok=True)
            tool_gz_path.unlink(missing_ok=True)

        except Exception as e:
            raise RuntimeError(f"工具下载失败: {str(e)}")

    def _validate_tool(self) -> None:
        try:
            result = subprocess.run([str(self.tool_path), "-v"], capture_output=True, text=True, check=True)
            Logger.info(f"工具版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"工具验证失败: {e.stderr}")

    def convert_ruleset(self, input_file: Path, output_file: Path, behavior: str) -> bool:
        cmd = [
            str(self.tool_path),
            "convert-ruleset",
            behavior,
            "text",
            str(input_file),
            str(output_file)
        ]
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            Logger.error(f"转换失败: {e.stderr}")
            return False

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--behavior",
        choices=["domain", "classical"],
        default=DEFAULT_BEHAVIOR_MODE,
        help=f"行为模式 (默认: {DEFAULT_BEHAVIOR_MODE})"
    )
    return parser.parse_args()

def setup_workdir() -> Path:
    work_dir = Path(tempfile.mkdtemp(prefix="clash_rule_"))
    atexit.register(lambda: shutil.rmtree(work_dir, ignore_errors=True))
    Logger.info(f"工作目录: {work_dir}")
    return work_dir

def process_rules(input_files: Dict[str, Path]) -> List[str]:
    merged_rules = []
    for name, path in input_files.items():
        if path.exists():
            Logger.info(f"处理文件: {path.name}")
            try:
                lines = FileHandler.read_lines(path)
                converted = filter(None, [
                    RuleConverter.convert_line(line, strict=INTERNAL_STRICT_MODE)
                    for line in lines
                ])
                merged_rules.extend(converted)
            except Exception as e:
                Logger.error(f"处理文件 {path} 失败: {str(e)}")
                raise
    return merged_rules

def main() -> int:
    args = parse_args()
    work_dir = setup_workdir()
    
    Logger.info(f"当前配置: behavior={args.behavior}, strict_mode={INTERNAL_STRICT_MODE}")

    try:
        script_dir = Path(__file__).parent
        repo_root = script_dir.parent.parent
        input_files = {
            'block': repo_root / 'adblock.txt',
            'allow': repo_root / 'allow.txt'
        }
        output_mrs = repo_root / 'adb.mrs'

        merged_rules = process_rules(input_files)
        merged_path = work_dir / 'merged.txt'
        FileHandler.safe_write(merged_path, '\n'.join(merged_rules))

        tool = MihomoToolManager(work_dir)
        Logger.info(f"开始转换规则 (behavior={args.behavior})...")
        if tool.convert_ruleset(merged_path, output_mrs, args.behavior):
            Logger.info(f"✅ 转换完成: {output_mrs}")
            Logger.info(f"规则总数: {len(merged_rules)}条")
            return 0
        return 1

    except Exception as e:
        Logger.error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())