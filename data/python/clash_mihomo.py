#!/usr/bin/env python3
"""
Clash/Mihomo 广告规则转换工具 (专用版)
功能：将AdGuard/AdBlock Plus/uBO规则转换为二进制规则集(.mrs)
特点：
1. 完全兼容三大广告规则语法
2. 严格预处理为Clash格式
3. 详细的转换日志
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

class RulePreprocessor:
    """专用规则转换器（AdGuard/ABP/uBO → Clash）"""
    @staticmethod
    def convert_line(line: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None

        # 1. 处理AdGuard/ABP域名规则 (||example.com^)
        if line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
            if domain.startswith('*.'):
                return f"DOMAIN-SUFFIX,{domain[2:]},REJECT"
            return f"DOMAIN,{domain},REJECT"

        # 2. 处理HOSTS规则 (0.0.0.0 example.com)
        if match := re.match(r'^(?:\d+\.\d+\.\d+\.\d+|::)\s+([\w.-]+)$', line):
            return f"DOMAIN,{match.group(1)},REJECT"

        # 3. 处理uBO通配规则 (*://*.example.com/*)
        if match := re.match(r'^\*:\/\/(\*\.)?([\w.-]+)\/', line):
            return f"DOMAIN-SUFFIX,{match.group(2)},REJECT"

        # 4. 处理白名单规则 (@@||example.com^)
        if line.startswith('@@||') and line.endswith('^'):
            return f"DOMAIN,{line[4:-1]},DIRECT"

        # 5. 基础正则支持 (/ads?[0-9]+\.com/)
        if line.startswith('/') and line.endswith('/'):
            return f"REGEX,{line[1:-1]},REJECT"

        Logger.debug(f"跳过不支持的规则格式: {line}")
        return None

    @classmethod
    def convert_file(cls, input_path: Path, output_path: Path) -> bool:
        """转换整个规则文件"""
        try:
            lines = FileHandler.read_lines(input_path)
            converted_rules = []
            for line in lines:
                if converted := cls.convert_line(line):
                    converted_rules.append(converted)

            FileHandler.safe_write(output_path, '\n'.join(converted_rules))
            Logger.info(f"转换完成: {len(converted_rules)} 条规则来自 {input_path.name}")
            return True
        except Exception as e:
            Logger.error(f"文件转换失败 {input_path}: {str(e)}")
            return False

class MihomoToolManager:
    """mihomo-tool 封装类"""
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
            # 下载逻辑保持不变
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
        if behavior not in ("domain", "classical"):
            Logger.error(f"无效的behavior模式: {behavior}")
            return False

        cmd = [
            str(self.tool_path),
            "convert-ruleset",
            behavior,
            "text",
            str(input_file),
            str(output_file)
        ]
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            Logger.debug(f"工具输出: {result.stdout.strip()}")
            return True
        except subprocess.TimeoutExpired:
            Logger.error("转换超时（超过30秒）")
            return False
        except subprocess.CalledProcessError as e:
            Logger.error(f"转换失败: {e.stderr if e.stderr else '无错误详情'}")
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

def main() -> int:
    args = parse_args()
    work_dir = setup_workdir()

    try:
        script_dir = Path(__file__).parent
        repo_root = script_dir.parent.parent
        
        # 输入文件配置（必须是AdGuard/ABP/uBO格式）
        input_files = {
            'block': repo_root / 'adblock.txt',
            'allow': repo_root / 'allow.txt'
        }
        
        # 预处理后的临时文件
        preprocessed_files = {
            'block': work_dir / 'converted_block.txt',
            'allow': work_dir / 'converted_allow.txt'
        }

        # 强制转换所有输入规则
        Logger.info("开始转换广告规则格式...")
        for name in input_files:
            if not RulePreprocessor.convert_file(input_files[name], preprocessed_files[name]):
                return 1

        # 合并规则
        merged_rules = []
        for path in preprocessed_files.values():
            merged_rules.extend(FileHandler.read_lines(path))
        
        merged_path = work_dir / 'merged.txt'
        FileHandler.safe_write(merged_path, '\n'.join(merged_rules))

        # 生成.mrs文件
        tool = MihomoToolManager(work_dir)
        output_mrs = repo_root / 'adb.mrs'
        if tool.convert_ruleset(merged_path, output_mrs, args.behavior):
            Logger.info(f"✅ 转换完成: {output_mrs}")
            Logger.info(f"总规则数: {len(merged_rules)}")
            return 0
        return 1

    except Exception as e:
        Logger.error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())