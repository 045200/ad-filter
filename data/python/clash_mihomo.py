#!/usr/bin/env python3
"""
Clash/Mihomo 广告规则转换工具 (YAML格式专用版)
功能：将广告规则转换为Clash YAML格式，再编译为.mrs二进制规则集
特点：
1. 严格遵循Clash YAML规则格式
2. 自动添加REJECT策略头
3. 支持大文件处理
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
from typing import List, Optional

# ==================== 全局配置 ====================
DEFAULT_BEHAVIOR = "domain"
MIHOMO_RELEASE_URL = "https://github.com/MetaCubeX/mihomo/releases/latest/download/"
DEFAULT_HEADER = """#TITLE=Generated Clash Rules
#VER={date}
#URL=https://github.com/045200/ad-filter
#RULE-SET,Ad-filter,REJECT
payload:
"""

class Logger:
    @staticmethod
    def info(msg: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: {msg}")

    @staticmethod
    def error(msg: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {msg}", file=sys.stderr)

class RuleConverter:
    """广告规则转换核心类"""
    @staticmethod
    def convert_line(line: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None

        # 跳过白名单规则
        if line.startswith('@@'):
            Logger.debug(f"跳过白名单: {line}")
            return None

        # 1. AdGuard格式 (||example.com^)
        if line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
            return f"+.{domain}"

        # 2. HOSTS格式 (0.0.0.0 example.com)
        if match := re.match(r'^(?:\d+\.\d+\.\d+\.\d+|::)\s+([\w.-]+)', line):
            return f"+.{match.group(1)}"

        # 3. uBO格式 (*://*.example.com/*)
        if match := re.match(r'^\*:\/\/(\*\.)?([\w.-]+)\/', line):
            return f"+.{match.group(2)}"

        Logger.debug(f"跳过不支持的规则: {line}")
        return None

    @classmethod
    def convert_to_yaml(cls, input_path: Path, output_path: Path) -> bool:
        """转换为Clash YAML格式"""
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            yaml_content = DEFAULT_HEADER.format(date=datetime.now().strftime('%Y%m%d%H%M%S'))
            rule_count = 0

            for line in lines:
                if converted := cls.convert_line(line):
                    yaml_content += f"  - '{converted}'\n"
                    rule_count += 1

            if rule_count == 0:
                Logger.error("未找到有效规则")
                return False

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            Logger.info(f"生成YAML规则: {rule_count}条")
            return True

        except Exception as e:
            Logger.error(f"YAML转换失败: {str(e)}")
            return False

class MihomoCompiler:
    """mihomo-tool 编译器封装"""
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.tool_path = work_dir / "mihomo-tool"
        self._setup_tool()

    def _setup_tool(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.tool_path.exists():
            self._download_tool()

        self.tool_path.chmod(0o755)
        self._verify_tool()

    def _download_tool(self) -> None:
        try:
            # 获取最新版本
            version_url = f"{MIHOMO_RELEASE_URL}version.txt"
            urllib.request.urlretrieve(version_url, self.work_dir/"version.txt")
            
            with open(self.work_dir/"version.txt", 'r') as f:
                version = f.read().strip()

            # 下载工具
            tool_name = f"mihomo-linux-amd64-{version}"
            tool_gz = self.work_dir / f"{tool_name}.gz"
            
            Logger.info(f"下载 mihomo-tool v{version}...")
            urllib.request.urlretrieve(f"{MIHOMO_RELEASE_URL}{tool_name}.gz", tool_gz)

            # 解压
            with gzip.open(tool_gz, 'rb') as f_in:
                with open(self.tool_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # 清理
            tool_gz.unlink()
            (self.work_dir/"version.txt").unlink()

        except Exception as e:
            raise RuntimeError(f"工具下载失败: {str(e)}")

    def _verify_tool(self) -> None:
        try:
            result = subprocess.run(
                [str(self.tool_path), "-v"],
                check=True,
                capture_output=True,
                text=True
            )
            Logger.info(f"工具版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"工具验证失败: {e.stderr}")

    def compile_ruleset(self, yaml_path: Path, output_path: Path, behavior: str) -> bool:
        """编译YAML为.mrs"""
        cmd = [
            str(self.tool_path),
            "convert-ruleset",
            behavior,
            "text",
            str(yaml_path),
            str(output_path)
        ]

        try:
            subprocess.run(cmd, check=True, timeout=30)
            return True
        except subprocess.TimeoutExpired:
            Logger.error("编译超时")
            return False
        except subprocess.CalledProcessError as e:
            Logger.error(f"编译失败: {e.stderr}")
            return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--behavior",
        choices=["domain", "classical"],
        default=DEFAULT_BEHAVIOR,
        help="规则行为模式"
    )
    args = parser.parse_args()

    # 设置工作目录
    work_dir = Path(tempfile.mkdtemp(prefix="clash_"))
    atexit.register(lambda: shutil.rmtree(work_dir, ignore_errors=True))

    try:
        # 输入输出路径
        input_file = Path("adblock.txt")
        yaml_file = work_dir / "rules.yaml"
        output_file = Path("adb.mrs")

        # 转换流程
        Logger.info("开始转换规则...")
        
        # 1. 转换为YAML
        if not RuleConverter.convert_to_yaml(input_file, yaml_file):
            return 1

        # 2. 编译为.mrs
        compiler = MihomoCompiler(work_dir)
        if compiler.compile_ruleset(yaml_file, output_file, args.behavior):
            Logger.info(f"✅ 成功生成: {output_file}")
            return 0
        
        return 1

    except Exception as e:
        Logger.error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())