#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则转换器（直接引用版）
输入: 原始 adblock_clash.yaml（位于仓库根目录）
输出: 直接转换的 adb.mrs（位于仓库根目录）
不进行规则过滤和验证，直接传递原始规则
"""

import os
import sys
import tempfile
import subprocess
import yaml
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple


class Config:
    """配置管理（输入输出均在仓库根目录）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    # 输入文件（位于仓库根目录）
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    # 输出文件（位于仓库根目录）
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")

    def __init__(self):
        self._validate_compiler()

    def _validate_compiler(self) -> None:
        """验证编译器路径有效性"""
        compiler_path = self.compiler_abs_path
        if not compiler_path.exists():
            logger.critical(f"编译器不存在: {compiler_path}")
            sys.exit(1)
        if not os.access(compiler_path, os.X_OK):
            logger.critical(f"编译器无执行权限: {compiler_path}")
            sys.exit(1)

    @property
    def input_path(self) -> Path:
        """输入文件路径（仓库根目录）"""
        path = Path(self.GITHUB_WORKSPACE) / self.INPUT_FILE
        if not path.exists():
            logger.critical(f"输入文件不存在: {path}")
            sys.exit(1)
        return path

    @property
    def output_path(self) -> Path:
        """输出文件路径（仓库根目录）"""
        return Path(self.GITHUB_WORKSPACE) / self.OUTPUT_FILE

    @property
    def compiler_abs_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.COMPILER_PATH if not os.path.isabs(self.COMPILER_PATH) else Path(self.COMPILER_PATH)


def setup_logger():
    """配置GitHub风格日志"""
    logger = logging.getLogger("AdblockConverterDirect")
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
            timestamp = datetime.now().strftime('%H:%M:%S')
            if record.levelno == logging.INFO:
                return f"[{timestamp}] ::notice:: {record.getMessage()}"
            elif record.levelno == logging.WARNING:
                return f"[{timestamp}] ::warning:: {record.getMessage()}"
            elif record.levelno == logging.ERROR:
                return f"[{timestamp}] ::error:: {record.getMessage()}"
            return f"[{timestamp}] {record.getMessage()}"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GitHubFormatter())
    logger.handlers = [handler]
    return logger


logger = setup_logger()


class AdblockConverter:
    """规则转换器（直接传递原始规则）"""
    def __init__(self, config: Config):
        self.config = config
        self.stats = {
            'total_rules': 0,    # 总规则数
            'mrs_sha256': ''     # MRS文件的SHA256校验和
        }

    def parse_rule_string(self, rule_str: str) -> Tuple[str, str]:
        """解析规则字符串，返回(类型, 值)"""
        if ',' in rule_str:
            parts = rule_str.split(',', 1)
            rule_type = parts[0].strip().upper()
            value = parts[1].strip()
            return rule_type, value
        return "", rule_str  # 保留无法解析的原始字符串

    def parse_input(self) -> List[Dict[str, str]]:
        """直接读取原始规则，不做过滤和验证"""
        logger.info(f"读取原始输入文件: {self.config.input_path}")
        try:
            with self.config.input_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'payload' not in data:
                logger.error("输入文件缺少'payload'节点")
                return []

            rules: List[Dict[str, str]] = []
            for rule in data['payload']:
                self.stats['total_rules'] += 1
                
                if isinstance(rule, dict):
                    # 保留原始字典格式规则
                    rule_type = rule.get('type', '').upper()
                    value = rule.get('value', '').strip()
                    rules.append({'type': rule_type, 'value': value})
                elif isinstance(rule, str):
                    # 转换字符串格式规则为字典
                    rule_type, value = self.parse_rule_string(rule)
                    rules.append({'type': rule_type, 'value': value})

            logger.info(f"原始规则加载完成: 共{self.stats['total_rules']}条")
            return rules
        except yaml.YAMLError as e:
            logger.error(f"输入文件YAML格式错误: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"读取输入文件失败: {str(e)}")
            return []

    def generate_compile_yaml(self, rules: List[Dict[str, str]]) -> str:
        """生成用于编译的YAML内容（保留所有规则）"""
        if not rules:
            return ""
        yaml_lines = ["payload:"]
        for rule in rules:
            yaml_lines.append(f"  - type: {rule['type']}")
            yaml_lines.append(f"    value: {rule['value']}")
        logger.info(f"生成编译用YAML: 包含{len(rules)}条规则")
        return '\n'.join(yaml_lines)

    def compute_sha256(self, file_path: Path) -> str:
        """计算文件的SHA256校验和"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # 逐块读取文件以处理大文件
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算SHA256校验和失败: {str(e)}")
            return ""

    def compile_to_mrs(self, yaml_content: str) -> bool:
        """编译为MRS格式（输出到仓库根目录）"""
        if not yaml_content:
            # 生成空文件避免下游错误
            with self.config.output_path.open('w', encoding='utf-8') as f:
                f.write("")
            logger.warning("无有效规则，生成空MRS文件")
            return True

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
                f.write(yaml_content)
                temp_file = f.name

            result = subprocess.run(
                [
                    str(self.config.compiler_abs_path),
                    "convert-ruleset",
                    "domain",
                    "yaml",
                    temp_file,
                    str(self.config.output_path)
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                text=True
            )

            if result.returncode != 0:
                logger.error(
                    f"编译失败(返回码{result.returncode}):\n"
                    f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
                )
                return False

            if not self.config.output_path.exists() or self.config.output_path.stat().st_size == 0:
                logger.error("编译成功但输出文件为空")
                return False

            # 计算SHA256校验和
            self.stats['mrs_sha256'] = self.compute_sha256(self.config.output_path)
            if not self.stats['mrs_sha256']:
                logger.error("无法计算MRS文件的SHA256校验和")
                return False

            logger.info(
                f"MRS生成成功: {self.config.output_path} "
                f"({self.config.output_path.stat().st_size / 1024:.1f}KB), "
                f"SHA256: {self.stats['mrs_sha256']}"
            )
            return True
        except subprocess.TimeoutExpired:
            logger.error("编译超时（>300秒）")
            return False
        except Exception as e:
            logger.error(f"编译异常: {str(e)}")
            return False
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception as e:
                    logger.warning(f"临时文件清理失败: {str(e)}")

    def run(self) -> int:
        """执行流程：读取原始规则 → 编译"""
        # 1. 读取原始规则
        rules = self.parse_input()
        if not rules:
            logger.error("无规则可处理，终止流程")
            return 1

        # 2. 生成编译内容并编译
        yaml_content = self.generate_compile_yaml(rules)
        if not self.compile_to_mrs(yaml_content):
            return 1

        # 输出GitHub Action变量
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"mrs_path={self.config.output_path}\n")
                f.write(f"final_rule_count={len(rules)}\n")
                f.write(f"mrs_sha256={self.stats['mrs_sha256']}\n")
        else:
            logger.warning("未检测到GITHUB_OUTPUT环境变量，跳过变量输出")

        logger.info("转换流程完成")
        return 0


def main():
    try:
        config = Config()
        return AdblockConverter(config).run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
