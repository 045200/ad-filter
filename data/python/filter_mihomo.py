#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则转换器（增强版）
输入: 已去重、格式合规的 Clash YAML 规则文件
输出: adb.mrs
适配GitHub Actions环境，支持多规则类型转换与完善的错误处理
"""

import os
import sys
import ipaddress
import tempfile
import subprocess
import idna
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict


class Config:
    """配置管理（含前置验证）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    MAX_DOMAIN_LENGTH = 253  # RFC 1035 限制
    MAX_LABEL_LENGTH = 63    # RFC 1035 限制
    SUPPORTED_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'}  # 支持的规则类型

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
        path = Path(self.GITHUB_WORKSPACE) / self.INPUT_FILE
        if not path.exists():
            logger.critical(f"输入文件不存在: {path}")
            sys.exit(1)
        return path

    @property
    def output_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.OUTPUT_FILE

    @property
    def compiler_abs_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.COMPILER_PATH if not os.path.isabs(self.COMPILER_PATH) else Path(self.COMPILER_PATH)


class DNSValidator:
    """DNS格式验证工具"""
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """验证域名格式合法性（基于RFC规范）"""
        domain = domain.strip().lower()
        # 基础长度校验
        if not domain or len(domain) > Config.MAX_DOMAIN_LENGTH:
            return False
        # 排除IP地址
        try:
            ipaddress.ip_address(domain)
            return False
        except ValueError:
            pass
        # 标签格式校验
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        for label in labels:
            if not label or len(label) > Config.MAX_LABEL_LENGTH or label.startswith('-') or label.endswith('-'):
                return False
        # IDNA编码验证（支持国际化域名）
        try:
            idna.encode(domain)
            return True
        except idna.IDNAError:
            return False


def setup_logger():
    """配置GitHub风格日志"""
    logger = logging.getLogger("AdblockConverter")
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
    """规则转换器核心逻辑"""
    def __init__(self, config: Config):
        self.config = config
        self.stats = {
            'total': 0,       # 总规则数
            'valid': 0,       # 有效规则数
            'invalid': 0,     # 无效规则数（格式错误）
            'unsupported': 0, # 不支持的规则类型
            'duplicate': 0    # 重复规则数
        }

    def _clean_yaml_content(self) -> str:
        """清理YAML内容（移除注释和空行）"""
        with self.config.input_path.open('r', encoding='utf-8') as f:
            lines = []
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue  # 跳过空行和注释行
                lines.append(line.rstrip('\n'))  # 保留原始缩进
        return '\n'.join(lines)

    def parse_input(self) -> List[Dict[str, str]]:
        """解析输入文件并提取有效规则"""
        logger.info(f"解析输入文件: {self.config.input_path}")

        try:
            cleaned_content = self._clean_yaml_content()
            data = yaml.safe_load(cleaned_content)

            if not data or 'payload' not in data:
                logger.error("文件缺少'payload'节点（可能来自上游生成脚本）")
                return []

            valid_rules: List[Dict[str, str]] = []
            seen = set()  # 用于去重的标记集合 (type, value)

            for rule in data['payload']:
                self.stats['total'] += 1

                # 基础格式校验
                if not isinstance(rule, dict):
                    self.stats['invalid'] += 1
                    continue

                # 提取规则类型和值
                rule_type = rule.get('type', '').upper()
                domain = rule.get('value', '').strip().lower()

                # 规则类型校验
                if rule_type not in self.config.SUPPORTED_TYPES:
                    self.stats['unsupported'] += 1
                    continue

                # 域名值校验
                if not domain:
                    self.stats['invalid'] += 1
                    continue

                # DNS格式校验
                if not DNSValidator.is_valid_domain(domain):
                    self.stats['invalid'] += 1
                    continue

                # 去重校验
                rule_key = (rule_type, domain)
                if rule_key in seen:
                    self.stats['duplicate'] += 1
                    continue

                # 通过所有校验
                seen.add(rule_key)
                valid_rules.append({'type': rule_type, 'value': domain})
                self.stats['valid'] += 1

            # 输出统计信息
            logger.info(
                f"解析完成: 总规则{self.stats['total']}, "
                f"有效{self.stats['valid']}, "
                f"无效{self.stats['invalid']}, "
                f"不支持{self.stats['unsupported']}, "
                f"重复{self.stats['duplicate']}"
            )
            return valid_rules

        except yaml.YAMLError as e:
            logger.error(f"YAML格式错误（可能来自上游生成脚本）: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"解析失败: {str(e)}")
            return []

    def generate_compile_yaml(self, rules: List[Dict[str, str]]) -> str:
        """生成用于编译的YAML内容（保留原始规则类型）"""
        if not rules:
            return ""

        # 按域名排序（增强可读性）
        sorted_rules = sorted(rules, key=lambda x: x['value'])

        # 构建YAML行
        yaml_lines = ["payload:"]
        for rule in sorted_rules:
            yaml_lines.append(f"  - type: {rule['type']}")
            yaml_lines.append(f"    value: {rule['value']}")

        logger.info(f"生成编译用YAML: 包含{len(sorted_rules)}条规则")
        return '\n'.join(yaml_lines)

    def compile_to_mrs(self, yaml_content: str) -> bool:
        """使用编译器将YAML转换为MRS格式"""
        if not yaml_content:
            logger.error("无有效内容可编译")
            return False

        temp_file = None
        try:
            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
                f.write(yaml_content)
                temp_file = f.name
                logger.debug(f"临时文件创建: {temp_file}")

            # 执行编译命令
            logger.info(f"开始编译: {self.config.compiler_abs_path}")
            result = subprocess.run(
                [
                    str(self.config.compiler_abs_path),
                    "convert-ruleset",
                    "domain",
                    "mrs",
                    temp_file,
                    str(self.config.output_path)
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                text=True
            )

            # 处理编译结果
            if result.returncode != 0:
                error_msg = (
                    f"编译失败(返回码: {result.returncode})\n"
                    f"标准输出: {result.stdout[:500]}...\n"
                    f"标准错误: {result.stderr[:500]}..."
                )
                logger.error(error_msg)
                return False

            # 验证输出文件
            if not self.config.output_path.exists():
                logger.error("编译成功但未生成输出文件")
                return False
            if self.config.output_path.stat().st_size == 0:
                logger.error("输出文件为空")
                return False

            logger.info(
                f"MRS生成成功: {self.config.output_path} "
                f"({self.config.output_path.stat().st_size / 1024:.1f}KB)"
            )
            return True

        except subprocess.TimeoutExpired:
            logger.error("编译超时（>300秒）")
            return False
        except Exception as e:
            logger.error(f"编译异常: {str(e)}")
            return False
        finally:
            # 清理临时文件
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                    logger.debug(f"临时文件已清理: {temp_file}")
                except Exception as e:
                    logger.warning(f"临时文件清理失败: {str(e)}")

    def run(self) -> int:
        """执行完整转换流程"""
        # 解析并提取规则
        valid_rules = self.parse_input()
        if not valid_rules:
            logger.error("无有效规则可处理，终止流程")
            return 1

        # 生成编译用YAML
        yaml_content = self.generate_compile_yaml(valid_rules)
        if not yaml_content:
            logger.error("生成编译内容失败")
            return 1

        # 编译为MRS
        if not self.compile_to_mrs(yaml_content):
            logger.error("编译流程失败")
            return 1

        # 输出GitHub Action变量
        print(f"::set-output name=mrs_path::{self.config.output_path}")
        print(f"::set-output name=rule_count::{self.stats['valid']}")

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
