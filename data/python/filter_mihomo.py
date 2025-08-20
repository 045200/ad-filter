#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则转换器（极简版）
输入: 已去重、格式合规的 Clash YAML 规则文件
输出: adb.mrs
适配GitHub Actions环境，直接解析生成并编译
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
from typing import List


class Config:
    """配置管理（优先读取GitHub环境变量）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    MAX_DOMAIN_LENGTH = 253  # RFC 1035 限制
    MAX_LABEL_LENGTH = 63    # RFC 1035 限制

    @property
    def input_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.INPUT_FILE

    @property
    def output_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.OUTPUT_FILE

    @property
    def compiler_abs_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.COMPILER_PATH if not os.path.isabs(self.COMPILER_PATH) else Path(self.COMPILER_PATH)


class DNSValidator:
    """极简DNS验证（仅检查格式合法性）"""
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
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
        # IDNA编码验证
        try:
            idna.encode(domain)
            return True
        except idna.IDNAError:
            return False


def setup_logger():
    """GitHub适配日志"""
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
    """极简转换器（输入已去重）"""
    def __init__(self, config: Config):
        self.config = config
        self.stats = {
            'total': 0,    # 输入总规则数
            'valid': 0,    # 有效域名数
            'invalid': 0   # 无效域名数（DNS格式问题）
        }

    def parse_input(self) -> List[str]:
        """直接解析输入文件（假设已去重）"""
        input_path = self.config.input_path
        logger.info(f"解析输入文件: {input_path}")

        if not input_path.exists():
            logger.error(f"输入文件不存在: {input_path}")
            return []

        try:
            with input_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'payload' not in data:
                logger.error("文件缺少'payload'节点")
                return []

            valid_domains = []
            for rule in data['payload']:
                self.stats['total'] += 1
                # 直接提取域名（假设type和policy已合规）
                domain = rule.get('value', '').strip().lower()
                if not domain:
                    self.stats['invalid'] += 1
                    continue

                # 仅做DNS格式验证（输入已去重，无需去重逻辑）
                if DNSValidator.is_valid_domain(domain):
                    valid_domains.append(domain)
                    self.stats['valid'] += 1
                else:
                    self.stats['invalid'] += 1

            logger.info(f"解析完成: 总规则{self.stats['total']}，有效{self.stats['valid']}，无效{self.stats['invalid']}")
            return valid_domains

        except Exception as e:
            logger.error(f"解析失败: {str(e)}")
            return []

    def generate_compile_yaml(self, domains: List[str]) -> str:
        """生成编译用YAML（保持Clash规范格式）"""
        sorted_domains = sorted(domains)  # 仅排序，无需去重
        yaml_lines = ["payload:"] + [f"  - type: DOMAIN-SUFFIX\n    value: {d}" for d in sorted_domains]
        return '\n'.join(yaml_lines)

    def compile_to_mrs(self, yaml_content: str) -> bool:
        """编译为MRS格式"""
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
                f.write(yaml_content)
                temp_file = f.name

            result = subprocess.run(
                [str(self.config.compiler_abs_path), "convert-ruleset", "domain", "mrs", temp_file, str(self.config.output_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, text=True
            )

            if result.returncode != 0:
                logger.error(f"编译失败: {result.stderr[:500]}...")
                return False

            if not self.config.output_path.exists() or self.config.output_path.stat().st_size == 0:
                logger.error("输出文件为空")
                return False

            logger.info(f"MRS生成成功: {self.config.output_path}（{self.config.output_path.stat().st_size/1024:.1f}KB）")
            return True

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
        """执行流程"""
        domains = self.parse_input()
        if not domains:
            logger.error("无有效域名可处理")
            return 1

        yaml_content = self.generate_compile_yaml(domains)
        if not self.compile_to_mrs(yaml_content):
            return 1

        # 输出GitHub变量
        print(f"::set-output name=mrs_path::{self.config.output_path}")
        print(f"::set-output name=rule_count::{self.stats['valid']}")

        logger.info("流程完成")
        return 0


def main():
    try:
        return AdblockConverter(Config()).run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
