#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则转换器（增强版，含白名单过滤）
输入: 步骤一生成的 Clash 拦截规则(clash_adblock.yaml)和放行规则(clash_allow.yaml)（位于仓库根目录）
输出: 经过白名单过滤的 adb.mrs（位于仓库根目录）
适配GitHub Actions环境，支持规则过滤与错误处理
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
from typing import List, Dict, Set


class Config:
    """配置管理（输入输出均在仓库根目录）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    # 输入文件（位于仓库根目录）
    INPUT_BLOCK_FILE = os.getenv("BLOCK_INPUT", "clash_adblock.yaml")
    INPUT_WHITELIST_FILE = os.getenv("WHITELIST_INPUT", "clash_allow.yaml")
    # 输出文件（位于仓库根目录）
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
    def block_path(self) -> Path:
        """步骤一生成的拦截规则文件路径（仓库根目录）"""
        path = Path(self.GITHUB_WORKSPACE) / self.INPUT_BLOCK_FILE
        if not path.exists():
            logger.critical(f"拦截规则文件不存在（步骤一生成失败？）: {path}")
            sys.exit(1)
        return path

    @property
    def whitelist_path(self) -> Path:
        """步骤一生成的白名单（放行规则）文件路径（仓库根目录）"""
        return Path(self.GITHUB_WORKSPACE) / self.INPUT_WHITELIST_FILE

    @property
    def output_path(self) -> Path:
        """输出文件路径（仓库根目录）"""
        return Path(self.GITHUB_WORKSPACE) / self.OUTPUT_FILE

    @property
    def compiler_abs_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.COMPILER_PATH if not os.path.isabs(self.COMPILER_PATH) else Path(self.COMPILER_PATH)


class DNSValidator:
    """DNS格式验证工具"""
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        domain = domain.strip().lower()
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
    logger = logging.getLogger("AdblockConverterWithWhitelist")
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
    """规则转换器（含白名单过滤逻辑）"""
    def __init__(self, config: Config):
        self.config = config
        self.stats = {
            'total_block': 0,    # 步骤一拦截规则总数
            'valid_block': 0,    # 有效拦截规则数
            'whitelist_count': 0,  # 白名单域名数量
            'filtered_count': 0   # 被白名单过滤的规则数
        }
        self.whitelist_domains: Set[str] = set()  # 白名单域名集合

    def parse_input(self) -> List[Dict[str, str]]:
        """解析步骤一生成的拦截规则文件（仓库根目录）"""
        logger.info(f"解析拦截规则文件: {self.config.block_path}")
        try:
            with self.config.block_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not data or 'payload' not in data:
                logger.error("拦截规则文件缺少'payload'节点（步骤一格式错误）")
                return []

            valid_rules: List[Dict[str, str]] = []
            seen = set()  # 去重标记

            for rule in data['payload']:
                self.stats['total_block'] += 1
                if not isinstance(rule, dict):
                    continue  # 跳过无效格式

                rule_type = rule.get('type', '').upper()
                domain = rule.get('value', '').strip().lower()

                # 校验规则类型和域名格式
                if rule_type not in self.config.SUPPORTED_TYPES:
                    continue
                if not DNSValidator.is_valid_domain(domain):
                    continue

                # 去重
                rule_key = (rule_type, domain)
                if rule_key in seen:
                    continue
                seen.add(rule_key)
                valid_rules.append({'type': rule_type, 'value': domain})
                self.stats['valid_block'] += 1

            logger.info(
                f"拦截规则解析完成: 总规则{self.stats['total_block']}, "
                f"有效{self.stats['valid_block']}"
            )
            return valid_rules
        except yaml.YAMLError as e:
            logger.error(f"拦截规则YAML格式错误: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"解析拦截规则失败: {str(e)}")
            return []

    def _load_whitelist(self) -> None:
        """加载步骤一生成的白名单（放行规则，仓库根目录）"""
        if not self.config.whitelist_path.exists():
            logger.warning("白名单文件不存在，将跳过过滤")
            return
        try:
            with self.config.whitelist_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not data or 'payload' not in data:
                logger.warning("白名单文件缺少'payload'节点（步骤一格式错误）")
                return

            # 提取所有白名单域名（忽略类型，仅保留值）
            for rule in data['payload']:
                if isinstance(rule, dict) and 'value' in rule:
                    domain = rule['value'].strip().lower()
                    if DNSValidator.is_valid_domain(domain):
                        self.whitelist_domains.add(domain)
            self.stats['whitelist_count'] = len(self.whitelist_domains)
            logger.info(f"白名单加载完成: 有效域名 {self.stats['whitelist_count']} 个")
        except yaml.YAMLError as e:
            logger.error(f"白名单YAML格式错误: {str(e)}")
        except Exception as e:
            logger.error(f"加载白名单失败: {str(e)}")

    def _filter_with_whitelist(self, rules: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """用白名单过滤拦截规则"""
        if not self.whitelist_domains:
            return rules  # 无白名单时直接返回原规则
        filtered_rules = []
        for rule in rules:
            domain = rule['value']
            if domain in self.whitelist_domains:
                self.stats['filtered_count'] += 1
            else:
                filtered_rules.append(rule)
        logger.info(
            f"白名单过滤完成: 过滤前{len(rules)}条, 过滤后{len(filtered_rules)}条, "
            f"被过滤{self.stats['filtered_count']}条"
        )
        return filtered_rules

    def generate_compile_yaml(self, rules: List[Dict[str, str]]) -> str:
        """生成用于编译的YAML内容"""
        if not rules:
            return ""
        sorted_rules = sorted(rules, key=lambda x: x['value'])
        yaml_lines = ["payload:"]
        for rule in sorted_rules:
            yaml_lines.append(f"  - type: {rule['type']}")
            yaml_lines.append(f"    value: {rule['value']}")
        logger.info(f"生成编译用YAML: 包含{len(sorted_rules)}条规则")
        return '\n'.join(yaml_lines)

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
                    "mrs",
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
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception as e:
                    logger.warning(f"临时文件清理失败: {str(e)}")

    def run(self) -> int:
        """执行完整流程：解析拦截规则 → 加载白名单 → 过滤 → 编译"""
        # 1. 解析步骤一的拦截规则（仓库根目录）
        valid_block_rules = self.parse_input()
        if not valid_block_rules:
            logger.error("无有效拦截规则，终止流程")
            return 1

        # 2. 加载白名单并过滤
        self._load_whitelist()
        final_rules = self._filter_with_whitelist(valid_block_rules)

        # 3. 生成编译内容并编译（输出到仓库根目录）
        yaml_content = self.generate_compile_yaml(final_rules)
        if not self.compile_to_mrs(yaml_content):
            return 1

        # 输出GitHub Action变量（使用环境文件）
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"mrs_path={self.config.output_path}\n")
                f.write(f"final_rule_count={len(final_rules)}\n")
                f.write(f"filtered_count={self.stats['filtered_count']}\n")
        else:
            logger.warning("未检测到GITHUB_OUTPUT环境变量，跳过变量输出")

        logger.info("步骤二转换流程完成")
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
