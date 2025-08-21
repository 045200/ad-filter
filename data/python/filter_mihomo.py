#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则转换器（增强版，含白名单过滤）
输入: 包含拦截规则和白名单规则的 adblock_clash.yaml（位于仓库根目录）
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
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple


class Config:
    """配置管理（输入输出均在仓库根目录）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    # 输入文件（位于仓库根目录）
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    # 输出文件（位于仓库根目录）
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    MAX_DOMAIN_LENGTH = 253  # RFC 1035 限制
    MAX_LABEL_LENGTH = 63    # RFC 1035 限制
    SUPPORTED_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR'}  # 支持的规则类型

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
            'total_block': 0,    # 拦截规则总数
            'valid_block': 0,    # 有效拦截规则数
            'whitelist_count': 0,  # 白名单域名数量
            'filtered_count': 0,   # 被白名单过滤的规则数
            'mrs_sha256': ''      # MRS文件的SHA256校验和
        }
        self.whitelist_domains: Set[str] = set()  # 白名单域名集合

    def parse_rule_string(self, rule_str: str) -> Tuple[str, str]:
        """解析规则字符串，返回(类型, 值)"""
        # 处理字符串格式的规则，如 'DOMAIN-SUFFIX,example.com'
        if ',' in rule_str:
            parts = rule_str.split(',', 1)
            rule_type = parts[0].strip().upper()
            value = parts[1].strip()
            return rule_type, value
        return "", ""

    def parse_input(self) -> List[Dict[str, str]]:
        """解析输入文件，提取拦截规则和白名单规则"""
        logger.info(f"解析输入文件: {self.config.input_path}")
        try:
            with self.config.input_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'payload' not in data:
                logger.error("输入文件缺少'payload'节点")
                return []

            valid_rules: List[Dict[str, str]] = []
            seen = set()  # 去重标记

            for rule in data['payload']:
                self.stats['total_block'] += 1
                
                rule_type = ""
                value = ""
                
                # 处理不同类型的规则格式
                if isinstance(rule, dict):
                    # 字典格式的规则: {'type': 'DOMAIN-SUFFIX', 'value': 'example.com'}
                    rule_type = rule.get('type', '').upper()
                    value = rule.get('value', '').strip().lower()
                elif isinstance(rule, str):
                    # 字符串格式的规则: 'DOMAIN-SUFFIX,example.com'
                    rule_type, value = self.parse_rule_string(rule)
                
                # 跳过无效规则
                if not rule_type or not value:
                    continue
                    
                # 校验规则类型和值格式
                if rule_type not in self.config.SUPPORTED_TYPES:
                    continue
                    
                # 特殊处理IP-CIDR规则
                if rule_type == 'IP-CIDR':
                    # 验证IP地址格式
                    try:
                        ipaddress.ip_network(value, strict=False)
                    except ValueError:
                        continue
                else:
                    # 验证域名格式
                    if not DNSValidator.is_valid_domain(value):
                        continue

                # 去重
                rule_key = (rule_type, value)
                if rule_key in seen:
                    continue
                seen.add(rule_key)
                
                valid_rules.append({'type': rule_type, 'value': value})
                self.stats['valid_block'] += 1

            logger.info(
                f"规则解析完成: 总规则{self.stats['total_block']}, "
                f"有效{self.stats['valid_block']}"
            )
            return valid_rules
        except yaml.YAMLError as e:
            logger.error(f"输入文件YAML格式错误: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"解析输入文件失败: {str(e)}")
            return []

    def _load_whitelist(self) -> None:
        """从输入文件中提取白名单规则"""
        try:
            with self.config.input_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'payload' not in data:
                logger.warning("输入文件缺少'payload'节点")
                return

            # 提取所有白名单域名（DOMAIN类型的规则视为白名单）
            for rule in data['payload']:
                rule_type = ""
                value = ""
                
                if isinstance(rule, dict):
                    rule_type = rule.get('type', '').upper()
                    value = rule.get('value', '').strip().lower()
                elif isinstance(rule, str):
                    rule_type, value = self.parse_rule_string(rule)
                
                # 只处理DOMAIN类型的规则作为白名单
                if rule_type == 'DOMAIN' and DNSValidator.is_valid_domain(value):
                    self.whitelist_domains.add(value)
                    
            self.stats['whitelist_count'] = len(self.whitelist_domains)
            logger.info(f"白名单加载完成: 有效域名 {self.stats['whitelist_count']} 个")
        except yaml.YAMLError as e:
            logger.error(f"输入文件YAML格式错误: {str(e)}")
        except Exception as e:
            logger.error(f"加载白名单失败: {str(e)}")

    def _filter_with_whitelist(self, rules: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """用白名单过滤拦截规则"""
        if not self.whitelist_domains:
            return rules  # 无白名单时直接返回原规则
            
        filtered_rules = []
        for rule in rules:
            # 只对域名相关规则进行白名单过滤
            if rule['type'] in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD']:
                domain = rule['value']
                # 检查是否在白名单中
                if domain in self.whitelist_domains:
                    self.stats['filtered_count'] += 1
                    continue
                    
                # 检查是否匹配白名单中的任何域名后缀
                for whitelist_domain in self.whitelist_domains:
                    if domain.endswith('.' + whitelist_domain) or domain == whitelist_domain:
                        self.stats['filtered_count'] += 1
                        break
                else:
                    filtered_rules.append(rule)
            else:
                # 非域名规则直接保留
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
        """执行完整流程：解析输入文件 → 提取白名单 → 过滤 → 编译"""
        # 1. 解析输入文件（仓库根目录）
        valid_block_rules = self.parse_input()
        if not valid_block_rules:
            logger.error("无有效拦截规则，终止流程")
            return 1

        # 2. 提取白名单并过滤
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
                f.write(f"mrs_sha256={self.stats['mrs_sha256']}\n")
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