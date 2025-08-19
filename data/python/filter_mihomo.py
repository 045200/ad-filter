#!/usr/bin/env python3
"""
AdBlock + Hosts 规则转换器
输入: adblock_clash.yaml (Clash规则文件)
输出: adb.mrs
使用 GitHub 工作空间根目录作为基准路径
"""

import os
import re
import sys
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import List, Set, Tuple
import tempfile
import subprocess
import idna
import yaml

# 配置 - 使用环境变量设置路径
GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")  # 输入文件
OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")           # 输出文件
COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool") # 编译器路径
MAX_DOMAIN_LENGTH = 253  # RFC 1035 限制
MAX_LABEL_LENGTH = 63    # RFC 1035 限制

class Logger:
    @staticmethod
    def info(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: {msg}")
    @staticmethod
    def error(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {msg}", file=sys.stderr)
    @staticmethod
    def warning(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] WARNING: {msg}")

class DNSValidator:
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """验证域名是否符合 DNS 标准"""
        if not domain or len(domain) > MAX_DOMAIN_LENGTH:
            return False

        # 排除 IP 地址
        try:
            ipaddress.ip_address(domain)
            return False
        except ValueError:
            pass

        # 验证域名结构
        labels = domain.split('.')
        if len(labels) < 2:
            return False

        for label in labels:
            if not label or len(label) > MAX_LABEL_LENGTH:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
            if not re.match(r'^[a-z0-9-]+$', label):
                return False

        # 验证国际化域名（IDNA）
        try:
            idna.encode(domain)
        except idna.IDNAError:
            return False

        return True

class RuleParser:
    def __init__(self):
        self.seen_domains: Set[str] = set()
        self.stats = {
            'total': 0,            # 总规则数
            'valid': 0,            # 有效域名数
            'invalid_dns': 0,      # DNS 无效
            'duplicates': 0,       # 重复域名
            'clash_rules': 0       # Clash 规则数
        }

    def parse_clash_file(self, input_file: Path) -> List[Tuple[str, str]]:
        """解析 Clash YAML 文件，提取有效域名"""
        Logger.info(f"解析 Clash 规则文件 {input_file}...")
        all_rules = []
        
        if not input_file.exists():
            Logger.error(f"输入文件 {input_file} 不存在")
            return all_rules
        
        try:
            with input_file.open('r', encoding='utf-8') as f:
                clash_data = yaml.safe_load(f)
            
            if 'payload' not in clash_data:
                Logger.error("Clash 文件格式错误：缺少 'payload' 部分")
                return all_rules
                
            for rule in clash_data['payload']:
                self.stats['total'] += 1
                self.stats['clash_rules'] += 1
                
                # 只处理 DOMAIN-SUFFIX 类型规则
                if rule.get('type') != 'DOMAIN-SUFFIX':
                    continue
                    
                domain = rule.get('value', '').strip().lower()
                policy = rule.get('policy', '').upper()
                
                # 只处理 REJECT 策略的规则（黑名单）
                if policy != 'REJECT':
                    continue
                    
                # 验证 DNS 并去重
                if not DNSValidator.is_valid_domain(domain):
                    self.stats['invalid_dns'] += 1
                    continue
                    
                if domain in self.seen_domains:
                    self.stats['duplicates'] += 1
                    continue
                    
                self.seen_domains.add(domain)
                self.stats['valid'] += 1
                all_rules.append((domain, f"'{domain}'"))
                
            return all_rules
        except Exception as e:
            Logger.error(f"解析 Clash 文件失败: {str(e)}")
            return all_rules

    def generate_antiad_yaml(self, rules: List[str]) -> str:
        """生成 YAML 规则集"""
        rules_sorted = sorted(set(rules))
        yaml = [
            "#Title: AD-Filter",
            f"#Update time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC+8",
            "",
            "payload:"
        ]
        yaml.extend(f"  - {rule}" for rule in rules_sorted)
        return '\n'.join(yaml)

    def compile_rules(self, yaml_content: str, output_path: Path) -> bool:
        """编译为 MRS 格式"""
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(yaml_content)
                temp_path = f.name

            result = subprocess.run(
                [COMPILER_PATH, "convert-ruleset", "domain", "mrs", temp_path, str(output_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False
            )

            if result.returncode != 0:
                error = result.stderr.decode('utf-8', errors='replace')
                Logger.error(f"编译失败：{error[:500]}...")
                return False

            if not output_path.exists() or output_path.stat().st_size == 0:
                Logger.error("输出文件为空")
                return False

            return True
        except Exception as e:
            Logger.error(f"编译异常：{str(e)}")
            return False
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    Logger.error(f"临时文件删除失败：{str(e)}")

def main():
    # 设置工作空间路径
    workspace = Path(GITHUB_WORKSPACE)
    input_path = workspace / INPUT_FILE
    output_path = workspace / OUTPUT_FILE
    
    # 编译器路径处理
    compiler_path = COMPILER_PATH
    if not os.path.isabs(COMPILER_PATH):
        compiler_path = workspace / COMPILER_PATH

    # 创建规则解析器
    parser = RuleParser()

    # 解析 Clash 规则文件
    all_rules = parser.parse_clash_file(input_path)

    # 生成 YAML 并编译
    yaml_content = parser.generate_antiad_yaml([rule for (domain, rule) in all_rules])
    Logger.info(f"从 {parser.stats['total']} 条规则中提取 {len(all_rules)} 个有效域名")

    Logger.info("编译为 MRS 格式...")
    if parser.compile_rules(yaml_content, output_path):
        file_size = output_path.stat().st_size / 1024
        Logger.info(f"✅ 成功生成：{output_path}（{file_size:.1f} KB）")

    # 输出统计
    Logger.info("\n=== 转换统计 ===")
    stats = [
        ("总规则数", parser.stats['total']),
        ("有效域名数", parser.stats['valid']),
        ("DNS 无效", parser.stats['invalid_dns']),
        ("重复域名", parser.stats['duplicates'])
    ]

    for name, value in stats:
        Logger.info(f"{name:<12}: {value}")

    if parser.stats['valid'] == 0:
        Logger.warning("未生成有效规则！")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
