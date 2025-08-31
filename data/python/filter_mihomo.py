#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mihomo规则转换工具 - GitHub Actions优化版
支持AdGuard Home语法，输出Clash/Mihomo兼容规则
专为GitHub Actions环境设计，修复了转换逻辑中的常见问题
"""

import os
import re
import sys
import subprocess
import hashlib
from typing import List, Set, Dict, Any, Tuple, Optional

# ==============================================================================
# 配置类 - 使用环境变量
# ==============================================================================
class Config:
    """配置管理器，使用环境变量"""
    
    def __init__(self):
        # 基础路径配置
        self.base_dir = os.getenv("GITHUB_WORKSPACE", os.getcwd())
        
        # 功能开关
        self.enable_whitelist = os.getenv("ENABLE_WHITELIST", "true").lower() == "false"
        
        # 输入输出路径
        self.input_blacklist = os.getenv("INPUT_BLACKLIST", os.path.join(self.base_dir, "adblock_adh.txt"))
        self.input_whitelist = os.getenv("INPUT_WHITELIST", os.path.join(self.base_dir, "allow_adh.txt"))
        self.output_mihomo = os.getenv("OUTPUT_MIHOMO", os.path.join(self.base_dir, "adb.mrs"))
        self.temp_clash = os.path.join(self.base_dir, "temp_clash.yaml")
        
        # 工具路径
        self.mihomo_tool = os.getenv("MIHOMO_TOOL_PATH", os.path.join(self.base_dir, "data/mihomo-tool"))
        
        # AdGuard规则类型映射
        self.ag_rule_types = {
            'domain': r'^\|\|([^\^]+)\^',
            'exact': r'^\|([^\^]+)\^',
            'regex': r'^/(.+)/$',
            'element': r'^##',
            'exception': r'^@@'
        }
    
    def validate_paths(self) -> bool:
        """验证必要的路径是否存在"""
        errors = []
        
        # 检查黑名单文件
        if not os.path.exists(self.input_blacklist):
            errors.append(f"黑名单文件不存在: {self.input_blacklist}")
        
        # 检查白名单文件（如果启用白名单过滤）
        if self.enable_whitelist and not os.path.exists(self.input_whitelist):
            errors.append(f"白名单文件不存在: {self.input_whitelist}")
        
        # 检查mihomo-tool
        if not os.path.exists(self.mihomo_tool):
            errors.append(f"Mihomo工具不存在: {self.mihomo_tool}")
        
        if errors:
            for error in errors:
                print(f"::error::{error}")
            return False
        
        return True


# ==============================================================================
# AdGuard Home规则处理 - 改进版
# ==============================================================================
class AdGuardRuleParser:
    """AdGuard规则解析器 - 改进版"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def parse_rule(self, rule: str) -> Dict[str, Any]:
        """解析AdGuard Home规则，返回规则类型和内容 - 改进版"""
        rule = rule.strip()
        result = {'original': rule, 'type': 'unknown', 'content': '', 'is_exception': False}

        # 跳过注释和空行
        if not rule or rule.startswith('!') or rule.startswith('#'):
            result['type'] = 'comment'
            return result

        # 检查是否为例外规则
        if rule.startswith('@@'):
            result['is_exception'] = True
            rule = rule[2:]  # 移除@@前缀

        # 检查规则类型
        for rule_type, pattern in self.config.ag_rule_types.items():
            if re.match(pattern, rule):
                result['type'] = rule_type
                break

        # 提取规则内容
        if result['type'] == 'domain':
            match = re.match(self.config.ag_rule_types['domain'], rule)
            if match:
                result['content'] = match.group(1)
        elif result['type'] == 'exact':
            match = re.match(self.config.ag_rule_types['exact'], rule)
            if match:
                result['content'] = match.group(1)
        elif result['type'] == 'exception':
            # 处理例外规则(@@)
            result['content'] = rule[2:]
        else:
            result['content'] = rule

        return result

    def extract_rules_from_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """从AdGuard Home规则文件中提取规则 - 改进版"""
        rules = []
        rule_stats = {'total': 0, 'domain_rules': 0, 'exact_rules': 0, 'exception_rules': 0, 'other_rules': 0}

        if not os.path.exists(file_path):
            print(f"::warning::文件不存在: {file_path}")
            return rules, rule_stats

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    rule_stats['total'] += 1
                    parsed = self.parse_rule(line)

                    if parsed['type'] == 'comment':
                        continue
                    
                    # 统计规则类型
                    if parsed['type'] == 'domain':
                        rule_stats['domain_rules'] += 1
                    elif parsed['type'] == 'exact':
                        rule_stats['exact_rules'] += 1
                    elif parsed['is_exception']:
                        rule_stats['exception_rules'] += 1
                    else:
                        rule_stats['other_rules'] += 1
                    
                    rules.append(parsed)
                    
                    # 每处理1000行输出一次进度
                    if line_num % 1000 == 0:
                        print(f"::notice::已处理 {line_num} 行规则...")

        except Exception as e:
            print(f"::error::读取文件时出错 {file_path}: {e}")

        return rules, rule_stats


# ==============================================================================
# 域名处理和过滤 - 改进版
# ==============================================================================
class DomainProcessor:
    """域名处理器 - 改进版"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def is_valid_domain(self, domain: str) -> bool:
        """验证域名是否合法 - 改进版"""
        if not domain or domain.strip() == "":
            return False

        domain = domain.strip()

        # 排除纯IP地址
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
            return False

        # 基本域名格式检查
        if not re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z0-9.*-]+$', domain):
            return False

        # 检查通配符位置
        if domain.startswith('*') and not domain.startswith('*.'):
            return False

        return True

    def filter_rules(self, black_rules: List[Dict[str, Any]], white_domains: Set[str]) -> List[Dict[str, Any]]:
        """使用白名单过滤黑名单规则 - 改进版"""
        if not self.config.enable_whitelist:
            return black_rules
            
        filtered_rules = []

        for rule in black_rules:
            # 例外规则不过滤
            if rule.get('is_exception', False):
                filtered_rules.append(rule)
                continue
                
            domain = rule.get('content', '')
            
            # 检查是否在白名单中
            if domain in white_domains:
                print(f"::debug::过滤规则 (精确匹配): {domain}")
                continue

            # 检查是否是白名单域名的子域名
            whitelisted = False
            for white_domain in white_domains:
                if (domain == white_domain or 
                    domain.endswith('.' + white_domain)):
                    whitelisted = True
                    print(f"::debug::过滤规则 (子域名匹配): {domain} (白名单: {white_domain})")
                    break

            if not whitelisted:
                filtered_rules.append(rule)

        return filtered_rules


# ==============================================================================
# Clash/Mihomo规则生成 - 改进版
# ==============================================================================
class RuleConverter:
    """规则转换器 - 改进版"""
    
    @staticmethod
    def convert_to_clash_rules(rules: List[Dict[str, Any]]) -> List[str]:
        """将规则列表转换为Clash规则 - 改进版"""
        clash_rules = []

        for rule in rules:
            domain = rule.get('content', '')
            rule_type = rule.get('type', '')
            is_exception = rule.get('is_exception', False)
            
            # 跳过无效域名
            if not domain or domain.strip() == "":
                continue
                
            # 确定规则动作
            action = "DIRECT" if is_exception else "REJECT"
            
            # 根据规则类型生成对应的Clash规则
            if rule_type == 'domain':
                if domain.startswith('*.'):
                    # 通配符域名 -> DOMAIN-SUFFIX规则
                    base_domain = domain[2:]
                    clash_rules.append(f"DOMAIN-SUFFIX,{base_domain},{action}")
                else:
                    # 普通域名 -> DOMAIN-SUFFIX规则（匹配域名及其子域）
                    clash_rules.append(f"DOMAIN-SUFFIX,{domain},{action}")
            elif rule_type == 'exact':
                # 精确匹配 -> DOMAIN规则
                clash_rules.append(f"DOMAIN,{domain},{action}")
            else:
                # 其他规则类型，尝试转换为DOMAIN-SUFFIX
                clash_rules.append(f"DOMAIN-SUFFIX,{domain},{action}")

        return clash_rules

    @staticmethod
    def create_clash_yaml(rules: List[str], output_path: str) -> None:
        """创建Clash格式的YAML文件 - 改进版"""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("payload:\n")
                for rule in rules:
                    f.write(f"  - {rule}\n")
            print(f"::notice::Clash临时文件创建成功: {output_path}")
        except Exception as e:
            print(f"::error::创建Clash临时文件失败: {e}")
            raise


# ==============================================================================
# Mihomo编译 - 改进版
# ==============================================================================
class MihomoCompiler:
    """Mihomo编译器 - 改进版"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def compile(self, clash_yaml_path: str, output_path: str) -> bool:
        """使用mihomo-tool编译规则集 - 改进版"""
        if not os.path.exists(self.config.mihomo_tool):
            print(f"::error::Mihomo工具不存在: {self.config.mihomo_tool}")
            return False

        cmd = [
            self.config.mihomo_tool,
            "convert-ruleset",
            "domain",
            "yaml",
            clash_yaml_path,
            output_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                print("::notice::Mihomo编译成功")
                return True
            else:
                print(f"::error::Mihomo编译失败: {result.stderr}")
                return False
        except subprocess.CalledProcessError as e:
            print(f"::error::Mihomo编译异常: {e.stderr if e.stderr else e}")
            return False
        except Exception as e:
            print(f"::error::Mihomo执行异常: {e}")
            return False


# ==============================================================================
# 文件验证工具
# ==============================================================================
class FileValidator:
    """文件验证工具类"""
    
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """计算文件的SHA256哈希值"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # 分块读取文件以处理大文件
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"::error::计算SHA256时出错: {e}")
            return ""

    @staticmethod
    def validate_file(file_path: str) -> Dict[str, Any]:
        """验证文件并返回详细信息"""
        result = {
            "exists": False,
            "size": 0,
            "sha256": "",
            "is_valid": False
        }
        
        if not os.path.exists(file_path):
            return result
            
        result["exists"] = True
        result["size"] = os.path.getsize(file_path)
        result["sha256"] = FileValidator.calculate_sha256(file_path)
        result["is_valid"] = result["size"] > 0 and result["sha256"] != ""
        
        return result


# ==============================================================================
# 主流程 - 改进版
# ==============================================================================
def main():
    """主函数 - 改进版"""
    # 初始化配置
    config = Config()
    
    # 输出配置信息
    print("::notice::在GitHub Actions环境中运行Mihomo规则转换")
    print(f"::notice::白名单过滤: {'启用' if config.enable_whitelist else '禁用'}")

    # 验证路径
    if not config.validate_paths():
        sys.exit(1)

    print("::notice::开始处理规则文件...")

    # 初始化组件
    rule_parser = AdGuardRuleParser(config)
    domain_processor = DomainProcessor(config)
    mihomo_compiler = MihomoCompiler(config)

    # 步骤1：提取规则
    print("::notice::【1/4】提取AdGuard Home规则...")
    black_rules, black_stats = rule_parser.extract_rules_from_file(config.input_blacklist)
    
    white_domains = set()
    white_stats = {'total': 0, 'domain_rules': 0, 'other_rules': 0}
    
    if config.enable_whitelist:
        white_rules, white_stats = rule_parser.extract_rules_from_file(config.input_whitelist)
        # 提取白名单域名
        for rule in white_rules:
            if rule.get('content') and not rule.get('is_exception', False):
                white_domains.add(rule['content'])

    print(f"::notice::📊 提取统计:")
    print(f"::notice::  黑名单: {len(black_rules)} 条规则 (共 {black_stats['total']} 行)")
    print(f"::notice::    域名规则: {black_stats['domain_rules']}")
    print(f"::notice::    精确规则: {black_stats['exact_rules']}")
    print(f"::notice::    例外规则: {black_stats['exception_rules']}")
    print(f"::notice::    其他规则: {black_stats['other_rules']}")
    
    if config.enable_whitelist:
        print(f"::notice::  白名单: {len(white_domains)} 个域名 (共 {white_stats['total']} 条规则)")

    # 步骤2：过滤黑名单
    print("::notice::【2/4】过滤黑名单规则...")
    filtered_rules = domain_processor.filter_rules(black_rules, white_domains)

    filtered_count = len(black_rules) - len(filtered_rules)
    print(f"::notice::📊 过滤统计:")
    print(f"::notice::  过滤前: {len(black_rules)} 条规则")
    print(f"::notice::  过滤后: {len(filtered_rules)} 条规则")
    if config.enable_whitelist:
        print(f"::notice::  过滤掉: {filtered_count} 条规则")

    # 步骤3：转换为Clash规则并创建临时文件
    print("::notice::【3/4】转换为Clash规则并创建临时文件...")
    clash_rules = RuleConverter.convert_to_clash_rules(filtered_rules)
    RuleConverter.create_clash_yaml(clash_rules, config.temp_clash)

    # 步骤4：编译Mihomo规则集
    print("::notice::【4/4】编译Mihomo规则集...")
    if mihomo_compiler.compile(config.temp_clash, config.output_mihomo):
        mrs_size = os.path.getsize(config.output_mihomo) / 1024 if os.path.exists(config.output_mihomo) else 0
        print(f"::notice::Mihomo规则集生成成功: {config.output_mihomo} ({mrs_size:.2f} KB)")
        
        # 验证规则集有效性
        if mrs_size > 0:
            print("::notice::规则集验证: 生成成功，文件大小正常")
        else:
            print("::warning::规则集验证: 文件大小异常，可能生成失败")
    else:
        print("::error::Mihomo规则集生成失败")
        sys.exit(1)

    # 步骤5：验证生成的文件
    print("::notice::【5/5】验证生成的文件...")
    file_validator = FileValidator()
    validation_result = file_validator.validate_file(config.output_mihomo)
    
    if validation_result["is_valid"]:
        print(f"::notice::✅ 文件验证成功:")
        print(f"::notice::  文件大小: {validation_result['size']} 字节")
        print(f"::notice::  SHA256: {validation_result['sha256']}")
        
        # 设置GitHub Actions输出变量
        if os.getenv("GITHUB_OUTPUT"):
            with open(os.getenv("GITHUB_OUTPUT"), "a") as f:
                f.write(f"mrs_file={config.output_mihomo}\n")
                f.write(f"mrs_size={validation_result['size']}\n")
                f.write(f"mrs_sha256={validation_result['sha256']}\n")
    else:
        print("::error::❌ 文件验证失败")
        sys.exit(1)

    # 清理临时文件
    if os.path.exists(config.temp_clash):
        os.remove(config.temp_clash)
        print(f"::notice::已清理临时文件: {config.temp_clash}")

    print("::notice::🎉 Mihomo转换任务完成！")


if __name__ == "__main__":
    main()