#!/usr/bin/env python3
import os
import re
import json
import sys
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Pattern, Tuple, Any
from dataclasses import dataclass, field
import logging
from pybloom_live import ScalableBloomFilter
from datetime import datetime
from collections import defaultdict


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@dataclass
class ConvertConfig:
    BASE_DIR: Path = Path(os.getenv("RULE_CONVERT_BASE", Path.cwd()))
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"
    OUTPUT_DIR: Path = BASE_DIR
    SYNTAX_DB: Path = BASE_DIR / "data" / "python" / "syntax_db.json"
    MIHOMO_BIN: Path = BASE_DIR / "data" / "mihomo-tool"

    # 输出配置
    OUTPUT_CLASH_BLOCK: str = "adblock_clash.yaml"
    OUTPUT_CLASH_ALLOW: str = "allow_clash.yaml"
    OUTPUT_MIHOMO: str = "adb.mrs"
    OUTPUT_ADBLOCK_PLUS_BLOCK: str = "adblock_abp.txt"
    OUTPUT_ADBLOCK_PLUS_ALLOW: str = "allow_abp.txt"
    OUTPUT_UBO_BLOCK: str = "adblock_ubo.txt"
    OUTPUT_UBO_ALLOW: str = "allow_ubo.txt"
    OUTPUT_PIHOLE: str = "adblock_pihole.list"
    OUTPUT_HOSTS: str = "hosts.txt"
    OUTPUT_SURGE_BLOCK: str = "adblock_surge.yaml"
    OUTPUT_SURGE_ALLOW: str = "allow_surge.yaml"

    # Hosts配置
    HOSTS_BLOCK_IP: str = "0.0.0.0"
    HOSTS_ALLOW_IP: str = "127.0.0.1"

    # 支持的AdGuard语法类型
    ADGUARD_SYNTAX: Set[str] = field(default_factory=lambda: {
        # 基础语法
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", 
        "adblock_basic_element_hiding", "adblock_basic_element_hiding_exception",
        "adblock_basic_url_rule", "adblock_basic_wildcard_domain",
        
        # AdGuard扩展语法
        "adguard_scriptlet", "adguard_dns_rewrite", "adguard_removeparam", 
        "adguard_redirect", "adguard_redirect_rule", "adguard_referrerpolicy",
        "adguard_removeheader", "adguard_csp", "adguard_stealth_rule", 
        "adguard_cookie_rule", "adguard_extended_css", "adguard_replace",
        "adguard_header", "adguard_jsonprune",
        
        # 正则和高级语法
        "regex_rule", "adblock_basic_regex_rule",
        
        # 其他格式
        "hosts_rule", "pihole_domain", "pihole_regex"
    })
    
    # 可转换的语法类型（DNS层面有效）
    CONVERTIBLE_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", 
        "hosts_rule", "adguard_home_dns_rewrite", "pihole_domain",
        "regex_rule", "adblock_basic_regex_rule", "pihole_regex"
    })

    # DNS层面无效的语法类型
    DNS_INVALID_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_element_hiding", "adblock_basic_element_hiding_exception",
        "adguard_scriptlet", "adguard_extended_css", "adblock_basic_css_id_selector",
        "adblock_basic_css_class_selector", "adblock_basic_css_attribute_selector",
        "adblock_basic_css_combinator", "adblock_basic_css_pseudo_class",
        "adblock_basic_css_pseudo_element", "adguard_extension_css"
    })

    BATCH_SIZE: int = 1000
    USE_BLOOM: bool = True
    ENABLE_MIHOMO: bool = True


class ComprehensiveSyntaxParser:
    def __init__(self, config: ConvertConfig):
        self.config = config
        self.syntax_db = self._load_db()
        self.compiled_patterns = self._compile_patterns()
        self.bloom = self._init_bloom()
        self.rule_type_cache: Dict[str, str] = {}
        self.domain_cache: Dict[str, str] = {}
        self.modifier_cache: Dict[str, Dict[str, str]] = {}
        self.platform_supported_rules = self._load_platform_supported_rules()
        self.modifier_patterns = self._compile_modifier_patterns()
        
        # 验证规则
        self.validation_results = {
            "valid_rules": 0,
            "invalid_rules": 0,
            "regex_validation_failures": 0,
            "domain_validation_failures": 0,
            "platform_compatibility_issues": 0
        }

    def _load_db(self) -> Dict:
        if not self.config.SYNTAX_DB.exists():
            logger.error(f"语法数据库缺失：{self.config.SYNTAX_DB}")
            sys.exit(1)
        try:
            with open(self.config.SYNTAX_DB, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"数据库加载失败：{str(e)}")
            sys.exit(1)

    def _compile_patterns(self) -> Dict[str, Pattern]:
        compiled = {}
        syntax_patterns = self.syntax_db["syntax_patterns"]
        
        # 基础模式
        base_patterns = [
            "adblock_basic_comment", "aglint_comment", "empty_rule"
        ]
        for pattern in base_patterns:
            if pattern in syntax_patterns:
                compiled[pattern] = re.compile(syntax_patterns[pattern], re.UNICODE)

        # 编译所有语法模式
        for syntax in self.config.ADGUARD_SYNTAX:
            if syntax in syntax_patterns:
                try:
                    flags = re.IGNORECASE | re.UNICODE
                    if syntax.endswith("_regex_rule"):
                        flags |= re.DOTALL
                    compiled[syntax] = re.compile(syntax_patterns[syntax], flags)
                except re.error as e:
                    logger.warning(f"正则编译失败 {syntax}: {e}")

        return compiled

    def _compile_modifier_patterns(self) -> Dict[str, Pattern]:
        modifiers = self.syntax_db.get("modifiers", {})
        compiled = {}
        for key, pattern in modifiers.items():
            try:
                compiled[key] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
        return compiled

    def _init_bloom(self) -> Dict[str, ScalableBloomFilter]:
        if not self.config.USE_BLOOM:
            return {}
        bloom_cfg = self.syntax_db.get("performance_optimization", {}).get("bloom_filter_config", {})
        return {
            "block": ScalableBloomFilter(
                initial_capacity=bloom_cfg.get("initial_capacity", 50000), 
                error_rate=bloom_cfg.get("error_rate", 0.001)
            ),
            "allow": ScalableBloomFilter(
                initial_capacity=bloom_cfg.get("initial_capacity", 10000), 
                error_rate=bloom_cfg.get("error_rate", 0.001)
            )
        }

    def _load_platform_supported_rules(self) -> Dict[str, Set[str]]:
        platform_support = self.syntax_db.get("platform_support", {})
        supported_rules = {}
        
        platform_mapping = {
            "adblock_plus": "adblock_plus",
            "ubo": "ublock_origin", 
            "pihole": "pihole",
            "hosts": "pihole",  # Hosts使用Pi-hole的规则集
            "surge": "surge",
            "clash": "clash_mihomo"
        }
        
        for internal_name, db_name in platform_mapping.items():
            if db_name in platform_support and "supported_rule_types" in platform_support[db_name]:
                supported_rules[internal_name] = set(platform_support[db_name]["supported_rule_types"])
            else:
                supported_rules[internal_name] = set()
                
        return supported_rules

    def get_rule_type(self, rule: str) -> str:
        if not rule or rule.strip() == "":
            return "empty_rule"
            
        if rule in self.rule_type_cache:
            return self.rule_type_cache[rule]

        # 检查注释和空行
        if self.compiled_patterns.get("adblock_basic_comment") and self.compiled_patterns["adblock_basic_comment"].match(rule):
            return "adblock_basic_comment"
        if self.compiled_patterns.get("aglint_comment") and self.compiled_patterns["aglint_comment"].match(rule):
            return "aglint_comment"
        if self.compiled_patterns.get("empty_rule") and self.compiled_patterns["empty_rule"].match(rule):
            return "empty_rule"

        # 检查各种语法规则
        for syntax, pattern in self.compiled_patterns.items():
            if syntax in ["adblock_basic_comment", "aglint_comment", "empty_rule"]:
                continue
            if pattern.match(rule):
                self.rule_type_cache[rule] = syntax
                return syntax

        self.rule_type_cache[rule] = "unknown_rule"
        return "unknown_rule"

    def extract_domain_from_rule(self, rule: str, rule_type: str) -> Optional[str]:
        if rule_type not in self.config.CONVERTIBLE_SYNTAX:
            return None
            
        cache_key = (rule, rule_type)
        if cache_key in self.domain_cache:
            return self.domain_cache[cache_key]

        domain = None
        pattern = self.compiled_patterns.get(rule_type)
        if not pattern:
            return None

        try:
            match = pattern.match(rule)
            if not match:
                return None

            # 基于规则类型提取域名
            if rule_type in ["adblock_basic_domain_rule", "adblock_basic_exception_rule"]:
                domain = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            elif rule_type == "hosts_rule":
                parts = rule.split()
                if len(parts) >= 2:
                    domain = parts[1]
            elif rule_type == "adguard_home_dns_rewrite":
                domain_match = re.search(r'\|\|([^\^$]+)', rule)
                domain = domain_match.group(1) if domain_match else None
            elif rule_type in ["pihole_domain", "regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
                domain = rule  # 对于正则和特殊规则，使用完整规则作为"域名"

            # 域名清洗和规范化
            if domain and not isinstance(domain, str):
                domain = str(domain)
            if domain and not domain.startswith('/'):  # 非正则规则
                domain = self._normalize_domain(domain)

        except Exception as e:
            logger.debug(f"域名提取失败 {rule_type}: {rule} - {e}")
            return None

        self.domain_cache[cache_key] = domain
        return domain

    def _normalize_domain(self, domain: str) -> str:
        """域名规范化"""
        if not domain:
            return domain
            
        domain = domain.lower().strip()
        
        # 移除常见前缀
        domain = re.sub(r'^\|+\*?\.?', '', domain)
        domain = re.sub(r'\^.*$', '', domain)
        domain = re.sub(r'\$.*$', '', domain)
        
        # 移除尾部修饰符
        domain = re.sub(r'[/|^$].*$', '', domain)
        
        # 验证基本域名格式
        if re.match(r'^[a-zA-Z0-9.*-]+$', domain):
            return domain
        return domain

    def extract_modifiers(self, rule: str) -> Dict[str, str]:
        """提取规则修饰符"""
        if rule in self.modifier_cache:
            return self.modifier_cache[rule]
            
        modifiers = {}
        parts = rule.split('$', 1)
        if len(parts) < 2:
            return modifiers
            
        modifier_part = parts[1]
        for modifier_name, pattern in self.modifier_patterns.items():
            match = pattern.search(modifier_part)
            if match:
                if match.lastindex:
                    modifiers[modifier_name] = match.group(1)
                else:
                    modifiers[modifier_name] = "true"
                    
        self.modifier_cache[rule] = modifiers
        return modifiers

    def validate_rule(self, rule: str, rule_type: str) -> Tuple[bool, List[str]]:
        """全面验证规则"""
        issues = []
        
        # 基础验证
        if not rule or len(rule.strip()) == 0:
            issues.append("空规则")
            return False, issues
            
        if len(rule) > self.syntax_db["validation_rules"].get("max_rule_length", 4096):
            issues.append("规则过长")
            return False, issues

        # 特定规则类型验证
        if rule_type in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
            if not self._validate_regex_syntax(rule):
                issues.append("正则语法错误")
                self.validation_results["regex_validation_failures"] += 1
                return False, issues
                
        elif rule_type in self.config.CONVERTIBLE_SYNTAX:
            domain = self.extract_domain_from_rule(rule, rule_type)
            if not domain or not self._validate_domain_syntax(domain, rule_type):
                issues.append("域名语法错误")
                self.validation_results["domain_validation_failures"] += 1
                return False, issues

        # 修饰符验证
        modifiers = self.extract_modifiers(rule)
        modifier_issues = self._validate_modifiers(modifiers, rule_type)
        issues.extend(modifier_issues)

        if issues:
            self.validation_results["invalid_rules"] += 1
            return False, issues
        else:
            self.validation_results["valid_rules"] += 1
            return True, []

    def _validate_regex_syntax(self, rule: str) -> bool:
        """验证正则语法"""
        if rule.startswith('/') and rule.endswith('/'):
            pattern = rule[1:-1]
            try:
                re.compile(pattern)
                return True
            except re.error:
                return False
        return False

    def _validate_domain_syntax(self, domain: str, rule_type: str) -> bool:
        """验证域名语法"""
        if not domain:
            return False
            
        if rule_type in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
            return True  # 正则规则已单独验证
            
        valid_chars = self.syntax_db["validation_rules"].get("valid_domain_chars", "a-zA-Z0-9.*-")
        domain_pattern = rf"^[{valid_chars}]+$"
        return bool(re.match(domain_pattern, domain)) and len(domain) <= 253

    def _validate_modifiers(self, modifiers: Dict[str, str], rule_type: str) -> List[str]:
        """验证修饰符组合"""
        issues = []
        valid_combinations = self.syntax_db["validation_rules"].get("valid_modifier_combinations", {})
        
        for modifier in modifiers:
            if rule_type in valid_combinations:
                if modifier not in valid_combinations[rule_type]:
                    issues.append(f"无效修饰符组合: {modifier} with {rule_type}")
                    
        return issues

    def is_platform_support_rule(self, platform: str, rule_type: str) -> bool:
        """检查平台支持"""
        supported = rule_type in self.platform_supported_rules.get(platform, set())
        if not supported:
            self.validation_results["platform_compatibility_issues"] += 1
        return supported

    def is_dns_compatible(self, rule_type: str) -> bool:
        """检查DNS兼容性"""
        return rule_type not in self.config.DNS_INVALID_SYNTAX

    def get_validation_report(self) -> Dict[str, Any]:
        """获取验证报告"""
        return self.validation_results.copy()


class ComprehensiveRuleConverter:
    def __init__(self, config: ConvertConfig):
        self.config = config
        self.parser = ComprehensiveSyntaxParser(config)

        # 统计数据
        self.adguard_rules = {"black": [], "white": []}
        self.rule_statistics = defaultdict(lambda: defaultdict(int))
        self.conversion_statistics = defaultdict(lambda: defaultdict(int))
        
        # 转换结果
        self.convertible_domains = {
            platform: {"block": set(), "allow": set()} 
            for platform in ["adblock_plus", "ubo", "pihole", "hosts", "surge", "clash"]
        }
        
        self.rule_issues = {
            "invalid_domains": [],
            "unsupported_platforms": [],
            "dns_incompatible": [],
            "validation_failures": []
        }

    def process_adguard_rules(self) -> None:
        """处理AdGuard规则文件"""
        logger.info("=" * 70)
        logger.info("第一步：全面处理AdGuard规则（支持完整语法覆盖）")
        logger.info("=" * 70)

        for is_allow, file_path in [
            (True, self.config.INPUT_ALLOW), 
            (False, self.config.INPUT_BLOCK)
        ]:
            file_type = "放行（白名单）" if is_allow else "拦截（黑名单）"
            if not file_path.exists():
                logger.warning(f"AdGuard{file_type}文件不存在：{file_path} → 跳过")
                continue
                
            logger.info(f"处理AdGuard{file_type}文件：{file_path.name}")
            self._process_single_file(file_path, is_allow)

    def _process_single_file(self, file_path: Path, is_allow: bool) -> None:
        """处理单个规则文件"""
        line_count = 0
        convertible_count = 0
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                line_count += 1

                rule_type = self.parser.get_rule_type(line)
                self._categorize_rule(line, rule_type, is_allow)

                # 处理可转换规则
                if rule_type in self.config.CONVERTIBLE_SYNTAX:
                    convertible_count += 1
                    self._process_convertible_rule(line, rule_type, is_allow)

                if line_count % self.config.BATCH_SIZE == 0:
                    logger.debug(f"已处理{line_count}行，可转换{convertible_count}条")

        logger.info(f"处理完成：{file_path.name} → 共{line_count}行，可转换{convertible_count}条")

    def _categorize_rule(self, rule: str, rule_type: str, is_allow: bool) -> None:
        """分类统计规则"""
        target = "white" if is_allow else "black"
        
        if rule_type in ["adblock_basic_comment", "aglint_comment", "empty_rule", "unknown_rule"]:
            self.rule_statistics["metadata"][rule_type] += 1
        elif rule_type in self.config.DNS_INVALID_SYNTAX:
            self.rule_statistics["dns_incompatible"][rule_type] += 1
            self.adguard_rules[target].append(rule)
        elif rule_type in self.config.CONVERTIBLE_SYNTAX:
            self.rule_statistics["convertible"][rule_type] += 1
            self.adguard_rules[target].append(rule)
        else:
            self.rule_statistics["other"][rule_type] += 1

    def _process_convertible_rule(self, rule: str, rule_type: str, is_allow: bool) -> None:
        """处理可转换规则"""
        # 验证规则
        is_valid, issues = self.parser.validate_rule(rule, rule_type)
        if not is_valid:
            self.rule_issues["validation_failures"].append((rule, issues))
            return

        # 提取域名
        domain = self.parser.extract_domain_from_rule(rule, rule_type)
        if not domain:
            self.rule_issues["invalid_domains"].append(rule)
            return

        target = "allow" if is_allow else "block"
        
        # 按平台分配规则
        for platform in self.convertible_domains.keys():
            if platform == "pihole" and target == "allow":
                continue  # Pi-hole不支持白名单
                
            if self.parser.is_platform_support_rule(platform, rule_type):
                if not self._is_duplicate_domain(domain, platform, target):
                    self.convertible_domains[platform][target].add(domain)
                    self.conversion_statistics[platform][target] += 1
            else:
                self.rule_issues["unsupported_platforms"].append((platform, rule_type, rule))

    def _is_duplicate_domain(self, domain: str, platform: str, target: str) -> bool:
        """检查重复域名"""
        if domain in self.convertible_domains[platform][target]:
            self.conversion_statistics["duplicates"]["total"] += 1
            return True
        return False

    def generate_comprehensive_report(self) -> None:
        """生成全面转换报告"""
        logger.info("\n" + "=" * 70)
        logger.info("第二步：完整转换统计报告")
        logger.info("=" * 70)

        self._print_rule_statistics()
        self._print_conversion_statistics()
        self._print_validation_report()
        self._print_issue_summary()

        logger.info("=" * 70)

    def _print_rule_statistics(self) -> None:
        """打印规则统计"""
        logger.info("1. 输入规则统计分析:")
        
        total_rules = sum(sum(category.values()) for category in self.rule_statistics.values())
        logger.info(f"   - 总规则数量: {total_rules}")
        
        # 元数据统计
        meta_count = sum(self.rule_statistics["metadata"].values())
        if meta_count > 0:
            logger.info(f"   - 元数据规则: {meta_count}条")
            for meta_type, count in self.rule_statistics["metadata"].items():
                if count > 0:
                    logger.info(f"     * {meta_type}: {count}条")
        
        # 可转换规则
        convertible_count = sum(self.rule_statistics["convertible"].values())
        logger.info(f"   - 可转换规则: {convertible_count}条")
        for rule_type, count in self.rule_statistics["convertible"].items():
            if count > 0:
                logger.info(f"     * {rule_type}: {count}条")
        
        # DNS不兼容规则
        dns_incompatible = sum(self.rule_statistics["dns_incompatible"].values())
        if dns_incompatible > 0:
            logger.info(f"   - DNS不兼容规则: {dns_incompatible}条")
            for rule_type, count in self.rule_statistics["dns_incompatible"].items():
                if count > 0:
                    logger.info(f"     * {rule_type}: {count}条")

    def _print_conversion_statistics(self) -> None:
        """打印转换统计"""
        logger.info("\n2. 多平台转换统计:")
        
        total_converted = 0
        for platform in self.convertible_domains:
            block_count = len(self.convertible_domains[platform]["block"])
            allow_count = len(self.convertible_domains[platform]["allow"])
            total_converted += block_count + allow_count
            
            if platform == "pihole":
                logger.info(f"   - {platform.upper():<12}: 拦截{block_count:>6}条 (无白名单)")
            else:
                logger.info(f"   - {platform.upper():<12}: 拦截{block_count:>6}条 | 放行{allow_count:>6}条")
        
        logger.info(f"   - 总计转换: {total_converted}条规则")

    def _print_validation_report(self) -> None:
        """打印验证报告"""
        validation_report = self.parser.get_validation_report()
        logger.info("\n3. 规则验证报告:")
        logger.info(f"   - 有效规则: {validation_report['valid_rules']}条")
        logger.info(f"   - 无效规则: {validation_report['invalid_rules']}条")
        
        if validation_report['regex_validation_failures'] > 0:
            logger.info(f"   - 正则语法错误: {validation_report['regex_validation_failures']}条")
        if validation_report['domain_validation_failures'] > 0:
            logger.info(f"   - 域名语法错误: {validation_report['domain_validation_failures']}条")
        if validation_report['platform_compatibility_issues'] > 0:
            logger.info(f"   - 平台兼容问题: {validation_report['platform_compatibility_issues']}条")

    def _print_issue_summary(self) -> None:
        """打印问题摘要"""
        total_issues = (
            len(self.rule_issues["invalid_domains"]) +
            len(self.rule_issues["unsupported_platforms"]) +
            len(self.rule_issues["validation_failures"])
        )
        
        if total_issues > 0:
            logger.info("\n4. 问题规则摘要:")
            logger.info(f"   - 总问题规则: {total_issues}条")
            
            if self.rule_issues["invalid_domains"]:
                logger.info(f"   - 无效域名: {len(self.rule_issues['invalid_domains'])}条")
            if self.rule_issues["validation_failures"]:
                logger.info(f"   - 验证失败: {len(self.rule_issues['validation_failures'])}条")
            if self.rule_issues["unsupported_platforms"]:
                logger.info(f"   - 平台不支持: {len(self.rule_issues['unsupported_platforms'])}条")
            
            # 显示前5个问题的示例
            if self.rule_issues["validation_failures"]:
                logger.info("    示例问题规则:")
                for rule, issues in self.rule_issues["validation_failures"][:3]:
                    logger.info(f"      - {rule[:60]}... [问题: {', '.join(issues[:2])}]")

    # 以下生成各平台产物的方法与之前类似，但确保完全纯净
    def _generate_adblock_plus_product(self) -> None:
        """生成Adblock Plus纯净规则"""
        adb_plus_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_ADBLOCK_PLUS_BLOCK,
                "domains": sorted(self.convertible_domains["adblock_plus"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_ADBLOCK_PLUS_ALLOW,
                "domains": sorted(self.convertible_domains["adblock_plus"]["allow"])
            }
        }

        for target, cfg in adb_plus_cfg.items():
            if not cfg["domains"]:
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                for domain in cfg["domains"]:
                    if not domain.startswith('/'):  # 跳过正则（ABP不支持）
                        rule = f"||{domain}^" if target == "block" else f"@@||{domain}^"
                        f.write(f"{rule}\n")

    def _generate_ubo_product(self) -> None:
        """生成uBlock Origin纯净规则"""
        ubo_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_UBO_BLOCK,
                "domains": sorted(self.convertible_domains["ubo"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_UBO_ALLOW,
                "domains": sorted(self.convertible_domains["ubo"]["allow"])
            }
        }

        for target, cfg in ubo_cfg.items():
            if not cfg["domains"]:
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                for domain in cfg["domains"]:
                    if domain.startswith('/') and domain.endswith('/'):
                        f.write(f"{domain}\n")  # 正则规则
                    else:
                        rule = f"||{domain}^" if target == "block" else f"@@||{domain}^"
                        f.write(f"{rule}\n")

    def _generate_pihole_product(self) -> None:
        """生成Pi-hole纯净规则"""
        pihole_path = self.config.OUTPUT_DIR / self.config.OUTPUT_PIHOLE
        domains = sorted(self.convertible_domains["pihole"]["block"])
        if not domains:
            return

        with open(pihole_path, "w", encoding="utf-8") as f:
            for domain in domains:
                f.write(f"{domain}\n")

    def _generate_hosts_product(self) -> None:
        """生成Hosts纯净规则"""
        hosts_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_HOSTS,
                "ip": self.config.HOSTS_BLOCK_IP,
                "domains": sorted([d for d in self.convertible_domains["hosts"]["block"] if not d.startswith('/')])
            }
        }

        for target, cfg in hosts_cfg.items():
            if not cfg["domains"]:
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                for domain in cfg["domains"]:
                    f.write(f"{cfg['ip']} {domain}\n")

    def _generate_surge_product(self) -> None:
        """生成Surge纯净规则"""
        surge_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_SURGE_BLOCK,
                "domains": sorted([d for d in self.convertible_domains["surge"]["block"] if not d.startswith('/')])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_SURGE_ALLOW,
                "domains": sorted([d for d in self.convertible_domains["surge"]["allow"] if not d.startswith('/')])
            }
        }

        for target, cfg in surge_cfg.items():
            if not cfg["domains"]:
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                policy = "REJECT" if target == "block" else "DIRECT"
                f.write(f"#DOMAIN-SET,adblock_surge_{target},{policy}\n")
                for domain in cfg["domains"]:
                    f.write(f".{domain}\n")

    def _generate_clash_product(self) -> None:
        """生成Clash纯净规则"""
        clash_config = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_CLASH_BLOCK,
                "domains": sorted([d for d in self.convertible_domains["clash"]["block"] if not d.startswith('/')])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_CLASH_ALLOW,
                "domains": sorted([d for d in self.convertible_domains["clash"]["allow"] if not d.startswith('/')])
            }
        }

        for target, cfg in clash_config.items():
            if not cfg["domains"]:
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                policy = "REJECT" if target == "block" else "DIRECT"
                f.write(f"#RULE-SET,adblock_clash_{target},{policy}\n")
                f.write("payload:\n")
                for domain in cfg["domains"]:
                    f.write(f"  - '+.{domain}'\n")

    def _generate_mihomo_product(self) -> None:
        """生成Mihomo二进制规则集"""
        if not self.config.ENABLE_MIHOMO or not self.config.MIHOMO_BIN.exists():
            return

        # 过滤域名
        white_domains = {d for d in self.convertible_domains["clash"]["allow"] if not d.startswith('/')}
        block_domains = [
            d for d in self.convertible_domains["clash"]["block"] 
            if not d.startswith('/') and d not in white_domains
        ]
        
        if not block_domains:
            return

        temp_yaml = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write("payload:\n")
                for domain in sorted(block_domains):
                    f.write(f"  - '+.{domain}'\n")
                temp_yaml = f.name

            output_mrs = self.config.OUTPUT_DIR / self.config.OUTPUT_MIHOMO
            cmd = [str(self.config.MIHOMO_BIN), "convert-ruleset", "domain", "yaml", temp_yaml, str(output_mrs)]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=True)
            
            # 计算哈希
            sha256 = hashlib.sha256()
            with open(output_mrs, "rb") as f:
                sha256.update(f.read())
            logger.info(f"Mihomo产物: {output_mrs} ({len(block_domains)}条, SHA256: {sha256.hexdigest()[:16]}...)")
            
        except Exception as e:
            logger.error(f"Mihomo编译失败: {e}")
        finally:
            if temp_yaml and os.path.exists(temp_yaml):
                os.unlink(temp_yaml)

    def generate_products(self) -> None:
        """生成所有平台产物"""
        logger.info("\n第三步：生成多平台纯净规则产物")
        logger.info("=" * 70)
        
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 生成各平台产物
        products = [
            ("Adblock Plus", self._generate_adblock_plus_product),
            ("uBlock Origin", self._generate_ubo_product),
            ("Pi-hole", self._generate_pihole_product),
            ("Hosts", self._generate_hosts_product),
            ("Surge", self._generate_surge_product),
            ("Clash", self._generate_clash_product),
            ("Mihomo", self._generate_mihomo_product)
        ]

        for name, generator in products:
            try:
                generator()
                logger.info(f"✓ {name:<15} → 生成完成")
            except Exception as e:
                logger.error(f"✗ {name:<15} → 生成失败: {e}")

        logger.info("=" * 70)
        logger.info("所有多平台纯净规则产物生成完成！")

    def run_full_flow(self) -> None:
        """运行完整转换流程"""
        try:
            self.process_adguard_rules()
            self.generate_comprehensive_report()
            self.generate_products()
        except KeyboardInterrupt:
            logger.info("\n流程被用户中断")
            sys.exit(0)
        except Exception as e:
            logger.error(f"\n转换流程失败: {e}")
            sys.exit(1)


if __name__ == "__main__":
    config = ConvertConfig()
    converter = ComprehensiveRuleConverter(config)
    converter.run_full_flow()