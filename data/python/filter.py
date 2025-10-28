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
from datetime import datetime
from collections import defaultdict

try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("pybloom_live not available, bloom filter disabled")

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

    # 输出配置 - 根据语法数据库修正命名
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

    # 根据语法数据库修正支持的语法类型
    ADGUARD_SYNTAX: Set[str] = field(default_factory=lambda: {
        # 基础语法 - 补充精准域名规则支持
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", 
        "adblock_basic_precise_domain", "adblock_basic_precise_exception",
        "adblock_basic_wildcard_domain", "adblock_basic_element_hiding",
        "adblock_basic_element_hiding_exception", "adblock_basic_url_rule",

        # AdGuard扩展语法
        "adguard_scriptlet", "adguard_dns_rewrite", "adguard_removeparam", 
        "adguard_redirect", "adguard_redirect_rule", "adguard_referrerpolicy",
        "adguard_removeheader", "adguard_csp", "adguard_stealth_rule", 
        "adguard_cookie_rule", "adguard_extended_css", "adguard_replace",
        "adguard_header", "adguard_jsonprune", "adguard_generichide",
        "adguard_specifichide",

        # AdGuard Home特定语法
        "adguard_home_dns_rewrite", "adguard_home_client", "adguard_home_dnstype",
        "adguard_home_precise_domain",

        # 正则和高级语法
        "regex_rule", "adblock_basic_regex_rule",

        # 其他格式
        "hosts_rule", "pihole_domain", "pihole_regex",

        # CSS选择器语法
        "adblock_basic_css_id_selector", "adblock_basic_css_class_selector",
        "adblock_basic_css_attribute_selector", "adblock_basic_css_combinator",
        "adblock_basic_css_pseudo_class", "adblock_basic_css_pseudo_element",

        # 元数据
        "adblock_basic_comment", "aglint_comment"
    })

    # 根据语法数据库修正可转换的语法类型
    CONVERTIBLE_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", 
        "adblock_basic_precise_domain", "adblock_basic_precise_exception",
        "adblock_basic_wildcard_domain", "hosts_rule", 
        "adguard_home_dns_rewrite", "adguard_home_precise_domain", 
        "pihole_domain", "regex_rule", "adblock_basic_regex_rule", 
        "pihole_regex"
    })

    # 根据语法数据库修正DNS层面无效的语法类型
    DNS_INVALID_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_element_hiding", "adblock_basic_element_hiding_exception",
        "adguard_scriptlet", "adguard_extended_css", 
        "adblock_basic_css_id_selector", "adblock_basic_css_class_selector",
        "adblock_basic_css_attribute_selector", "adblock_basic_css_combinator",
        "adblock_basic_css_pseudo_class", "adblock_basic_css_pseudo_element",
        "adguard_extension_css", "ubo_extended_css"
    })

    BATCH_SIZE: int = 1000
    USE_BLOOM: bool = BLOOM_AVAILABLE
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

        # 基础模式 - 修正为数据库中的精确模式
        base_patterns = [
            "adblock_basic_comment", "aglint_comment"
        ]
        for pattern in base_patterns:
            if pattern in syntax_patterns:
                try:
                    compiled[pattern] = re.compile(syntax_patterns[pattern], re.UNICODE)
                except re.error as e:
                    logger.warning(f"基础模式编译失败 {pattern}: {e}")

        # 编译所有语法模式 - 使用数据库中的精确正则
        for syntax in self.config.ADGUARD_SYNTAX:
            if syntax in syntax_patterns:
                try:
                    flags = re.IGNORECASE | re.UNICODE
                    if syntax.endswith("_regex_rule"):
                        flags |= re.DOTALL
                    compiled[syntax] = re.compile(syntax_patterns[syntax], flags)
                except re.error as e:
                    logger.warning(f"正则编译失败 {syntax}: {e}")

        # 添加空行规则
        compiled["empty_rule"] = re.compile(r'^\s*$')

        return compiled

    def _compile_modifier_patterns(self) -> Dict[str, Pattern]:
        """编译修饰符模式 - 修正正则表达式格式"""
        modifiers = self.syntax_db.get("modifiers", {})
        compiled = {}
        
        # 基础修饰符模式
        base_modifiers = {
            "domain": r"domain=([^\s,]+)",
            "third-party": r"third-party",
            "script": r"script",
            "image": r"image", 
            "stylesheet": r"stylesheet",
            "important": r"important",
            "badfilter": r"badfilter",
            "redirect": r"redirect=([^\s,]+)",
            "removeparam": r"removeparam=([^\s,]+)",
            "csp": r"csp=([^\s,]+)",
            "client": r"client=([^\s,]+)",
            "dnstype": r"dnstype=([^\s,]+)",
            "dnsrewrite": r"dnsrewrite=([^\s,]+)"
        }
        
        for key, pattern in base_modifiers.items():
            try:
                compiled[key] = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"修饰符模式编译失败 {key}: {e}")
                continue
                
        return compiled

    def _init_bloom(self) -> Dict[str, Any]:
        if not self.config.USE_BLOOM or not BLOOM_AVAILABLE:
            return {}
        try:
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
        except Exception as e:
            logger.warning(f"Bloom filter初始化失败: {e}")
            return {}

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

        # 检查注释和空行 - 使用数据库中的精确模式
        if self.compiled_patterns.get("adblock_basic_comment") and self.compiled_patterns["adblock_basic_comment"].match(rule):
            return "adblock_basic_comment"
        if self.compiled_patterns.get("aglint_comment") and self.compiled_patterns["aglint_comment"].match(rule):
            return "aglint_comment"
        if self.compiled_patterns.get("empty_rule") and self.compiled_patterns["empty_rule"].match(rule):
            return "empty_rule"

        # 检查各种语法规则 - 优先检查精准域名规则
        for syntax in ["adblock_basic_precise_domain", "adblock_basic_precise_exception", 
                      "adblock_basic_domain_rule", "adblock_basic_exception_rule"]:
            if syntax in self.compiled_patterns and self.compiled_patterns[syntax].match(rule):
                self.rule_type_cache[rule] = syntax
                return syntax

        # 检查其他语法规则
        for syntax, pattern in self.compiled_patterns.items():
            if syntax in ["adblock_basic_comment", "aglint_comment", "empty_rule", 
                         "adblock_basic_precise_domain", "adblock_basic_precise_exception",
                         "adblock_basic_domain_rule", "adblock_basic_exception_rule"]:
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
        
        try:
            # 基于规则类型提取域名 - 根据数据库模式修正
            if rule_type in ["adblock_basic_domain_rule", "adblock_basic_exception_rule",
                           "adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
                domain_match = re.search(r'\|\|([^\^$]+)', rule)
                domain = domain_match.group(1) if domain_match else None
            elif rule_type == "adblock_basic_wildcard_domain":
                domain_match = re.search(r'\|\|([^\^$]+)', rule)
                domain = domain_match.group(1) if domain_match else None
            elif rule_type == "hosts_rule":
                parts = rule.split()
                if len(parts) >= 2:
                    domain = parts[1]
            elif rule_type in ["adguard_home_dns_rewrite", "adguard_home_precise_domain"]:
                domain_match = re.search(r'\|\|([^\^$]+)', rule)
                domain = domain_match.group(1) if domain_match else None
            elif rule_type in ["pihole_domain"]:
                domain = rule.strip()
            elif rule_type in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
                domain = rule  # 对于正则和特殊规则，使用完整规则作为"域名"

            # 域名清洗和规范化 - 根据数据库规范化规则
            if domain and not isinstance(domain, str):
                domain = str(domain)

            # 应用数据库中的规范化规则
            domain = self._normalize_domain(domain, rule_type)

        except Exception as e:
            logger.debug(f"域名提取失败 {rule_type}: {rule} - {e}")
            return None

        self.domain_cache[cache_key] = domain
        return domain

    def _normalize_domain(self, domain: str, rule_type: str) -> str:
        """域名规范化 - 根据数据库规范化规则修正"""
        if not domain:
            return domain

        # 应用数据库规范化规则
        normalization_rules = self.syntax_db.get("normalization_rules", {})

        if normalization_rules.get("domain_to_lowercase", True):
            domain = domain.lower()

        domain = domain.strip()

        # 移除常见前缀和后缀 - 根据数据库模式
        if rule_type not in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
            # 非正则规则进行域名清洗
            domain = re.sub(r'^\|+\*?\.?', '', domain)
            domain = re.sub(r'\^.*$', '', domain)
            domain = re.sub(r'\$.*$', '', domain)
            domain = re.sub(r'[/|^$].*$', '', domain)

        # 应用精准域名规范化
        if rule_type in ["adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
            precise_norm = normalization_rules.get("precise_domain_normalization", {})
            if precise_norm.get("strip_modifiers", True):
                # 移除修饰符部分
                domain = re.sub(r'\$.*$', '', domain)
            if precise_norm.get("extract_clean_domain", True):
                # 提取纯净域名
                clean_match = re.search(r'\|\|([^\^$]+)', domain)
                if clean_match:
                    domain = clean_match.group(1)

        # 验证基本域名格式 - 根据数据库验证规则
        if rule_type not in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
            valid_chars = self.syntax_db["validation_rules"].get("valid_domain_chars", "a-zA-Z0-9.*-")
            if not re.match(rf'^[{valid_chars}]+$', domain):
                return ""

        return domain

    def extract_modifiers(self, rule: str) -> Dict[str, str]:
        """提取规则修饰符 - 修正提取逻辑"""
        if rule in self.modifier_cache:
            return self.modifier_cache[rule]

        modifiers = {}

        # 查找修饰符部分
        modifier_match = re.search(r'\$([^#\n]+)$', rule)
        if not modifier_match:
            return modifiers

        modifier_part = modifier_match.group(1)

        # 使用编译的修饰符模式进行匹配
        for modifier_name, pattern in self.modifier_patterns.items():
            match = pattern.search(modifier_part)
            if match:
                if match.lastindex and match.group(1):
                    modifiers[modifier_name] = match.group(1)
                else:
                    modifiers[modifier_name] = "true"

        self.modifier_cache[rule] = modifiers
        return modifiers

    def validate_rule(self, rule: str, rule_type: str) -> Tuple[bool, List[str]]:
        """全面验证规则 - 根据数据库验证规则修正"""
        issues = []

        # 基础验证 - 使用数据库中的验证规则
        validation_rules = self.syntax_db["validation_rules"]

        if not rule or len(rule.strip()) == 0:
            issues.append("空规则")
            return False, issues

        max_length = validation_rules.get("max_rule_length", 4096)
        if len(rule) > max_length:
            issues.append(f"规则过长 ({len(rule)} > {max_length})")
            return False, issues

        min_length = validation_rules.get("min_rule_length", 3)
        if len(rule.strip()) < min_length:
            issues.append(f"规则过短 ({len(rule.strip())} < {min_length})")
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

        # 修饰符验证 - 使用数据库中的修饰符组合规则
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
        """验证正则语法 - 根据数据库验证规则修正"""
        validation_rules = self.syntax_db["validation_rules"]

        # 检查正则格式
        if not (rule.startswith('/') and rule.endswith('/')):
            return False

        pattern = rule[1:-1]

        # 检查正则长度
        max_regex_length = validation_rules.get("regex_max_length", 1998)
        if len(pattern) > max_regex_length:
            return False

        # 检查嵌套层数
        max_nesting = validation_rules.get("regex_max_nesting", 3)
        nesting_level = pattern.count('(') - pattern.count('\\(')
        if nesting_level > max_nesting:
            return False

        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def _validate_domain_syntax(self, domain: str, rule_type: str) -> bool:
        """验证域名语法 - 根据数据库验证规则修正"""
        if not domain:
            return False

        if rule_type in ["regex_rule", "adblock_basic_regex_rule", "pihole_regex"]:
            return True  # 正则规则已单独验证

        validation_rules = self.syntax_db["validation_rules"]

        # 检查域名长度
        if len(domain) > 253:
            return False

        # 检查域名字符集
        valid_chars = validation_rules.get("valid_domain_chars", "a-zA-Z0-9.*-")
        domain_pattern = rf"^[{valid_chars}]+$"

        if not re.match(domain_pattern, domain):
            return False

        # 特殊验证：精准域名规则
        if rule_type in ["adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
            precise_validation = validation_rules.get("precise_domain_validation", {})
            if precise_validation.get("validate_clean_domain_only", True):
                # 验证纯净域名格式
                clean_domain = re.sub(r'\$.*$', '', domain)
                if not re.match(domain_pattern, clean_domain):
                    return False

        return True

    def _validate_modifiers(self, modifiers: Dict[str, str], rule_type: str) -> List[str]:
        """验证修饰符组合 - 根据数据库验证规则修正"""
        issues = []
        valid_combinations = self.syntax_db["validation_rules"].get("valid_modifier_combinations", {})

        # 检查修饰符组合是否有效
        for modifier in modifiers:
            if rule_type in valid_combinations:
                if modifier not in valid_combinations[rule_type]:
                    issues.append(f"无效修饰符组合: {modifier} with {rule_type}")
            elif modifier not in ["domain", "important"]:  # 允许通用修饰符
                issues.append(f"未知修饰符: {modifier}")

        return issues

    def is_platform_support_rule(self, platform: str, rule_type: str) -> bool:
        """检查平台支持 - 根据数据库平台支持配置修正"""
        supported = rule_type in self.platform_supported_rules.get(platform, set())
        if not supported:
            self.validation_results["platform_compatibility_issues"] += 1
        return supported

    def is_dns_compatible(self, rule_type: str) -> bool:
        """检查DNS兼容性 - 根据数据库DNS无效语法修正"""
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
        """处理AdGuard规则文件 - 增强精准域名规则支持"""
        logger.info("=" * 70)
        logger.info("第一步：全面处理AdGuard规则（支持完整语法覆盖 + 精准域名规则）")
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
        """处理单个规则文件 - 增强精准域名规则处理"""
        line_count = 0
        convertible_count = 0
        precise_domain_count = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    line_count += 1

                    rule_type = self.parser.get_rule_type(line)
                    self._categorize_rule(line, rule_type, is_allow)

                    # 统计精准域名规则
                    if rule_type in ["adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
                        precise_domain_count += 1

                    # 处理可转换规则
                    if rule_type in self.config.CONVERTIBLE_SYNTAX:
                        convertible_count += 1
                        self._process_convertible_rule(line, rule_type, is_allow)

                    if line_count % self.config.BATCH_SIZE == 0:
                        logger.debug(f"已处理{line_count}行，可转换{convertible_count}条，精准域名{precise_domain_count}条")

            logger.info(f"处理完成：{file_path.name} → 共{line_count}行，可转换{convertible_count}条，精准域名{precise_domain_count}条")
            
        except Exception as e:
            logger.error(f"处理文件失败 {file_path}: {e}")

    def _categorize_rule(self, rule: str, rule_type: str, is_allow: bool) -> None:
        """分类统计规则 - 增强精准域名规则统计"""
        target = "white" if is_allow else "black"

        if rule_type in ["adblock_basic_comment", "aglint_comment", "empty_rule", "unknown_rule"]:
            self.rule_statistics["metadata"][rule_type] += 1
        elif rule_type in self.config.DNS_INVALID_SYNTAX:
            self.rule_statistics["dns_incompatible"][rule_type] += 1
            self.adguard_rules[target].append(rule)
        elif rule_type in self.config.CONVERTIBLE_SYNTAX:
            self.rule_statistics["convertible"][rule_type] += 1
            self.adguard_rules[target].append(rule)

            # 特别统计精准域名规则
            if rule_type in ["adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
                self.rule_statistics["precise_domains"][rule_type] += 1
        else:
            self.rule_statistics["other"][rule_type] += 1

    def _process_convertible_rule(self, rule: str, rule_type: str, is_allow: bool) -> None:
        """处理可转换规则 - 增强精准域名规则处理"""
        # 验证规则
        is_valid, issues = self.parser.validate_rule(rule, rule_type)
        if not is_valid:
            self.rule_issues["validation_failures"].append((rule, issues))
            return

        # 提取域名 - 特别处理精准域名规则
        domain = self.parser.extract_domain_from_rule(rule, rule_type)
        if not domain:
            self.rule_issues["invalid_domains"].append(rule)
            return

        target = "allow" if is_allow else "block"

        # 按平台分配规则 - 根据数据库平台支持配置
        for platform in self.convertible_domains.keys():
            if platform == "pihole" and target == "allow":
                continue  # Pi-hole不支持白名单

            if self.parser.is_platform_support_rule(platform, rule_type):
                if not self._is_duplicate_domain(domain, platform, target):
                    self.convertible_domains[platform][target].add(domain)
                    self.conversion_statistics[platform][target] += 1

                    # 特别统计精准域名转换
                    if rule_type in ["adblock_basic_precise_domain", "adblock_basic_precise_exception"]:
                        self.conversion_statistics["precise_domains"][platform] += 1
            else:
                self.rule_issues["unsupported_platforms"].append((platform, rule_type, rule))

    def _is_duplicate_domain(self, domain: str, platform: str, target: str) -> bool:
        """检查重复域名"""
        if domain in self.convertible_domains[platform][target]:
            self.conversion_statistics["duplicates"]["total"] += 1
            return True
        return False

    def generate_comprehensive_report(self) -> None:
        """生成全面转换报告 - 增强精准域名规则报告"""
        logger.info("\n" + "=" * 70)
        logger.info("第二步：完整转换统计报告（含精准域名规则支持）")
        logger.info("=" * 70)

        self._print_rule_statistics()
        self._print_conversion_statistics()
        self._print_validation_report()
        self._print_issue_summary()

        logger.info("=" * 70)

    def _print_rule_statistics(self) -> None:
        """打印规则统计 - 增强精准域名规则统计"""
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

        # 精准域名规则统计
        if "precise_domains" in self.rule_statistics:
            precise_count = sum(self.rule_statistics["precise_domains"].values())
            if precise_count > 0:
                logger.info(f"   - 精准域名规则: {precise_count}条")
                for rule_type, count in self.rule_statistics["precise_domains"].items():
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
        """打印转换统计 - 增强精准域名转换统计"""
        logger.info("\n2. 多平台转换统计:")

        total_converted = 0
        for platform in self.convertible_domains:
            block_count = len(self.convertible_domains[platform]["block"])
            allow_count = len(self.convertible_domains[platform]["allow"])
            total_converted += block_count + allow_count

            # 精准域名转换统计
            precise_count = self.conversion_statistics["precise_domains"].get(platform, 0)

            if platform == "pihole":
                logger.info(f"   - {platform.upper():<12}: 拦截{block_count:>6}条 (无白名单)")
            else:
                logger.info(f"   - {platform.upper():<12}: 拦截{block_count:>6}条 | 放行{allow_count:>6}条")

            if precise_count > 0:
                logger.info(f"     [精准域名: {precise_count}条]")

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

    def _generate_adblock_plus_product(self) -> None:
        """生成Adblock Plus纯净规则 - 根据数据库格式修正"""
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
            try:
                with open(cfg["path"], "w", encoding="utf-8") as f:
                    # 写入文件头
                    f.write("! Adblock Plus规则 - 由AdGuard规则转换生成\n")
                    f.write("! 包含精准域名规则支持\n\n")

                    for domain in cfg["domains"]:
                        if domain.startswith('/') and domain.endswith('/'):
                            continue  # ABP不支持正则规则
                        else:
                            # 使用数据库中的ABP格式
                            rule = f"||{domain}^" if target == "block" else f"@@||{domain}^"
                            f.write(f"{rule}\n")
            except Exception as e:
                logger.error(f"生成Adblock Plus {target}规则失败: {e}")

    def _generate_ubo_product(self) -> None:
        """生成uBlock Origin纯净规则 - 根据数据库格式修正"""
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
            try:
                with open(cfg["path"], "w", encoding="utf-8") as f:
                    # 写入文件头
                    f.write("! uBlock Origin规则 - 由AdGuard规则转换生成\n")
                    f.write("! 包含精准域名规则和正则规则支持\n\n")

                    for domain in cfg["domains"]:
                        if domain.startswith('/') and domain.endswith('/'):
                            f.write(f"{domain}\n")  # 正则规则
                        else:
                            # 使用数据库中的UBO格式
                            rule = f"||{domain}^" if target == "block" else f"@@||{domain}^"
                            f.write(f"{rule}\n")
            except Exception as e:
                logger.error(f"生成uBlock Origin {target}规则失败: {e}")

    def _generate_pihole_product(self) -> None:
        """生成Pi-hole纯净规则 - 根据数据库格式修正"""
        pihole_path = self.config.OUTPUT_DIR / self.config.OUTPUT_PIHOLE
        domains = sorted([d for d in self.convertible_domains["pihole"]["block"] if not d.startswith('/')])
        if not domains:
            return

        try:
            with open(pihole_path, "w", encoding="utf-8") as f:
                # 写入文件头
                f.write("# Pi-hole规则 - 由AdGuard规则转换生成\n")
                f.write("# 专注于DNS层广告拦截\n\n")

                for domain in domains:
                    f.write(f"{domain}\n")
        except Exception as e:
            logger.error(f"生成Pi-hole规则失败: {e}")

    def _generate_hosts_product(self) -> None:
        """生成Hosts纯净规则 - 根据数据库格式修正"""
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
            try:
                with open(cfg["path"], "w", encoding="utf-8") as f:
                    # 写入文件头
                    f.write("# Hosts规则 - 由AdGuard规则转换生成\n")
                    f.write("# 用于系统级广告拦截\n\n")

                    for domain in cfg["domains"]:
                        f.write(f"{cfg['ip']} {domain}\n")
            except Exception as e:
                logger.error(f"生成Hosts规则失败: {e}")

    def _generate_surge_product(self) -> None:
        """生成Surge纯净规则 - 根据数据库格式修正"""
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
            try:
                with open(cfg["path"], "w", encoding="utf-8") as f:
                    policy = "REJECT" if target == "block" else "DIRECT"
                    # 使用数据库中的Surge格式
                    f.write(f"#DOMAIN-SET,adblock_surge_{target},{policy}\n")
                    for domain in cfg["domains"]:
                        f.write(f".{domain}\n")
            except Exception as e:
                logger.error(f"生成Surge {target}规则失败: {e}")

    def _generate_clash_product(self) -> None:
        """生成Clash纯净规则 - 根据数据库格式修正"""
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
            try:
                with open(cfg["path"], "w", encoding="utf-8") as f:
                    policy = "REJECT" if target == "block" else "DIRECT"
                    # 使用数据库中的Clash格式
                    f.write(f"#RULE-SET,adblock_clash_{target},{policy}\n")
                    f.write("payload:\n")
                    for domain in cfg["domains"]:
                        f.write(f"  - '+.{domain}'\n")
            except Exception as e:
                logger.error(f"生成Clash {target}规则失败: {e}")

    def _generate_mihomo_product(self) -> None:
        """生成Mihomo二进制规则集 - 根据数据库格式修正"""
        if not self.config.ENABLE_MIHOMO or not self.config.MIHOMO_BIN.exists():
            return

        # 过滤域名 - 专注DNS层广告拦截
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
                # 使用数据库中的Clash格式
                f.write("# Mihomo规则集 - 由AdGuard规则转换生成\n")
                f.write("payload:\n")
                for domain in sorted(block_domains):
                    f.write(f"  - '+.{domain}'\n")
                temp_yaml = f.name

            output_mrs = self.config.OUTPUT_DIR / self.config.OUTPUT_MIHOMO
            cmd = [str(self.config.MIHOMO_BIN), "convert-ruleset", "domain", "yaml", temp_yaml, str(output_mrs)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # 计算哈希
                sha256 = hashlib.sha256()
                with open(output_mrs, "rb") as f:
                    sha256.update(f.read())
                logger.info(f"Mihomo产物: {output_mrs} ({len(block_domains)}条, SHA256: {sha256.hexdigest()[:16]}...)")
            else:
                logger.error(f"Mihomo编译失败: {result.stderr}")

        except Exception as e:
            logger.error(f"Mihomo编译失败: {e}")
        finally:
            if temp_yaml and os.path.exists(temp_yaml):
                os.unlink(temp_yaml)

    def generate_products(self) -> None:
        """生成所有平台产物 - 根据数据库平台支持修正"""
        logger.info("\n第三步：生成多平台纯净规则产物（基于语法数据库规范）")
        logger.info("=" * 70)

        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 生成各平台产物 - 按照数据库支持修正
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
                logger.info(f"✓ {name:<15} → 生成完成（符合语法数据库规范）")
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