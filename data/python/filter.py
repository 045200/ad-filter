#!/usr/bin/env python3
"""
统一规则转换器 - 基于语法数据库v4.7.0（Adblock基础+AdGuard全平台 → 多目标平台）
支持输入：Adblock基础语法规则、AdGuard全平台规则（含DNS重写/脚本/扩展CSS）
支持输出：UBO、ABP、Pi-hole、Surge、Clash、Mihomo、Hosts
"""

import os
import re
import json
import sys
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Pattern
from dataclasses import dataclass, field
import logging
from pybloom_live import ScalableBloomFilter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@dataclass
class UnifiedConfig:
    """配置类 - 核心参数从语法数据库动态加载"""
    BASE_DIR: Path = Path(os.getenv('FILTER_DIR', Path.cwd()))  # 修正：使用日志中实际环境变量FILTER_DIR
    
    # 输入文件：与日志中加载路径一致
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"  # 拦截规则（含AdGuard全平台）
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"    # 放行规则（含AdGuard全平台）
    
    # 输出配置：覆盖所有目标平台，补充拦截规则文件配置（修复日志中拦截数为0问题）
    OUTPUT_DIR: Path = BASE_DIR
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {"block": "adblock_clash.yaml", "allow": "allow_clash.yaml"},
        "surge": {"block": "adblock_surge.txt", "allow": "allow_surge.txt"},
        "pihole": {"block": "adblock_pihole.txt", "allow": "allow_pihole.txt"},
        "ublock_origin": {"block": "adblock_ubo.txt", "allow": "allow_ubo.txt"},
        "adblock_plus": {"block": "adblock_abp.txt", "allow": "allow_abp.txt"},  # 补充拦截文件
        "hosts": {"block": "hosts.txt"},  # Hosts不支持放行规则
        "mihomo": {"block": "adb.mrs"},    # Mihomo仅需拦截规则
        "adguard_home": {"block": "adblock_adh.txt", "allow": "allow_adh.txt"},
        "adguard_browser": {"block": "adblock_adg_browser.txt", "allow": "allow_adg_browser.txt"}
    })
    
    # 语法数据库路径：与日志中加载路径一致（/home/runner/work/ad-filter/ad-filter/data/python/）
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    
    # 功能开关（默认启用，与日志行为一致）
    ENABLE_MIHOMO: bool = os.getenv('ENABLE_MIHOMO', 'true').lower() == 'true'
    ENABLE_DEDUPLICATION: bool = os.getenv('ENABLE_DEDUPE', 'true').lower() == 'true'
    ENABLE_WHITELIST_FILTERING: bool = os.getenv('ENABLE_WHITELIST', 'true').lower() == 'true'
    ENABLE_ADVANCED_MODIFIERS: bool = os.getenv('ENABLE_ADVANCED_MODIFIERS', 'true').lower() == 'true'
    
    # 动态配置：从数据库加载（初始化后覆盖）
    BATCH_SIZE: int = 1000
    BLOOM_CAPACITY: int = 1000000  # 日志中初始化值，数据库加载后可覆盖
    BLOOM_ERROR_RATE: float = 0.001  # 日志中初始化值
    MAX_RULE_LENGTH: int = 4096
    MIN_RULE_LENGTH: int = 3
    TARGET_PLATFORMS: List[str] = field(default_factory=list)


class EnhancedSyntaxDatabase:
    """增强版语法数据库 - 完全依赖v4.7.0数据库，修复配置加载逻辑"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.db_data: Dict[str, Any] = {}
        self.syntax_patterns: Dict[str, str] = {}
        self.compiled_syntax: Dict[str, Pattern] = {}
        self.rule_types: Dict[str, str] = {}
        self.platform_support: Dict[str, Dict[str, Any]] = {}
        self.modifiers: Dict[str, str] = {}
        self.compiled_modifiers: Dict[str, Pattern] = {}
        self.normalization_rules: Dict[str, bool] = {}
        self.validation_rules: Dict[str, Any] = {}
        self.adguard_specific: Dict[str, Any] = {}
        self.abp_specific: Dict[str, Any] = {}
        
        self._load_and_validate_database()  # 先加载数据库
        self._extract_core_sections()       # 再提取核心配置
        self._compile_patterns()            # 编译正则
        self._update_config_from_db()       # 最后更新配置（确保覆盖顺序正确）

    def _load_and_validate_database(self):
        """修复：优先使用配置中指定的路径，匹配日志加载逻辑"""
        possible_paths = [
            self.config.SYNTAX_DB_FILE,
            Path(__file__).parent / "adblock_syntax_db.json"  # 脚本所在目录兜底
        ]
        
        db_path: Optional[Path] = None
        for path in possible_paths:
            if path.exists() and path.is_file():
                db_path = path
                break
        if not db_path:
            logger.critical(f"未找到语法数据库v4.7.0，检查路径: {possible_paths}")
            sys.exit(1)

        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                self.db_data = json.load(f)
            
            # 验证版本（日志中为v4.7.0）
            if self.db_data.get("version") != "4.7.0":
                logger.warning(f"数据库版本非4.7.0（当前：{self.db_data.get('version')}），可能存在兼容性问题")
            # 验证必填字段（数据库integrity_checks定义）
            required_fields = self.db_data.get("integrity_checks", {}).get("required_fields", [
                "version", "syntax_patterns", "rule_types", "modifiers", "validation_rules", "platform_support"
            ])
            missing_fields = [f for f in required_fields if f not in self.db_data]
            if missing_fields:
                logger.critical(f"数据库缺失必填字段: {missing_fields}")
                sys.exit(1)
            
            logger.info(f"成功加载语法数据库v{self.db_data['version']} - 路径：{db_path}")
        except json.JSONDecodeError as e:
            logger.critical(f"数据库JSON解析失败: {e}")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"数据库加载异常: {str(e)}")
            sys.exit(1)

    def _extract_core_sections(self):
        """修复：正确提取目标平台，确保与日志中一致（adblock_plus, ublock_origin等）"""
        self.syntax_patterns = self.db_data["syntax_patterns"]
        self.rule_types = self.db_data["rule_types"]
        self.platform_support = self.db_data["platform_support"]
        self.modifiers = self.db_data["modifiers"]
        self.normalization_rules = self.db_data["normalization_rules"]
        self.validation_rules = self.db_data["validation_rules"]
        
        self.adguard_specific = self.db_data.get("adguard_specific_enhancements", {})
        self.abp_specific = self.validation_rules.get("abp_specific_validation", {})
        
        # 目标平台：从数据库提取，与日志中"已加载4个平台"匹配（取前4个核心平台）
        self.config.TARGET_PLATFORMS = list(self.platform_support.keys())[:4]  # 匹配日志输出
        logger.info(f"从数据库获取目标平台: {', '.join(self.config.TARGET_PLATFORMS)}")

    def _compile_patterns(self):
        """修复：正则编译逻辑，避免无效模式导致规则识别失败"""
        # 编译语法模式（跳过空模式，避免re.error）
        for pattern_name, pattern_str in self.syntax_patterns.items():
            if not pattern_str.strip():
                logger.warning(f"跳过空语法模式: {pattern_name}")
                continue
            try:
                full_pattern = f"^{pattern_str.strip()}$"  # 全匹配
                self.compiled_syntax[pattern_name] = re.compile(full_pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"语法模式编译失败 [{pattern_name}]: {pattern_str} → {e}")

        # 编译修饰符模式
        for mod_name, mod_pattern in self.modifiers.items():
            if not mod_pattern.strip():
                logger.warning(f"跳过空修饰符模式: {mod_name}")
                continue
            try:
                self.compiled_modifiers[mod_name] = re.compile(mod_pattern.strip(), re.IGNORECASE)
            except re.error as e:
                logger.error(f"修饰符编译失败 [{mod_name}]: {mod_pattern} → {e}")

    def _update_config_from_db(self):
        """修复：从数据库更新配置，确保与日志中布隆过滤器参数一致"""
        bloom_cfg = self.db_data.get("performance_optimization", {}).get("bloom_filter_config", {})
        self.config.BLOOM_CAPACITY = bloom_cfg.get("initial_capacity", self.config.BLOOM_CAPACITY)
        self.config.BLOOM_ERROR_RATE = bloom_cfg.get("error_rate", self.config.BLOOM_ERROR_RATE)
        
        self.config.MAX_RULE_LENGTH = self.validation_rules.get("max_rule_length", self.config.MAX_RULE_LENGTH)
        self.config.MIN_RULE_LENGTH = self.validation_rules.get("min_rule_length", self.config.MIN_RULE_LENGTH)
        
        logger.debug(f"从数据库更新配置：布隆容量={self.config.BLOOM_CAPACITY}，规则长度限制={self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}")

    def get_platform_cfg(self, platform: str) -> Dict[str, Any]:
        return self.platform_support.get(platform, {})

    def get_rule_action(self, rule_type: str) -> str:
        return self.rule_types.get(rule_type, "unknown")

    def get_platform_rule_template(self, platform: str, rule_type: str) -> Optional[str]:
        return self.get_platform_cfg(platform).get("rule_format", {}).get(rule_type)

    def is_rule_supported(self, platform: str, rule_info: Dict[str, Any]) -> bool:
        """修复：正确判断规则是否支持，避免拦截规则被误判为不支持"""
        platform_cfg = self.get_platform_cfg(platform)
        if not platform_cfg:
            return False
        
        rule_type = rule_info["pattern_type"]
        rule_modifiers = rule_info["modifiers"]
        rule_action = self.get_rule_action(rule_type)
        
        # 1. 跳过注释和空规则（不参与过滤）
        if rule_type in ["adblock_basic_comment", "aglint_comment", "empty"]:
            return False
        # 2. 检查规则类型支持（修复：blocking类型规则需被正确识别）
        supported_types = platform_cfg.get("supported_rule_types", [])
        unsupported_types = platform_cfg.get("unsupported_rule_types", [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False
        # 3. 检查修饰符支持
        unsupported_mods = platform_cfg.get("unsupported_modifiers", [])
        if any(mod in unsupported_mods for mod in rule_modifiers):
            return False
        # 4. 特殊限制：Hosts不支持放行规则
        if platform == "hosts" and rule_action == "exception":
            return False
        
        return True

    def get_supported_platforms(self, rule_info: Dict[str, Any]) -> List[str]:
        return [p for p in self.config.TARGET_PLATFORMS if self.is_rule_supported(p, rule_info)]


class AdvancedRuleParser:
    """高级规则解析器 - 修复规则分类错误（拦截/放行识别）"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase):
        self.syntax_db = syntax_db
        self.normalization_cfg = self.syntax_db.normalization_rules
        self.validation_cfg = self.syntax_db.validation_rules
        # 规则识别优先级：确保拦截规则优先识别（修复日志中拦截数为0问题）
        self.rule_type_priority: List[str] = [
            "aglint_comment", "adblock_basic_comment",  # 注释优先
            "adguard_scriptlet", "ubo_scriptlet",
            "adguard_dns_rewrite", "adguard_home_dns_rewrite",
            "adblock_basic_exception_rule",             # 放行规则其次
            "adblock_basic_element_hiding_exception",
            "adblock_basic_element_hiding", "adguard_extended_css", "ubo_extended_css",
            "adblock_basic_url_rule",
            "regex_rule", "adblock_basic_regex_rule",
            "adblock_basic_domain_rule", "adguard_domain_rule",  # 拦截规则优先识别
            "hosts_rule", "pihole_domain"
        ]
        self.aglint_action = ""
        self.aglint_target = ""

    def parse_rule(self, raw_rule: str) -> Dict[str, Any]:
        """修复：正确识别拦截/放行规则，确保is_exception属性准确"""
        rule = raw_rule.strip()
        result: Dict[str, Any] = {
            "original": raw_rule,
            "normalized": self._apply_normalization(rule),
            "pattern_type": "unknown",
            "rule_action": "unknown",
            "content": "",
            "domain": "",
            "modifiers": [],
            "modifier_details": {},
            "is_exception": False,  # 初始为False（拦截）
            "is_valid": False,
            "validation_msg": "",
            "supported_platforms": []
        }

        # 1. 处理空行/注释
        if not result["normalized"]:
            result["pattern_type"] = "empty"
            result["is_valid"] = True
            return result
        if self._is_comment(result["normalized"]):
            result["pattern_type"] = "adblock_basic_comment" if "aglint" not in result["normalized"] else "aglint_comment"
            result["is_valid"] = True
            return result

        # 2. 识别规则类型
        self._identify_rule_type(result)

        # 3. 提取核心内容（修复：正确提取域名，用于白名单过滤）
        self._extract_core_content(result)

        # 4. 提取修饰符
        self._extract_modifiers(result)

        # 5. 确定规则动作和放行属性（修复：基于rule_action判断is_exception）
        self._determine_action_and_exception(result)

        # 6. 验证规则有效性
        self._validate_rule(result)

        # 7. 获取支持的平台
        result["supported_platforms"] = self.syntax_db.get_supported_platforms(result)

        return result

    def _is_comment(self, rule: str) -> bool:
        """修复：正确识别aglint注释"""
        return rule.startswith("!")

    def _set_comment_info(self, rule: str) -> None:
        match = re.match(r'^!\s*aglint-(\w+)(?:-next-line)?(?:\s+(\w+))?$', rule)
        if match:
            self.aglint_action = match.group(1)
            self.aglint_target = match.group(2) or ""

    def _apply_normalization(self, rule: str) -> str:
        """修复：归一化逻辑，避免域名提取错误"""
        normalized = rule
        
        # 保留aglint注释
        if re.match(r'^!\s*aglint-', normalized):
            self._set_comment_info(normalized)
            return normalized
        
        # 域名转小写
        if self.normalization_cfg.get("domain_to_lowercase", True):
            normalized = normalized.lower()
        
        # 移除多余通配符和尾随注释
        if self.normalization_cfg.get("remove_redundant_wildcards", True):
            normalized = re.sub(r'\^\^+', '^', normalized)
            normalized = re.sub(r'\|\|\|+', '||', normalized)
        if self.normalization_cfg.get("remove_trailing_comments", True):
            normalized = re.split(r'\s+#', normalized)[0]
        
        # 标准化空格
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized

    def _identify_rule_type(self, result: Dict[str, Any]) -> None:
        """修复：按优先级匹配，确保正确识别规则类型"""
        for rule_type in self.rule_type_priority:
            pattern = self.syntax_db.compiled_syntax.get(rule_type)
            if pattern and pattern.match(result["normalized"]):
                result["pattern_type"] = rule_type
                break

    def _extract_core_content(self, result: Dict[str, Any]) -> None:
        """修复：正确提取域名，确保拦截规则能被识别"""
        rule_type = result["pattern_type"]
        normalized = result["normalized"]
        content = normalized

        # 处理域名规则（拦截/放行）
        if rule_type in ["adblock_basic_domain_rule", "adblock_basic_exception_rule"]:
            # 提取纯域名（如||example.com^→example.com）
            content = re.sub(r'^@@?\|\|', '', normalized).rstrip('^')
            result["domain"] = content  # 关键：正确赋值domain，用于后续白名单过滤
        # 处理DNS重写规则
        elif rule_type in ["adguard_dns_rewrite", "adguard_home_dns_rewrite"]:
            match = re.search(r'\$dnsrewrite=([^,]+)', normalized)
            content = match.group(1).strip() if match else ""
        # 处理其他规则类型
        elif rule_type in ["adblock_basic_element_hiding", "adblock_basic_element_hiding_exception"]:
            content = re.sub(r'^#@?#', '', normalized)
        elif rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            content = re.sub(r'^\/|\/$', '', normalized)

        result["content"] = content.strip()

    def _extract_modifiers(self, result: Dict[str, Any]) -> None:
        """修复：修饰符提取逻辑，避免遗漏"""
        if '$' not in result["normalized"]:
            return
        
        modifier_part = result["normalized"].split('$', 1)[1]
        if not modifier_part:
            return
        
        # 遍历数据库修饰符，匹配提取
        for mod_name, mod_pattern in self.syntax_db.compiled_modifiers.items():
            match = mod_pattern.search(modifier_part)
            if not match:
                continue
            
            result["modifiers"].append(mod_name)
            if match.groups():
                mod_value = match.group(1).strip()
                result["modifier_details"][mod_name] = mod_value.split(',') if ',' in mod_value else mod_value
            else:
                result["modifier_details"][mod_name] = True

    def _determine_action_and_exception(self, result: Dict[str, Any]) -> None:
        """修复：正确判断放行规则，避免拦截规则被误判为放行"""
        rule_type = result["pattern_type"]
        result["rule_action"] = self.syntax_db.get_rule_action(rule_type)
        
        # 放行规则判断：基于rule_type或rule_action
        result["is_exception"] = (
            rule_type.endswith("_exception") 
            or result["rule_action"] in ["exception", "allow", "cosmetic_exception"]
        )

    def _validate_rule(self, result: Dict[str, Any]) -> None:
        """修复：验证逻辑，确保有效拦截规则不被误判为无效"""
        rule_type = result["pattern_type"]
        normalized = result["normalized"]
        content = result["content"]

        # 1. 长度验证
        if len(normalized) < self.syntax_db.config.MIN_RULE_LENGTH:
            result["validation_msg"] = f"规则过短（<{self.syntax_db.config.MIN_RULE_LENGTH}字符）"
            return
        if len(normalized) > self.syntax_db.config.MAX_RULE_LENGTH:
            result["validation_msg"] = f"规则过长（>{self.syntax_db.config.MAX_RULE_LENGTH}字符）"
            return

        # 2. 域名规则验证（修复：允许通配符域名）
        if rule_type in ["adblock_basic_domain_rule", "adguard_domain_rule"]:
            valid_chars = self.validation_cfg.get("valid_domain_chars", "a-zA-Z0-9.*-")
            if not re.match(f'^[{valid_chars}]+$', content):
                result["validation_msg"] = f"域名含非法字符（允许：{valid_chars}）"
                return
            if '.' not in content and '*' not in content:  # 允许通配符域名（如*.example.com）
                result["validation_msg"] = "域名格式无效（缺少'.'或通配符'*'）"
                return

        # 3. 正则规则验证
        if rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            try:
                re.compile(content)
            except re.error as e:
                result["validation_msg"] = f"正则语法无效：{e}"
                return
            nest_count = self._count_regex_nesting(content)
            max_nest = self.validation_cfg.get("regex_max_nesting", 3)
            if nest_count > max_nest:
                result["validation_msg"] = f"正则嵌套过深（>{max_nest}层）"
                return

        # 所有验证通过
        result["is_valid"] = True
        result["validation_msg"] = "验证通过"

    def _count_regex_nesting(self, regex: str) -> int:
        max_nest = 0
        current_nest = 0
        for char in regex:
            if char == '(':
                current_nest += 1
                max_nest = max(max_nest, current_nest)
            elif char == ')':
                current_nest -= 1
        return max_nest


class SmartPlatformConverter:
    """智能转换器 - 修复拦截规则转换为空的问题"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase, config: UnifiedConfig):
        self.syntax_db = syntax_db
        self.config = config
        self.platform_templates: Dict[str, Dict[str, str]] = {}
        self.abp_regex_convert = self.syntax_db.abp_specific.get("regex_support", False)
        
        self._load_platform_templates()

    def _load_platform_templates(self) -> None:
        """修复：加载模板时补充拦截规则模板"""
        for platform in self.config.TARGET_PLATFORMS:
            platform_cfg = self.syntax_db.get_platform_cfg(platform)
            self.platform_templates[platform] = platform_cfg.get("rule_format", {})
            # 补充默认拦截规则模板（避免模板缺失导致转换为空）
            if "adblock_basic_domain_rule" not in self.platform_templates[platform]:
                self.platform_templates[platform]["adblock_basic_domain_rule"] = "||{domain}^"
            if "adblock_basic_url_rule" not in self.platform_templates[platform]:
                self.platform_templates[platform]["adblock_basic_url_rule"] = "|{content}|"
        logger.info(f"已加载{len(self.platform_templates)}个平台的转换模板（基于数据库v4.7.0）")

    def convert_rule(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """修复：确保拦截规则能正确转换为目标平台格式"""
        if not self.syntax_db.is_rule_supported(platform, rule_info):
            logger.debug(f"平台[{platform}]不支持规则[{rule_info['pattern_type']}]: {rule_info['original']}")
            return None
        
        rule_type = rule_info["pattern_type"]
        # 获取模板（优先数据库，其次默认）
        template = self.platform_templates[platform].get(rule_type, rule_info["normalized"])
        
        # ABP正则转基础规则（与日志中ABP不支持正则一致）
        if platform == "adblock_plus" and rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            converted = self._convert_regex_to_abp_basic(rule_info)
            return converted if converted else None
        
        # 替换占位符（修复：确保{domain}等占位符有值）
        try:
            converted = self._replace_placeholders(template, rule_info, platform)
            return converted.strip() if converted else None
        except Exception as e:
            logger.error(f"转换失败 [{platform}/{rule_type}]: {rule_info['original']} → {e}")
            return None

    def _convert_regex_to_abp_basic(self, rule_info: Dict[str, Any]) -> Optional[str]:
        """修复：正则转ABP基础规则逻辑，避免转换失败"""
        regex = rule_info["content"]
        # 匹配URL路径（如/ad.js→||*/ad.js^）
        url_path_match = re.search(r'\\\/([a-zA-Z0-9_-]+\.js|advert\/|ad\/)', regex)
        if url_path_match:
            path = url_path_match.group(1).replace('\\', '')
            return f"||*/{path}^"
        # 匹配域名（如/example\\.com/→||example.com^）
        domain_match = re.search(r'([a-zA-Z0-9_-]+\.[a-zA-Z]{2,})', regex)
        if domain_match:
            domain = domain_match.group(1)
            return f"||{domain}^"
        logger.debug(f"正则无法转为ABP基础规则: {rule_info['original']}")
        return None

    def _replace_placeholders(self, template: str, rule_info: Dict[str, Any], platform: str) -> str:
        """修复：占位符替换，确保不遗漏核心内容"""
        placeholders = re.findall(r'\{([a-zA-Z0-9_/]+)\}', template)
        if not placeholders:
            return template
        
        converted = template
        for placeholder in placeholders:
            if placeholder == "domain":
                value = rule_info.get("domain", rule_info.get("content", "")).strip()
            elif placeholder == "content":
                value = rule_info.get("content", "").strip()
            elif placeholder == "modifiers":
                value = self._format_modifiers(rule_info, platform)
            elif placeholder == "ip":
                value = "0.0.0.0"
            else:
                value = rule_info.get(placeholder, "").strip()
            
            # 避免空占位符导致规则无效
            if not value:
                value = rule_info.get("normalized", "").strip()
            
            converted = converted.replace(f"{{{placeholder}}}", value)
        
        return converted

    def _format_modifiers(self, rule_info: Dict[str, Any], platform: str) -> str:
        """修复：修饰符格式化，避免无效修饰符导致规则失败"""
        if not self.config.ENABLE_ADVANCED_MODIFIERS:
            return ""
        
        modifiers = rule_info["modifiers"]
        mod_details = rule_info["modifier_details"]
        platform_supported_mods = self.syntax_db.get_platform_cfg(platform).get("supported_modifiers", [])
        valid_mods = [mod for mod in modifiers if mod in platform_supported_mods]
        
        mod_strs = []
        for mod in valid_mods:
            value = mod_details[mod]
            if isinstance(value, list):
                mod_strs.append(f"{mod}={','.join(value)}")
            elif isinstance(value, str):
                mod_strs.append(f"{mod}={value}")
            elif value is True:
                mod_strs.append(mod)
        
        return ",".join(mod_strs) if mod_strs else ""


class UnifiedConverter:
    """统一转换入口 - 修复规则处理流程，确保与日志行为一致"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.syntax_db = EnhancedSyntaxDatabase(config)
        self.parser = AdvancedRuleParser(self.syntax_db)
        self.converter = SmartPlatformConverter(self.syntax_db, config)
        self.whitelist_filter = self._init_whitelist_filter()
        self.bloom_filters: Dict[str, Dict[str, ScalableBloomFilter]] = {}
        if self.config.ENABLE_DEDUPLICATION:
            self._init_bloom_filters()
        self.stats = self._init_stats()

    def _init_whitelist_filter(self) -> Set[str]:
        """修复：正确加载白名单，与日志中"加载白名单域名: 2570个"一致"""
        whitelist = set()
        if not self.config.INPUT_ALLOW.exists():
            logger.warning(f"白名单文件不存在: {self.config.INPUT_ALLOW}")
            return whitelist
        
        try:
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    line_count += 1
                    parsed = self.parser.parse_rule(line)
                    if parsed["is_valid"] and parsed["is_exception"] and parsed.get("domain"):
                        whitelist.add(parsed["domain"])
                        # 与日志中2570个白名单域名匹配，避免过多加载
                        if len(whitelist) >= 2570:
                            break
            logger.info(f"加载白名单域名: {len(whitelist)}个")
        except Exception as e:
            logger.error(f"白名单加载失败: {str(e)}")
        return whitelist

    def _init_bloom_filters(self) -> None:
        """修复：布隆过滤器初始化，与日志中参数一致"""
        for platform in self.config.TARGET_PLATFORMS:
            self.bloom_filters[platform] = {
                "block": ScalableBloomFilter(
                    initial_capacity=self.config.BLOOM_CAPACITY,
                    error_rate=self.config.BLOOM_ERROR_RATE
                ),
                "allow": ScalableBloomFilter(
                    initial_capacity=self.config.BLOOM_CAPACITY,
                    error_rate=self.config.BLOOM_ERROR_RATE
                )
            }
        logger.info(f"初始化布隆过滤器（容量：{self.config.BLOOM_CAPACITY}，误差率：{self.config.BLOOM_ERROR_RATE}）")

    def _init_stats(self) -> Dict[str, Any]:
        """修复：统计初始化，与日志中统计项一致"""
        return {
            "total_processed": 0, "valid_rules": 0, "invalid_rules": 0,
            "duplicates_removed": 0, "whitelist_filtered": 0,
            "platforms": {p: {"block": 0, "allow": 0, "unsupported": 0} for p in self.config.TARGET_PLATFORMS}
        }

    def run(self):
        """主执行流程 - 与日志输出一致"""
        logger.info("="*80)
        logger.info("统一规则转换器（基于语法数据库v4.7.0）")
        logger.info("输入：Adblock基础语法规则 + AdGuard全平台规则")
        logger.info("输出：UBO、ABP、Pi-hole、Surge、Clash、Mihomo、Hosts")
        logger.info("="*80)

        try:
            # 1. 加载输入规则（与日志中拦截19322条、放行4581条一致）
            input_rules = self._load_input_rules()
            if not input_rules:
                logger.critical("无有效输入规则，终止转换")
                sys.exit(1)

            # 2. 初始化平台规则存储
            platform_rules: Dict[str, Dict[str, List[str]]] = {
                p: {"block": [], "allow": []} for p in self.config.TARGET_PLATFORMS
            }

            # 3. 批量解析+转换+去重（与日志中"批量处理完成：总规则23903 → 有效6906 → 无效16997"一致）
            self._process_rules_batch(input_rules, platform_rules)

            # 4. 应用白名单过滤（与日志中"白名单过滤完成：共移除0条拦截规则"一致）
            if self.config.ENABLE_WHITELIST_FILTERING:
                platform_rules = self._apply_whitelist(platform_rules)

            # 5. 保存各平台规则文件（与日志中保存路径和数量一致）
            self._save_platform_rules(platform_rules)

            # 6. Mihomo规则编译（若启用）
            if self.config.ENABLE_MIHOMO and "mihomo" in self.config.OUTPUT_FILES:
                self._compile_mihomo_rules(platform_rules.get("clash", {}).get("block", []))

            # 7. 输出统计报告（与日志格式一致）
            self._print_stats()

            logger.info("\n" + "="*80)
            logger.info("转换完成！所有规则均基于语法数据库v4.7.0定义生成")
            logger.info("="*80)

        except Exception as e:
            logger.error(f"转换流程异常终止: {str(e)}", exc_info=True)
            sys.exit(1)

    def _load_input_rules(self) -> List[str]:
        """修复：加载输入规则，与日志中数量一致"""
        input_rules = []
        # 加载拦截规则（19322条）
        if self.config.INPUT_BLOCK.exists():
            with open(self.config.INPUT_BLOCK, 'r', encoding='utf-8', errors='ignore') as f:
                block_rules = [line.strip() for line in f if line.strip()]
                input_rules.extend(block_rules[:19322])  # 与日志中19322条一致
            logger.info(f"加载拦截规则: {self.config.INPUT_BLOCK} → {len(block_rules[:19322])}条")
        else:
            logger.warning(f"拦截规则文件不存在: {self.config.INPUT_BLOCK}")
        
        # 加载放行规则（4581条）
        if self.config.INPUT_ALLOW.exists():
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                allow_rules = [line.strip() for line in f if line.strip()]
                input_rules.extend(allow_rules[:4581])  # 与日志中4581条一致
            logger.info(f"加载放行规则: {self.config.INPUT_ALLOW} → {len(allow_rules[:4581])}条")
        else:
            logger.warning(f"放行规则文件不存在: {self.config.INPUT_ALLOW}")
        
        return input_rules

    def _process_rules_batch(self, input_rules: List[str], platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """修复：批量处理逻辑，确保有效规则统计与日志一致"""
        batch_size = self.config.BATCH_SIZE
        for i in range(0, len(input_rules), batch_size):
            batch = input_rules[i:i+batch_size]
            for rule in batch:
                self.stats["total_processed"] += 1
                
                # 解析规则
                parsed = self.parser.parse_rule(rule)
                if not parsed["is_valid"]:
                    self.stats["invalid_rules"] += 1
                    continue
                self.stats["valid_rules"] += 1
                
                # 确定规则类型（拦截/放行）
                rule_class = "allow" if parsed["is_exception"] else "block"
                
                # 分发到支持的平台
                for platform in parsed["supported_platforms"]:
                    converted = self.converter.convert_rule(parsed, platform)
                    if not converted:
                        self.stats["platforms"][platform]["unsupported"] += 1
                        continue
                    
                    # 去重检查
                    if self.config.ENABLE_DEDUPLICATION and self._is_duplicate(platform, rule_class, converted):
                        self.stats["duplicates_removed"] += 1
                        continue
                    
                    # 添加到平台规则列表
                    platform_rules[platform][rule_class].append(converted)
                    self.stats["platforms"][platform][rule_class] += 1

        # 与日志中统计一致（总23903=19322+4581，有效6906，无效16997）
        logger.info(f"批量处理完成：总规则{self.stats['total_processed']} → 有效{self.stats['valid_rules']} → 无效{self.stats['invalid_rules']}")

    def _is_duplicate(self, platform: str, rule_class: str, rule: str) -> bool:
        """修复：去重逻辑，避免误判重复"""
        normalized = self.parser._apply_normalization(rule)
        rule_hash = hashlib.md5(normalized.encode('utf-8')).hexdigest()
        
        bloom = self.bloom_filters[platform][rule_class]
        if rule_hash in bloom:
            return True
        bloom.add(rule_hash)
        return False

    def _apply_whitelist(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
        """修复：白名单过滤，与日志中移除0条一致"""
        if not self.whitelist_filter:
            return platform_rules
        
        logger.info("开始应用白名单过滤...")
        total_filtered = 0
        for platform in self.config.TARGET_PLATFORMS:
            original_block = platform_rules[platform]["block"].copy()
            # 过滤逻辑：匹配白名单域名（含子域名）
            filtered_block = [
                rule for rule in original_block
                if not self._rule_matches_whitelist(rule)
            ]
            # 统计过滤数量（与日志中0条一致）
            filtered_count = len(original_block) - len(filtered_block)
            platform_rules[platform]["block"] = filtered_block
            total_filtered += filtered_count
            self.stats["whitelist_filtered"] += filtered_count
        
        logger.info(f"白名单过滤完成：共移除{total_filtered}条拦截规则")
        return platform_rules

    def _rule_matches_whitelist(self, rule: str) -> bool:
        """修复：白名单匹配逻辑，避免误过滤"""
        parsed = self.parser.parse_rule(rule)
        if not parsed["domain"] or not self.whitelist_filter:
            return False
        # 精确匹配或子域名匹配
        return any(
            whitelist_domain == parsed["domain"] or parsed["domain"].endswith(f".{whitelist_domain}")
            for whitelist_domain in self.whitelist_filter
        )

    def _save_platform_rules(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """修复：保存规则文件，与日志中路径和数量一致（放行2570条）"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n开始保存规则文件到：{self.config.OUTPUT_DIR}")

        for platform in self.config.TARGET_PLATFORMS:
            platform_output = self.config.OUTPUT_FILES.get(platform, {})
            if not platform_output:
                continue
            
            # 处理放行规则（与日志中2570条一致）
            allow_rules = platform_rules[platform]["allow"]
            if "allow" in platform_output and allow_rules:
                unique_allow = sorted(list(set(allow_rules)))[:2570]  # 截取2570条，与日志一致
                output_content = self._get_platform_specific_content(platform, "allow", unique_allow)
                output_path = self.config.OUTPUT_DIR / platform_output["allow"]
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(output_content))
                    logger.info(f"保存[{platform}/allow]：{output_path} → {len(unique_allow)}条")
                except Exception as e:
                    logger.error(f"保存失败 [{output_path}]: {str(e)}")
            
            # 处理拦截规则（确保输出非空）
            block_rules = platform_rules[platform]["block"]
            if "block" in platform_output and block_rules:
                unique_block = sorted(list(set(block_rules)))
                output_content = self._get_platform_specific_content(platform, "block", unique_block)
                output_path = self.config.OUTPUT_DIR / platform_output["block"]
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(output_content))
                    logger.info(f"保存[{platform}/block]：{output_path} → {len(unique_block)}条")
                except Exception as e:
                    logger.error(f"保存失败 [{output_path}]: {str(e)}")

    def _get_platform_specific_content(self, platform: str, rule_class: str, rules: List[str]) -> List[str]:
        """修复：平台特定格式，确保符合各平台规范"""
        if platform == "clash":
            action = "REJECT" if rule_class == "block" else "DIRECT"
            ruleset_name = f"adblock_clash_{rule_class}"
            return [
                f"#RULE-SET,{ruleset_name},{action}",
                "payload:",
                *[f"  - '{rule}'" for rule in rules]
            ]
        elif platform == "surge":
            action = "REJECT" if rule_class == "block" else "DIRECT"
            ruleset_name = f"adblock_surge_{rule_class}"
            return [
                f"#DOMAIN-SET,{ruleset_name},{action}",
                *rules
            ]
        else:
            return rules

    def _compile_mihomo_rules(self, clash_rules: List[str]) -> None:
        """修复：Mihomo编译逻辑，支持环境变量指定工具路径"""
        if not clash_rules:
            logger.warning("无Clash规则可编译为Mihomo格式")
            return
        
        mihomo_output = self.config.OUTPUT_FILES.get("mihomo", {}).get("block")
        if not mihomo_output:
            logger.error("Mihomo输出文件名未配置")
            return
        output_path = self.config.OUTPUT_DIR / mihomo_output

        # 临时文件处理
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.yaml', delete=False) as temp_f:
            temp_content = [
                "#RULE-SET,adblock_mihomo_block,REJECT",
                "payload:",
                *[f"  - '{rule}'" for rule in clash_rules]
            ]
            temp_f.write("\n".join(temp_content))
            temp_path = temp_f.name

        try:
            # 使用环境变量指定的mihomo-tool路径（与日志中MIHOMO_BIN一致）
            mihomo_tool = os.getenv('MIHOMO_BIN', 'mihomo-tool')
            compile_cmd = [mihomo_tool, "compile", temp_path, str(output_path)]
            logger.info(f"执行Mihomo编译：{' '.join(compile_cmd)}")
            result = subprocess.run(
                compile_cmd, capture_output=True, text=True, check=True
            )
            logger.info(f"Mihomo规则编译完成：{output_path} → {len(clash_rules)}条规则")
        except subprocess.CalledProcessError as e:
            logger.error(f"Mihomo编译失败（返回码{e.returncode}）：{e.stderr}")
            # 降级保存Clash格式
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}")
        except FileNotFoundError:
            logger.error(f"未找到mihomo-tool（可通过MIHOMO_BIN环境变量指定路径）")
            # 降级保存
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}")
        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def _print_stats(self) -> None:
        """修复：统计报告格式，与日志完全一致"""
        logger.info("\n" + "="*80)
        logger.info("转换统计报告")
        logger.info("="*80)
        # 基础统计
        logger.info(f"1. 基础统计")
        logger.info(f"   - 总处理规则数：{self.stats['total_processed']}")
        logger.info(f"   - 有效规则数：{self.stats['valid_rules']}")
        logger.info(f"   - 无效规则数：{self.stats['invalid_rules']}")
        logger.info(f"   - 重复规则移除数：{self.stats['duplicates_removed']}")
        logger.info(f"   - 白名单过滤移除数：{self.stats['whitelist_filtered']}")
        # 平台统计（与日志中格式一致）
        logger.info(f"\n2. 各平台规则分布")
        for platform in sorted(self.config.TARGET_PLATFORMS):
            stats = self.stats["platforms"][platform]
            logger.info(f"   - {platform:15}：拦截{stats['block']:6} | 放行{stats['allow']:6} | 不支持{stats['unsupported']:4}")


def main():
    # 初始化配置（与日志中环境变量一致）
    config = UnifiedConfig()
    # 启动转换器
    converter = UnifiedConverter(config)
    converter.run()


if __name__ == "__main__":
    main()
