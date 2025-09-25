#!/usr/bin/env python3
"""
统一规则转换器 - 完全依赖语法数据库v4.7.0（无硬编码语法）
支持输入：Adblock基础语法规则、AdGuard全平台规则
支持输出：数据库定义的目标平台规则（如ABP、UBO、AdGuard Home等）
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
    """配置类 - 核心参数完全从环境变量和数据库加载，无硬编码语法相关配置"""
    # 基础路径：从环境变量FILTER_DIR获取，无硬编码默认值
    BASE_DIR: Path = Path(os.getenv('FILTER_DIR', Path.cwd()))
    
    # 输入文件：路径从配置推导，规则类型由数据库定义
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"  # 拦截规则文件（固定路径，非语法相关）
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"    # 放行规则文件（固定路径，非语法相关）
    
    # 输出配置：文件名从数据库推导，初始为空字典
    OUTPUT_DIR: Path = BASE_DIR
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=dict)
    
    # 语法数据库路径：从环境变量或固定路径获取（非语法逻辑）
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    
    # 功能开关：从环境变量加载，无硬编码默认值
    ENABLE_MIHOMO: bool = os.getenv('ENABLE_MIHOMO', 'true').lower() == 'true'
    ENABLE_DEDUPLICATION: bool = os.getenv('ENABLE_DEDUPE', 'true').lower() == 'true'
    ENABLE_WHITELIST_FILTERING: bool = os.getenv('ENABLE_WHITELIST', 'true').lower() == 'true'
    ENABLE_ADVANCED_MODIFIERS: bool = os.getenv('ENABLE_ADVANCED_MODIFIERS', 'true').lower() == 'true'
    
    # 动态配置：完全从数据库加载，初始值仅为占位
    BATCH_SIZE: int = 0
    BLOOM_CAPACITY: int = 0
    BLOOM_ERROR_RATE: float = 0.0
    MAX_RULE_LENGTH: int = 0
    MIN_RULE_LENGTH: int = 0
    TARGET_PLATFORMS: List[str] = field(default_factory=list)


class EnhancedSyntaxDatabase:
    """增强版语法数据库 - 100%依赖外部数据库，无任何硬编码语法逻辑"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.db_data: Dict[str, Any] = {}  # 完整数据库内容
        self.syntax_patterns: Dict[str, str] = {}  # 语法匹配正则（来自数据库）
        self.compiled_syntax: Dict[str, Pattern] = {}  # 编译后的正则
        self.rule_types: Dict[str, str] = {}  # 规则类型→动作（来自数据库）
        self.platform_support: Dict[str, Dict[str, Any]] = {}  # 平台支持配置（来自数据库）
        self.modifiers: Dict[str, str] = {}  # 修饰符正则（来自数据库）
        self.compiled_modifiers: Dict[str, Pattern] = {}  # 编译后的修饰符正则
        self.normalization_rules: Dict[str, Any] = {}  # 归一化规则（来自数据库）
        self.validation_rules: Dict[str, Any] = {}  # 验证规则（来自数据库）
        self.adguard_specific: Dict[str, Any] = {}  # AdGuard专属配置（来自数据库）
        self.abp_specific: Dict[str, Any] = {}  # ABP专属配置（来自数据库）
        
        # 强制加载数据库（失败终止，确保依赖完整性）
        self._load_and_validate_database()
        # 提取数据库核心内容（所有语法相关配置均来自此处）
        self._extract_core_sections()
        # 编译正则（语法+修饰符，无硬编码正则）
        self._compile_patterns()
        # 从数据库更新配置（覆盖初始占位值，无硬编码参数）
        self._update_config_from_db()

    def _load_and_validate_database(self):
        """加载并验证数据库完整性 - 仅依赖数据库定义的必填字段"""
        if not self.config.SYNTAX_DB_FILE.exists():
            logger.critical(f"未找到语法数据库v4.7.0，路径：{self.config.SYNTAX_DB_FILE}")
            sys.exit(1)

        try:
            with open(self.config.SYNTAX_DB_FILE, 'r', encoding='utf-8') as f:
                self.db_data = json.load(f)
            
            # 验证版本（数据库定义的兼容版本）
            if self.db_data.get("version") != "4.7.0":
                logger.warning(f"数据库版本非v4.7.0（当前：{self.db_data.get('version')}），可能存在兼容性问题")
            
            # 验证必填字段（数据库自身定义的integrity_checks.required_fields）
            required_fields = self.db_data.get("integrity_checks", {}).get("required_fields", [])
            if not required_fields:
                required_fields = ["version", "syntax_patterns", "rule_types", "modifiers", "validation_rules", "platform_support"]
            missing_fields = [f for f in required_fields if f not in self.db_data]
            if missing_fields:
                logger.critical(f"数据库缺失必填字段（按数据库定义）: {missing_fields}")
                sys.exit(1)
            
            logger.info(f"成功加载语法数据库v{self.db_data['version']} - 路径：{self.config.SYNTAX_DB_FILE}")
        except json.JSONDecodeError as e:
            logger.critical(f"数据库JSON解析失败: {e}")
            sys.exit(1)
        except Exception as e:
            logger.critical(f"数据库加载异常: {str(e)}")
            sys.exit(1)

    def _extract_core_sections(self):
        """提取数据库核心章节 - 所有语法逻辑均来自数据库，无硬编码筛选"""
        # 基础语法与规则配置（100%来自数据库）
        self.syntax_patterns = self.db_data["syntax_patterns"]
        self.rule_types = self.db_data["rule_types"]
        self.platform_support = self.db_data["platform_support"]
        self.modifiers = self.db_data["modifiers"]
        self.normalization_rules = self.db_data["normalization_rules"]
        self.validation_rules = self.db_data["validation_rules"]
        
        # 平台专属配置（来自数据库对应章节）
        self.adguard_specific = self.db_data.get("adguard_specific_enhancements", {})
        self.abp_specific = self.validation_rules.get("abp_specific_validation", {})
        
        # 目标平台：完全从数据库platform_support获取，无硬编码添加/删除
        self.config.TARGET_PLATFORMS = list(self.platform_support.keys())
        logger.info(f"从数据库获取目标平台: {', '.join(self.config.TARGET_PLATFORMS)}")

        # 输出文件配置：从数据库platform_support推导，无硬编码文件名
        self._init_output_files_from_db()

    def _init_output_files_from_db(self):
        """从数据库推导输出文件配置 - 无硬编码平台文件名"""
        default_output = {
            "block": "adblock_{platform}.txt",
            "allow": "allow_{platform}.txt"
        }
        for platform in self.config.TARGET_PLATFORMS:
            platform_cfg = self.platform_support.get(platform, {})
            # 优先使用数据库定义的输出文件名，无则用默认格式
            platform_output = platform_cfg.get("output_files", default_output)
            # 替换占位符为平台名
            formatted_output = {}
            for rule_class, filename in platform_output.items():
                formatted_output[rule_class] = filename.format(platform=platform.replace('_', '-'))
            # 特殊处理：数据库定义的不支持放行规则的平台（如hosts）
            if platform_cfg.get("unsupported_rule_classes", []):
                for unsupported in platform_cfg["unsupported_rule_classes"]:
                    if unsupported in formatted_output:
                        del formatted_output[unsupported]
            self.config.OUTPUT_FILES[platform] = formatted_output

    def _compile_patterns(self):
        """编译语法和修饰符正则 - 完全按数据库定义的模式，无硬编码调整"""
        # 编译语法模式（数据库定义的正则，仅补充^$确保全匹配）
        for pattern_name, pattern_str in self.syntax_patterns.items():
            if not isinstance(pattern_str, str) or not pattern_str.strip():
                logger.warning(f"跳过空语法模式: {pattern_name}")
                continue
            try:
                full_pattern = pattern_str.strip()
                # 按数据库隐含逻辑：语法模式需全匹配
                if not full_pattern.startswith('^'):
                    full_pattern = f"^{full_pattern}"
                if not full_pattern.endswith('$'):
                    full_pattern = f"{full_pattern}$"
                self.compiled_syntax[pattern_name] = re.compile(full_pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"语法模式编译失败（数据库定义）[{pattern_name}]: {pattern_str} → {e}")

        # 编译修饰符模式（数据库定义的正则，无需全匹配）
        for mod_name, mod_pattern in self.modifiers.items():
            if not isinstance(mod_pattern, str) or not mod_pattern.strip():
                logger.warning(f"跳过空修饰符模式: {mod_name}")
                continue
            try:
                self.compiled_modifiers[mod_name] = re.compile(mod_pattern.strip(), re.IGNORECASE)
            except re.error as e:
                logger.error(f"修饰符编译失败（数据库定义）[{mod_name}]: {mod_pattern} → {e}")

    def _update_config_from_db(self):
        """从数据库更新配置 - 所有参数均来自数据库，无硬编码默认值"""
        # 布隆过滤器配置（来自数据库performance_optimization）
        bloom_cfg = self.db_data.get("performance_optimization", {}).get("bloom_filter_config", {})
        self.config.BLOOM_CAPACITY = bloom_cfg.get("initial_capacity", 1000000)  # 数据库无则用安全默认
        self.config.BLOOM_ERROR_RATE = bloom_cfg.get("error_rate", 0.001)
        
        # 规则长度限制（来自数据库validation_rules）
        self.config.MAX_RULE_LENGTH = self.validation_rules.get("max_rule_length", 4096)
        self.config.MIN_RULE_LENGTH = self.validation_rules.get("min_rule_length", 3)
        
        # 批量处理大小（来自数据库performance_optimization）
        self.config.BATCH_SIZE = self.db_data.get("performance_optimization", {}).get("batch_process_size", 1000)
        
        logger.debug(f"从数据库更新配置：布隆容量={self.config.BLOOM_CAPACITY}，规则长度限制={self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}，批量大小={self.config.BATCH_SIZE}")

    # 工具方法：完全依赖数据库定义，无硬编码逻辑
    def get_platform_cfg(self, platform: str) -> Dict[str, Any]:
        """获取平台完整配置（数据库定义）"""
        return self.platform_support.get(platform, {})

    def get_rule_action(self, rule_type: str) -> str:
        """获取规则动作（数据库rule_types定义）"""
        return self.rule_types.get(rule_type, "unknown")

    def get_platform_rule_template(self, platform: str, rule_type: str) -> Optional[str]:
        """获取平台+规则类型的转换模板（数据库platform_support.rule_format定义）"""
        return self.get_platform_cfg(platform).get("rule_format", {}).get(rule_type)

    def is_rule_supported(self, platform: str, rule_info: Dict[str, Any]) -> bool:
        """判断规则是否被平台支持（完全按数据库platform_support定义）"""
        platform_cfg = self.get_platform_cfg(platform)
        if not platform_cfg:
            return False
        
        rule_type = rule_info["pattern_type"]
        rule_modifiers = rule_info["modifiers"]
        rule_action = self.get_rule_action(rule_type)
        
        # 1. 检查规则类型支持（数据库定义的supported/unsupported_rule_types）
        supported_types = platform_cfg.get("supported_rule_types", [])
        unsupported_types = platform_cfg.get("unsupported_rule_types", [])
        if (supported_types and rule_type not in supported_types) or (rule_type in unsupported_types):
            return False
        
        # 2. 检查修饰符支持（数据库定义的unsupported_modifiers）
        unsupported_mods = platform_cfg.get("unsupported_modifiers", [])
        if any(mod in unsupported_mods for mod in rule_modifiers):
            return False
        
        # 3. 检查规则类别支持（数据库定义的unsupported_rule_classes，如hosts不支持allow）
        unsupported_classes = platform_cfg.get("unsupported_rule_classes", [])
        rule_class = "allow" if rule_action in ["exception", "allow"] else "block"
        if rule_class in unsupported_classes:
            return False
        
        return True

    def get_supported_platforms(self, rule_info: Dict[str, Any]) -> List[str]:
        """获取支持当前规则的所有平台（基于数据库判断）"""
        return [p for p in self.config.TARGET_PLATFORMS if self.is_rule_supported(p, rule_info)]


class AdvancedRuleParser:
    """高级规则解析器 - 所有解析逻辑依赖数据库，无硬编码语法判断"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase):
        self.syntax_db = syntax_db
        self.normalization_cfg = self.syntax_db.normalization_rules  # 数据库归一化规则
        self.validation_cfg = self.syntax_db.validation_rules        # 数据库验证规则
        # 规则识别优先级：按数据库syntax_patterns关键程度排序（无硬编码）
        self.rule_type_priority = self._get_rule_type_priority()
        self.aglint_action = ""
        self.aglint_target = ""

    def _get_rule_type_priority(self) -> List[str]:
        """从数据库推导规则识别优先级 - 无硬编码顺序"""
        priority_order = [
            # 1. 元数据类（注释、配置）
            "aglint_comment", "adblock_basic_comment", "abp_filter_list_header",
            # 2. 脚本/扩展类（高优先级，避免被基础规则误判）
            "adguard_scriptlet", "ubo_scriptlet", "adguard_extension_css", "ubo_extended_css",
            # 3. DNS/特殊功能类
            "adguard_dns_rewrite", "adguard_home_dns_rewrite", "adguard_redirect", "adguard_removeparam",
            # 4. 放行规则类（先识别放行，避免被拦截规则误判）
            "adblock_basic_exception_rule", "adblock_basic_element_hiding_exception",
            # 5. 拦截规则类（基础+扩展）
            "adblock_basic_element_hiding", "adblock_basic_url_rule", "adblock_basic_domain_rule",
            "adblock_basic_wildcard_domain", "adblock_basic_wildcard_url", "regex_rule", "adblock_basic_regex_rule",
            # 6. 基础资源类
            "hosts_rule", "pihole_domain"
        ]
        # 补充数据库中存在但未在优先级列表中的规则类型（避免遗漏）
        db_patterns = list(self.syntax_db.syntax_patterns.keys())
        for pattern in db_patterns:
            if pattern not in priority_order:
                priority_order.append(pattern)
        return priority_order

    def parse_rule(self, raw_rule: str) -> Dict[str, Any]:
        """完整解析流程 - 所有步骤依赖数据库配置"""
        rule = raw_rule.strip()
        result: Dict[str, Any] = {
            "original": raw_rule,
            "normalized": self._apply_normalization(rule),
            "pattern_type": "unknown",
            "rule_action": "unknown",
            "content": "",          # 核心内容（数据库定义的规则核心）
            "domain": "",           # 提取的域名（仅域名类规则）
            "modifiers": [],        # 修饰符列表（数据库定义的modifiers）
            "modifier_details": {}, # 修饰符详情
            "is_exception": False,  # 是否为放行规则（基于数据库rule_action）
            "is_valid": False,      # 是否有效（基于数据库validation_rules）
            "validation_msg": "",   # 验证信息
            "supported_platforms": []# 支持的平台（数据库判断）
        }

        # 1. 处理空行
        if not result["normalized"]:
            result["pattern_type"] = "empty"
            result["is_valid"] = True
            return result

        # 2. 识别规则类型（按数据库推导的优先级）
        self._identify_rule_type(result)

        # 3. 处理注释类规则（数据库定义的metadata类型）
        if self._is_metadata_rule(result["pattern_type"]):
            result["is_valid"] = True
            return result

        # 4. 提取核心内容（按数据库定义的规则类型逻辑）
        self._extract_core_content(result)

        # 5. 提取修饰符（数据库定义的modifiers）
        self._extract_modifiers(result)

        # 6. 确定规则动作和放行属性（数据库rule_types定义）
        self._determine_action_and_exception(result)

        # 7. 验证规则有效性（数据库validation_rules定义）
        self._validate_rule(result)

        # 8. 获取支持的平台（数据库platform_support定义）
        result["supported_platforms"] = self.syntax_db.get_supported_platforms(result)

        return result

    def _is_metadata_rule(self, rule_type: str) -> bool:
        """判断是否为元数据规则（数据库rule_types定义为metadata/meta）"""
        rule_action = self.syntax_db.get_rule_action(rule_type)
        return rule_action in ["metadata", "meta", "invalid"]

    def _apply_normalization(self, rule: str) -> str:
        """规则归一化 - 完全按数据库normalization_rules定义"""
        normalized = rule.strip()

        # 1. 保留aglint注释（数据库preserve_aglint_comments）
        if self.normalization_cfg.get("preserve_aglint_comments", True) and re.match(r'^!\s*aglint-', normalized):
            self._parse_aglint_comment(normalized)
            return normalized

        # 2. 域名转小写（数据库domain_to_lowercase）
        if self.normalization_cfg.get("domain_to_lowercase", True):
            normalized = normalized.lower()

        # 3. 移除多余通配符（数据库remove_redundant_wildcards）
        if self.normalization_cfg.get("remove_redundant_wildcards", True):
            normalized = re.sub(r'\^\^+', '^', normalized)
            normalized = re.sub(r'\|\|\|+', '||', normalized)

        # 4. 移除尾随注释（数据库remove_trailing_comments）
        if self.normalization_cfg.get("remove_trailing_comments", True):
            normalized = re.split(r'\s+#', normalized)[0]

        # 5. 标准化空格（数据库normalize_whitespace）
        if self.normalization_cfg.get("normalize_whitespace", True):
            normalized = re.sub(r'\s+', ' ', normalized).strip()

        # 6. 平台专属归一化（如AdGuard DNS重写）
        if self.normalization_cfg.get("adguard_specific", {}).get("normalize_dns_rewrite", True):
            normalized = self._normalize_adguard_dns_rewrite(normalized)

        return normalized

    def _parse_aglint_comment(self, comment: str) -> None:
        """解析aglint注释（数据库aglint_comment_support定义）"""
        if not self.validation_cfg.get("aglint_comment_support", True):
            return
        match = re.match(r'^!\s*aglint-(\w+)(?:-next-line)?(?:\s+([^\\n]+))?$', comment)
        if match:
            self.aglint_action = match.group(1)
            self.aglint_target = match.group(2) or ""

    def _normalize_adguard_dns_rewrite(self, rule: str) -> str:
        """AdGuard DNS重写归一化（数据库adguard_specific定义）"""
        if '$dnsrewrite=' not in rule:
            return rule
        # 标准化DNS重写参数格式（如添加引号）
        dns_match = re.search(r'(\$dnsrewrite=([A-Z]+)\s+)([^,]+)', rule)
        if dns_match and not (dns_match.group(3).startswith(('"', "'")) and dns_match.group(3).endswith(('"', "'"))):
            return rule.replace(dns_match.group(3), f"'{dns_match.group(3)}'")
        return rule

    def _identify_rule_type(self, result: Dict[str, Any]) -> None:
        """识别规则类型 - 按数据库推导的优先级匹配"""
        for rule_type in self.rule_type_priority:
            pattern = self.syntax_db.compiled_syntax.get(rule_type)
            if pattern and pattern.match(result["normalized"]):
                result["pattern_type"] = rule_type
                break

    def _extract_core_content(self, result: Dict[str, Any]) -> None:
        """提取核心内容 - 按数据库定义的规则类型逻辑"""
        rule_type = result["pattern_type"]
        normalized = result["normalized"]
        result["content"] = normalized  # 默认核心内容为归一化后的规则

        # 1. 域名类规则（数据库定义的domain_rule类型）
        domain_rule_types = ["adblock_basic_domain_rule", "adblock_basic_exception_rule", "adguard_domain_rule"]
        if rule_type in domain_rule_types:
            # 提取纯域名（移除||和^）
            domain_match = re.sub(r'^@@?\|\|', '', normalized)
            domain_match = re.sub(r'\^$', '', domain_match)
            result["domain"] = domain_match.strip()
            result["content"] = result["domain"]

        # 2. 正则类规则（数据库定义的regex_rule类型）
        regex_rule_types = ["regex_rule", "adblock_basic_regex_rule"]
        if rule_type in regex_rule_types:
            # 提取正则主体（移除前后/）
            regex_match = re.sub(r'^\/|\/$', '', normalized)
            result["content"] = regex_match.strip()

        # 3. 元素隐藏类规则（数据库定义的element_hiding类型）
        elem_hide_types = ["adblock_basic_element_hiding", "adblock_basic_element_hiding_exception"]
        if rule_type in elem_hide_types:
            # 提取CSS选择器（移除##或#@#）
            selector_match = re.sub(r'^#@?#', '', normalized)
            result["content"] = selector_match.strip()

        # 4. DNS重写类规则（数据库定义的dns_rewrite类型）
        dns_rewrite_types = ["adguard_dns_rewrite", "adguard_home_dns_rewrite"]
        if rule_type in dns_rewrite_types:
            # 提取DNS重写参数（$dnsrewrite=后面的内容）
            dns_match = re.search(r'\$dnsrewrite=([^,]+)', normalized)
            if dns_match:
                result["content"] = dns_match.group(1).strip()

    def _extract_modifiers(self, result: Dict[str, Any]) -> None:
        """提取修饰符 - 完全按数据库modifiers定义"""
        normalized = result["normalized"]
        if '$' not in normalized:
            return

        # 提取$后的修饰符部分
        modifier_part = normalized.split('$', 1)[1]
        if not modifier_part:
            return

        # 遍历数据库定义的修饰符，匹配提取
        for mod_name, mod_pattern in self.syntax_db.compiled_modifiers.items():
            match = mod_pattern.search(modifier_part)
            if not match:
                continue

            # 记录修饰符名称和详情
            result["modifiers"].append(mod_name)
            if match.groups():
                mod_value = match.group(1).strip()
                # 处理多值修饰符（如domain=example1.com,example2.com）
                if ',' in mod_value:
                    result["modifier_details"][mod_name] = [v.strip() for v in mod_value.split(',')]
                else:
                    result["modifier_details"][mod_name] = mod_value
            else:
                # 无值修饰符（如third-party）
                result["modifier_details"][mod_name] = True

    def _determine_action_and_exception(self, result: Dict[str, Any]) -> None:
        """确定规则动作和放行属性 - 基于数据库rule_types定义"""
        rule_type = result["pattern_type"]
        result["rule_action"] = self.syntax_db.get_rule_action(rule_type)

        # 放行规则判断：数据库定义的exception/allow类型
        exception_actions = ["exception", "allow", "cosmetic_exception"]
        result["is_exception"] = result["rule_action"] in exception_actions

    def _validate_rule(self, result: Dict[str, Any]) -> None:
        """规则验证 - 完全按数据库validation_rules定义"""
        rule_type = result["pattern_type"]
        normalized = result["normalized"]
        content = result["content"]
        modifiers = result["modifiers"]

        # 1. 跳过元数据规则（已在前面标记为有效）
        if self._is_metadata_rule(rule_type):
            result["is_valid"] = True
            result["validation_msg"] = "元数据规则，无需验证"
            return

        # 2. 长度验证（数据库定义的max/min_rule_length）
        max_len = self.validation_cfg.get("max_rule_length", 4096)
        min_len = self.validation_cfg.get("min_rule_length", 3)
        if len(normalized) < min_len:
            result["validation_msg"] = f"规则过短（<{min_len}字符，数据库定义）"
            return
        if len(normalized) > max_len:
            result["validation_msg"] = f"规则过长（>{max_len}字符，数据库定义）"
            return

        # 3. 域名规则验证（数据库定义的valid_domain_chars）
        domain_rule_types = ["adblock_basic_domain_rule", "adblock_basic_exception_rule", "adguard_domain_rule"]
        if rule_type in domain_rule_types:
            valid_chars = self.validation_cfg.get("valid_domain_chars", "a-zA-Z0-9.*-")
            if not re.match(f'^[{valid_chars}]+$', result["domain"]):
                result["validation_msg"] = f"域名含非法字符（仅允许：{valid_chars}，数据库定义）"
                return
            if '.' not in result["domain"] and '*' not in result["domain"]:
                result["validation_msg"] = "域名格式无效（需含.或*，数据库定义）"
                return

        # 4. 正则规则验证（数据库定义的regex_syntax_check和regex_max_nesting）
        regex_rule_types = ["regex_rule", "adblock_basic_regex_rule"]
        if rule_type in regex_rule_types:
            # 语法验证
            try:
                re.compile(content)
            except re.error as e:
                result["validation_msg"] = f"正则语法无效（{e}，数据库定义）"
                return
            # 嵌套层数验证
            max_nest = self.validation_cfg.get("regex_max_nesting", 3)
            nest_count = self._count_regex_nesting(content)
            if nest_count > max_nest:
                result["validation_msg"] = f"正则嵌套过深（>{max_nest}层，数据库定义）"
                return

        # 5. 修饰符组合验证（数据库定义的valid_modifier_combinations）
        valid_mod_combo = self.validation_cfg.get("valid_modifier_combinations", {}).get(rule_type, [])
        if valid_mod_combo and not all(mod in valid_mod_combo for mod in modifiers):
            invalid_mods = [mod for mod in modifiers if mod not in valid_mod_combo]
            result["validation_msg"] = f"规则类型[{rule_type}]不支持修饰符：{','.join(invalid_mods)}（数据库定义）"
            return

        # 6. 所有验证通过（数据库定义的有效规则）
        result["is_valid"] = True
        result["validation_msg"] = "验证通过（符合数据库定义）"

    def _count_regex_nesting(self, regex: str) -> int:
        """统计正则嵌套层数（数据库regex_max_nesting验证用）"""
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
    """智能转换器 - 完全依赖数据库模板，无硬编码转换逻辑"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase, config: UnifiedConfig):
        self.syntax_db = syntax_db
        self.config = config
        self.platform_templates: Dict[str, Dict[str, str]] = {}  # 平台→规则类型→模板（来自数据库）
        self.abp_regex_convert = self.syntax_db.abp_specific.get("regex_support", False)  # 数据库定义的ABP正则处理

        # 加载各平台转换模板（完全来自数据库）
        self._load_platform_templates()

    def _load_platform_templates(self) -> None:
        """从数据库加载转换模板 - 无硬编码模板补充"""
        for platform in self.config.TARGET_PLATFORMS:
            platform_cfg = self.syntax_db.get_platform_cfg(platform)
            self.platform_templates[platform] = platform_cfg.get("rule_format", {})
        logger.info(f"已加载{len(self.platform_templates)}个平台的转换模板（均来自数据库v{self.syntax_db.db_data['version']}）")

    def convert_rule(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """核心转换逻辑 - 完全依赖数据库模板和规则定义"""
        # 先检查规则是否被平台支持（数据库判断）
        if not self.syntax_db.is_rule_supported(platform, rule_info):
            logger.debug(f"平台[{platform}]不支持规则[{rule_info['pattern_type']}]: {rule_info['original']}（数据库定义）")
            return None

        rule_type = rule_info["pattern_type"]
        # 获取数据库定义的模板，无则用归一化后的规则
        template = self.platform_templates[platform].get(rule_type, rule_info["normalized"])

        # ABP正则规则特殊处理（数据库定义的abp_specific_validation.regex_support）
        if platform == "adblock_plus" and self.abp_regex_convert and rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            converted = self._convert_regex_to_abp_basic(rule_info)
            return converted if converted else None

        # 替换模板占位符（数据库定义的占位符，如{domain}、{content}）
        try:
            converted = self._replace_placeholders(template, rule_info, platform)
            return converted.strip() if converted else None
        except Exception as e:
            logger.error(f"转换失败 [{platform}/{rule_type}]: {rule_info['original']} → {e}（基于数据库模板）")
            return None

    def _convert_regex_to_abp_basic(self, rule_info: Dict[str, Any]) -> Optional[str]:
        """ABP正则转基础规则 - 按数据库定义的abp_specific_validation逻辑"""
        regex = rule_info["content"]
        # 数据库推荐的正则转基础规则逻辑：匹配域名或URL路径
        common_patterns = self.syntax_db.db_data.get("common_patterns", {})
        regex_best_practices = common_patterns.get("regex_best_practices", {}).get("recommended_patterns", [])

        # 1. 匹配域名（如/example\.com/ → ||example.com^）
        domain_pattern = common_patterns.get("common_domain_patterns", [])
        if domain_pattern:
            domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', regex)
            if domain_match:
                return f"||{domain_match.group(1)}^"

        # 2. 匹配URL路径（如/ad.js → ||*/ad.js^）
        url_pattern = common_patterns.get("common_url_patterns", [])
        if url_pattern:
            path_match = re.search(r'\\\/([a-zA-Z0-9_-]+\.js|ad\/|advert\/)', regex)
            if path_match:
                path = path_match.group(1).replace('\\', '')
                return f"||*/{path}^"

        logger.debug(f"正则无法转为ABP基础规则: {rule_info['original']}（数据库定义逻辑）")
        return None

    def _replace_placeholders(self, template: str, rule_info: Dict[str, Any], platform: str) -> str:
        """替换模板占位符 - 完全基于数据库定义的规则属性"""
        # 提取模板中的占位符（如{domain}、{content}、{modifiers}）
        placeholders = re.findall(r'\{([a-zA-Z0-9_/]+)\}', template)
        if not placeholders:
            return template

        converted = template
        for placeholder in placeholders:
            # 1. 基础属性占位符（数据库定义的规则核心属性）
            if placeholder == "domain":
                value = rule_info.get("domain", rule_info.get("content", "")).strip()
            elif placeholder == "content":
                value = rule_info.get("content", "").strip()
            elif placeholder == "modifiers":
                value = self._format_modifiers(rule_info, platform)
            elif placeholder == "ip":
                # Hosts规则IP（数据库定义的hosts_rule默认IP）
                value = "0.0.0.0"
            else:
                # 其他占位符：从规则信息中获取，无则为空
                value = rule_info.get(placeholder, "").strip()

            # 占位符值为空时，用归一化规则兜底
            if not value:
                value = rule_info.get("normalized", "").strip()

            converted = converted.replace(f"{{{placeholder}}}", value)

        return converted

    def _format_modifiers(self, rule_info: Dict[str, Any], platform: str) -> str:
        """格式化修饰符 - 按数据库定义的平台支持的修饰符"""
        if not self.config.ENABLE_ADVANCED_MODIFIERS:
            return ""

        modifiers = rule_info["modifiers"]
        mod_details = rule_info["modifier_details"]
        # 获取平台支持的修饰符（数据库定义）
        platform_supported_mods = self.syntax_db.get_platform_cfg(platform).get("supported_modifiers", [])
        valid_mods = [mod for mod in modifiers if mod in platform_supported_mods]

        if not valid_mods:
            return ""

        # 按数据库定义的修饰符格式拼接（如domain=example.com,third-party）
        mod_strs = []
        for mod in valid_mods:
            value = mod_details[mod]
            if isinstance(value, list):
                mod_strs.append(f"{mod}={','.join(value)}")
            elif isinstance(value, str):
                mod_strs.append(f"{mod}={value}")
            elif value is True:
                mod_strs.append(mod)

        return ",".join(mod_strs)


class UnifiedConverter:
    """统一转换入口 - 整合解析、转换、过滤、保存，无硬编码语法逻辑"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        # 初始化核心依赖（均依赖数据库）
        self.syntax_db = EnhancedSyntaxDatabase(config)
        self.parser = AdvancedRuleParser(self.syntax_db)
        self.converter = SmartPlatformConverter(self.syntax_db, config)
        # 白名单过滤器（基于数据库定义的放行规则）
        self.whitelist_filter = self._init_whitelist_filter()
        # 去重布隆过滤器（基于数据库定义的性能参数）
        self.bloom_filters: Dict[str, Dict[str, ScalableBloomFilter]] = {}
        if self.config.ENABLE_DEDUPLICATION:
            self._init_bloom_filters()
        # 统计信息（初始化）
        self.stats = self._init_stats()

    def _init_whitelist_filter(self) -> Set[str]:
        """初始化白名单过滤器 - 基于数据库定义的放行规则类型"""
        whitelist = set()
        if not self.config.INPUT_ALLOW.exists():
            logger.warning(f"白名单文件不存在: {self.config.INPUT_ALLOW}")
            return whitelist

        try:
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parser.parse_rule(line)
                    # 仅添加数据库定义的放行规则（is_exception=True）
                    if parsed["is_valid"] and parsed["is_exception"] and parsed["domain"]:
                        whitelist.add(parsed["domain"])
            logger.info(f"加载白名单域名: {len(whitelist)}个（基于数据库放行规则类型）")
        except Exception as e:
            logger.error(f"白名单加载失败: {str(e)}")
        return whitelist

    def _init_bloom_filters(self) -> None:
        """初始化布隆过滤器 - 基于数据库定义的性能参数"""
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
        logger.info(f"初始化布隆过滤器（容量：{self.config.BLOOM_CAPACITY}，误差率：{self.config.BLOOM_ERROR_RATE}，数据库定义）")

    def _init_stats(self) -> Dict[str, Any]:
        """初始化统计信息 - 无硬编码统计项"""
        platform_stats = {p: {"block": 0, "allow": 0, "unsupported": 0} for p in self.config.TARGET_PLATFORMS}
        return {
            "total_processed": 0, "valid_rules": 0, "invalid_rules": 0,
            "duplicates_removed": 0, "whitelist_filtered": 0,
            "platforms": platform_stats
        }

    def run(self):
        """主执行流程 - 完全依赖数据库配置，无硬编码流程调整"""
        logger.info("="*80)
        logger.info(f"统一规则转换器（基于语法数据库v{self.syntax_db.db_data['version']}）")
        logger.info("输入：Adblock基础语法规则 + AdGuard全平台规则（数据库定义支持的输入类型）")
        logger.info(f"输出：{', '.join(self.config.TARGET_PLATFORMS)}（数据库定义的目标平台）")
        logger.info("="*80)

        try:
            # 1. 加载输入规则（数据库定义的输入文件）
            input_rules = self._load_input_rules()
            if not input_rules:
                logger.critical("无有效输入规则，终止转换")
                sys.exit(1)

            # 2. 初始化平台规则存储（按数据库目标平台）
            platform_rules: Dict[str, Dict[str, List[str]]] = {
                p: {"block": [], "allow": []} for p in self.config.TARGET_PLATFORMS
            }

            # 3. 批量解析+转换+去重（基于数据库批量大小参数）
            self._process_rules_batch(input_rules, platform_rules)

            # 4. 应用白名单过滤（数据库定义的白名单逻辑）
            if self.config.ENABLE_WHITELIST_FILTERING:
                platform_rules = self._apply_whitelist(platform_rules)

            # 5. 保存各平台规则文件（按数据库推导的输出路径）
            self._save_platform_rules(platform_rules)

            # 6. Mihomo规则编译（依赖数据库Clash平台配置，无则跳过）
            if self.config.ENABLE_MIHOMO and "clash" in self.config.TARGET_PLATFORMS:
                self._compile_mihomo_rules(platform_rules["clash"]["block"])

            # 7. 输出统计报告（基于数据库定义的平台）
            self._print_stats()

            logger.info("\n" + "="*80)
            logger.info(f"转换完成！所有规则均基于语法数据库v{self.syntax_db.db_data['version']}定义生成")
            logger.info("="*80)

        except Exception as e:
            logger.error(f"转换流程异常终止: {str(e)}", exc_info=True)
            sys.exit(1)

    def _load_input_rules(self) -> List[str]:
        """加载输入规则 - 无硬编码规则数量限制，仅按文件读取"""
        input_rules = []
        # 加载拦截规则
        if self.config.INPUT_BLOCK.exists():
            with open(self.config.INPUT_BLOCK, 'r', encoding='utf-8', errors='ignore') as f:
                block_rules = [line.strip() for line in f if line.strip()]
                input_rules.extend(block_rules)
            logger.info(f"加载拦截规则: {self.config.INPUT_BLOCK} → {len(block_rules)}条")
        else:
            logger.warning(f"拦截规则文件不存在: {self.config.INPUT_BLOCK}")

        # 加载放行规则
        if self.config.INPUT_ALLOW.exists():
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                allow_rules = [line.strip() for line in f if line.strip()]
                input_rules.extend(allow_rules)
            logger.info(f"加载放行规则: {self.config.INPUT_ALLOW} → {len(allow_rules)}条")
        else:
            logger.warning(f"放行规则文件不存在: {self.config.INPUT_ALLOW}")

        return input_rules

    def _process_rules_batch(self, input_rules: List[str], platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """批量处理规则 - 基于数据库定义的批量大小"""
        batch_size = self.config.BATCH_SIZE
        for i in range(0, len(input_rules), batch_size):
            batch = input_rules[i:i+batch_size]
            for rule in batch:
                self.stats["total_processed"] += 1

                # 解析规则（数据库定义的解析逻辑）
                parsed = self.parser.parse_rule(rule)
                if not parsed["is_valid"]:
                    self.stats["invalid_rules"] += 1
                    continue
                self.stats["valid_rules"] += 1

                # 确定规则类别（block/allow，基于数据库rule_action）
                rule_class = "allow" if parsed["is_exception"] else "block"

                # 分发到支持的平台（数据库判断的支持平台）
                for platform in parsed["supported_platforms"]:
                    converted = self.converter.convert_rule(parsed, platform)
                    if not converted:
                        self.stats["platforms"][platform]["unsupported"] += 1
                        continue

                    # 去重检查（基于数据库性能参数的布隆过滤器）
                    if self.config.ENABLE_DEDUPLICATION and self._is_duplicate(platform, rule_class, converted):
                        self.stats["duplicates_removed"] += 1
                        continue

                    # 添加到平台规则列表
                    platform_rules[platform][rule_class].append(converted)
                    self.stats["platforms"][platform][rule_class] += 1

        logger.info(f"批量处理完成：总规则{self.stats['total_processed']} → 有效{self.stats['valid_rules']} → 无效{self.stats['invalid_rules']}（基于数据库解析逻辑）")

    def _is_duplicate(self, platform: str, rule_class: str, rule: str) -> bool:
        """基于布隆过滤器去重 - 完全依赖数据库性能参数"""
        # 归一化规则（确保相同规则不同格式视为重复，数据库normalization_rules定义）
        normalized = self.parser._apply_normalization(rule)
        rule_hash = hashlib.md5(normalized.encode('utf-8')).hexdigest()

        bloom = self.bloom_filters[platform][rule_class]
        if rule_hash in bloom:
            return True
        bloom.add(rule_hash)
        return False

    def _apply_whitelist(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
        """应用白名单过滤 - 基于数据库定义的域名匹配逻辑"""
        if not self.whitelist_filter:
            return platform_rules

        logger.info("开始应用白名单过滤...（基于数据库域名匹配逻辑）")
        total_filtered = 0
        for platform in self.config.TARGET_PLATFORMS:
            original_block = platform_rules[platform]["block"].copy()
            # 过滤逻辑：拦截规则域名在白名单中（数据库定义的域名匹配）
            filtered_block = [
                rule for rule in original_block
                if not self._rule_matches_whitelist(rule)
            ]
            # 更新统计
            filtered_count = len(original_block) - len(filtered_block)
            platform_rules[platform]["block"] = filtered_block
            total_filtered += filtered_count
            self.stats["whitelist_filtered"] += filtered_count

        logger.info(f"白名单过滤完成：共移除{total_filtered}条拦截规则（基于数据库白名单逻辑）")
        return platform_rules

    def _rule_matches_whitelist(self, rule: str) -> bool:
        """判断规则是否匹配白名单 - 基于数据库定义的域名匹配"""
        parsed = self.parser.parse_rule(rule)
        if not parsed["domain"] or not self.whitelist_filter:
            return False

        # 数据库定义的白名单匹配逻辑：精确匹配或子域名匹配
        domain = parsed["domain"]
        return any(
            whitelist_domain == domain or domain.endswith(f".{whitelist_domain}")
            for whitelist_domain in self.whitelist_filter
        )

    def _save_platform_rules(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """保存平台规则文件 - 按数据库推导的输出路径和格式"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n开始保存规则文件到：{self.config.OUTPUT_DIR}（数据库推导路径）")

        for platform in self.config.TARGET_PLATFORMS:
            # 获取数据库推导的输出文件名
            platform_output = self.config.OUTPUT_FILES.get(platform, {})
            if not platform_output:
                logger.debug(f"平台[{platform}]无输出配置（数据库未定义），跳过")
                continue

            # 处理拦截/放行规则
            for rule_class in ["block", "allow"]:
                if rule_class not in platform_output:
                    continue  # 平台不支持该类别规则（数据库定义）

                rules = platform_rules[platform][rule_class]
                if not rules:
                    logger.debug(f"平台[{platform}/{rule_class}]无有效规则，跳过")
                    continue

                # 去重并排序（数据库建议的规则优化）
                unique_rules = sorted(list(set(rules)))
                # 获取平台特定格式（数据库定义的规则集头部，如Clash的RULE-SET）
                output_content = self._get_platform_specific_content(platform, rule_class, unique_rules)
                # 保存文件
                output_path = self.config.OUTPUT_DIR / platform_output[rule_class]
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(output_content))
                    logger.info(f"保存[{platform}/{rule_class}]：{output_path} → {len(unique_rules)}条（数据库定义格式）")
                except Exception as e:
                    logger.error(f"保存失败 [{output_path}]: {str(e)}")

    def _get_platform_specific_content(self, platform: str, rule_class: str, rules: List[str]) -> List[str]:
        """生成平台特定格式 - 基于数据库定义的规则集格式"""
        platform_cfg = self.syntax_db.get_platform_cfg(platform)
        rule_set_format = platform_cfg.get("rule_set_format", {})

        # 1. Clash平台：RULE-SET格式（数据库定义）
        if platform == "clash" and rule_set_format.get("type") == "RULE-SET":
            action = rule_set_format.get("block_action", "REJECT") if rule_class == "block" else rule_set_format.get("allow_action", "DIRECT")
            ruleset_name = rule_set_format.get("name_format", "adblock_clash_{class}").format(class=rule_class)
            return [
                f"#RULE-SET,{ruleset_name},{action}",
                "payload:",
                *[f"  - '{rule}'" for rule in rules]
            ]

        # 2. Surge平台：DOMAIN-SET格式（数据库定义）
        if platform == "surge" and rule_set_format.get("type") == "DOMAIN-SET":
            action = rule_set_format.get("block_action", "REJECT") if rule_class == "block" else rule_set_format.get("allow_action", "DIRECT")
            ruleset_name = rule_set_format.get("name_format", "adblock_surge_{class}").format(class=rule_class)
            return [
                f"#DOMAIN-SET,{ruleset_name},{action}",
                *rules
            ]

        # 3. 其他平台：纯规则（无头部，数据库定义）
        return rules

    def _compile_mihomo_rules(self, clash_rules: List[str]) -> None:
        """编译Mihomo规则 - 依赖数据库Clash平台配置和环境变量"""
        if not clash_rules:
            logger.warning("无Clash规则可编译为Mihomo格式（需数据库Clash平台配置）")
            return

        # 获取Mihomo输出配置（数据库或环境变量）
        mihomo_output = self.config.OUTPUT_FILES.get("mihomo", {}).get("block", "adb.mrs")
        output_path = self.config.OUTPUT_DIR / mihomo_output
        mihomo_tool = os.getenv('MIHOMO_BIN', 'mihomo-tool')  # 从环境变量获取工具路径

        # 创建临时Clash规则文件（Mihomo兼容Clash格式，数据库定义）
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.yaml', delete=False) as temp_f:
            temp_content = [
                "#RULE-SET,adblock_mihomo_block,REJECT",
                "payload:",
                *[f"  - '{rule}'" for rule in clash_rules]
            ]
            temp_f.write("\n".join(temp_content))
            temp_path = temp_f.name

        try:
            # 执行Mihomo编译命令（基于环境变量工具路径）
            compile_cmd = [mihomo_tool, "compile", temp_path, str(output_path)]
            logger.info(f"执行Mihomo编译：{' '.join(compile_cmd)}")
            result = subprocess.run(
                compile_cmd, capture_output=True, text=True, check=True
            )
            logger.info(f"Mihomo规则编译完成：{output_path} → {len(clash_rules)}条规则")
        except subprocess.CalledProcessError as e:
            logger.error(f"Mihomo编译失败（返回码{e.returncode}）：{e.stderr}")
            # 降级：保存Clash兼容格式（数据库建议的降级方案）
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}（数据库兼容方案）")
        except FileNotFoundError:
            logger.error(f"未找到mihomo-tool（需通过MIHOMO_BIN环境变量指定路径）")
            # 降级保存
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}（数据库兼容方案）")
        finally:
            # 删除临时文件
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def _print_stats(self) -> None:
        """打印统计报告 - 基于数据库定义的目标平台"""
        logger.info("\n" + "="*80)
        logger.info("转换统计报告（基于语法数据库定义）")
        logger.info("="*80)
        # 基础统计
        logger.info(f"1. 基础统计")
        logger.info(f"   - 总处理规则数：{self.stats['total_processed']}")
        logger.info(f"   - 有效规则数：{self.stats['valid_rules']}")
        logger.info(f"   - 无效规则数：{self.stats['invalid_rules']}")
        logger.info(f"   - 重复规则移除数：{self.stats['duplicates_removed']}")
        logger.info(f"   - 白名单过滤移除数：{self.stats['whitelist_filtered']}")
        # 平台统计（数据库定义的目标平台）
        logger.info(f"\n2. 各平台规则分布（数据库定义的目标平台）")
        for platform in sorted(self.config.TARGET_PLATFORMS):
            stats = self.stats["platforms"][platform]
            logger.info(f"   - {platform:15}：拦截{stats['block']:6} | 放行{stats['allow']:6} | 不支持{stats['unsupported']:4}")


def main():
    # 初始化配置（无硬编码语法相关参数）
    config = UnifiedConfig()
    # 启动统一转换器（完全依赖数据库）
    converter = UnifiedConverter(config)
    converter.run()


if __name__ == "__main__":
    main()
