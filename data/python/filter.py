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
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    
    # 输入文件：Adblock基础语法+AdGuard全平台规则（用户指定输入产物）
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"  # 拦截规则（含AdGuard全平台）
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"    # 放行规则（含AdGuard全平台）
    
    # 输出配置：覆盖用户指定的所有目标平台
    OUTPUT_DIR: Path = BASE_DIR
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {"block": "adblock_clash.yaml", "allow": "allow_clash.yaml"},
        "surge": {"block": "adblock_surge.txt", "allow": "allow_surge.txt"},
        "pihole": {"block": "adblock_pihole.txt", "allow": "allow_pihole.txt"},
        "ublock_origin": {"block": "adblock_ubo.txt", "allow": "allow_ubo.txt"},
        "adblock_plus": {"block": "adblock_abp.txt", "allow": "allow_abp.txt"},
        "hosts": {"block": "hosts.txt"},  # Hosts不支持放行规则（数据库定义）
        "mihomo": {"block": "adb.mrs"},    # Mihomo仅需拦截规则
        "adguard_home": {"block": "adblock_adh.txt", "allow": "allow_adh.txt"},
        "adguard_browser": {"block": "adblock_adg_browser.txt", "allow": "allow_adg_browser.txt"}
    })
    
    # 语法数据库路径（核心依赖，优先加载用户指定路径）
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    
    # 功能开关（可通过环境变量覆盖，默认启用）
    ENABLE_MIHOMO: bool = os.getenv('ENABLE_MIHOMO', 'true').lower() == 'true'
    ENABLE_DEDUPLICATION: bool = os.getenv('ENABLE_DEDUPE', 'true').lower() == 'true'
    ENABLE_WHITELIST_FILTERING: bool = os.getenv('ENABLE_WHITELIST', 'true').lower() == 'true'
    ENABLE_ADVANCED_MODIFIERS: bool = os.getenv('ENABLE_ADVANCED_MODIFIERS', 'true').lower() == 'true'
    
    # 动态配置：从数据库加载（初始化后覆盖）
    BATCH_SIZE: int = 1000
    BLOOM_CAPACITY: int = 0
    BLOOM_ERROR_RATE: float = 0.0
    MAX_RULE_LENGTH: int = 0
    MIN_RULE_LENGTH: int = 0
    TARGET_PLATFORMS: List[str] = field(default_factory=list)


class EnhancedSyntaxDatabase:
    """增强版语法数据库 - 完全依赖v4.7.0数据库，无硬编码语法"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.db_data: Dict[str, Any] = {}  # 完整数据库内容
        self.syntax_patterns: Dict[str, str] = {}  # 语法匹配正则（如adblock_basic_domain_rule）
        self.compiled_syntax: Dict[str, Pattern] = {}  # 编译后的正则
        self.rule_types: Dict[str, str] = {}  # 规则类型→动作（如adblock_basic_domain_rule→blocking）
        self.platform_support: Dict[str, Dict[str, Any]] = {}  # 平台支持配置（如abp的supported_rule_types）
        self.modifiers: Dict[str, str] = {}  # 修饰符正则（如domain=([^\\s,]+)）
        self.compiled_modifiers: Dict[str, Pattern] = {}  # 编译后的修饰符正则
        self.normalization_rules: Dict[str, bool] = {}  # 归一化规则（如domain_to_lowercase）
        self.validation_rules: Dict[str, Any] = {}  # 验证规则（如regex_max_nesting）
        self.adguard_specific: Dict[str, Any] = {}  # AdGuard专属配置（如dns_rewrite_types）
        self.abp_specific: Dict[str, Any] = {}  # ABP专属配置（如regex_support）
        
        # 强制加载数据库（失败终止）
        self._load_and_validate_database()
        # 提取数据库核心内容（含AdGuard/ABP专属配置）
        self._extract_core_sections()
        # 编译正则（语法+修饰符）
        self._compile_patterns()
        # 从数据库更新配置（覆盖硬编码）
        self._update_config_from_db()

    def _load_and_validate_database(self):
        """加载并验证数据库完整性（v4.7.0必填字段）"""
        possible_paths = [
            self.config.SYNTAX_DB_FILE,
            self.config.BASE_DIR / "adblock_syntax_db.json",
            Path(__file__).parent / "adblock_syntax_db.json"
        ]
        
        # 查找数据库文件
        db_path: Optional[Path] = None
        for path in possible_paths:
            if path.exists() and path.is_file():
                db_path = path
                break
        if not db_path:
            logger.critical(f"未找到语法数据库v4.7.0，检查路径: {possible_paths}")
            sys.exit(1)

        # 解析数据库
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                self.db_data = json.load(f)
            
            # 验证版本和必填字段（数据库integrity_checks定义）
            if self.db_data.get("version") != "4.7.0":
                logger.warning(f"数据库版本非4.7.0（当前：{self.db_data.get('version')}），可能存在兼容性问题")
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
        """提取数据库核心章节（含AdGuard/ABP专属配置）"""
        # 基础语法与规则
        self.syntax_patterns = self.db_data["syntax_patterns"]
        self.rule_types = self.db_data["rule_types"]
        self.platform_support = self.db_data["platform_support"]
        self.modifiers = self.db_data["modifiers"]
        self.normalization_rules = self.db_data["normalization_rules"]
        self.validation_rules = self.db_data["validation_rules"]
        
        # AdGuard专属配置（用于处理AdGuard全平台输入）
        self.adguard_specific = self.db_data.get("adguard_specific_enhancements", {})
        # ABP专属配置（用于正则转基础规则）
        self.abp_specific = self.validation_rules.get("abp_specific_validation", {})
        
        # 目标平台：从数据库platform_support提取（确保覆盖用户指定的输出平台）
        self.config.TARGET_PLATFORMS = list(self.platform_support.keys())
        logger.info(f"从数据库获取目标平台: {', '.join(self.config.TARGET_PLATFORMS)}")

    def _compile_patterns(self):
        """编译语法规则和修饰符正则（基于数据库定义）"""
        # 编译语法模式（全匹配，补^和$）
        for pattern_name, pattern_str in self.syntax_patterns.items():
            try:
                full_pattern = pattern_str
                if not full_pattern.startswith('^'):
                    full_pattern = f"^{full_pattern}"
                if not full_pattern.endswith('$'):
                    full_pattern = f"{full_pattern}$"
                self.compiled_syntax[pattern_name] = re.compile(full_pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"语法模式编译失败 [{pattern_name}]: {pattern_str} → {e}")

        # 编译修饰符模式（部分匹配，无需全匹配）
        for mod_name, mod_pattern in self.modifiers.items():
            try:
                self.compiled_modifiers[mod_name] = re.compile(mod_pattern, re.IGNORECASE)
            except re.error as e:
                logger.error(f"修饰符编译失败 [{mod_name}]: {mod_pattern} → {e}")

    def _update_config_from_db(self):
        """从数据库更新配置（覆盖硬编码，如布隆过滤器、规则长度）"""
        # 布隆过滤器配置（performance_optimization定义）
        bloom_cfg = self.db_data.get("performance_optimization", {}).get("bloom_filter_config", {})
        self.config.BLOOM_CAPACITY = bloom_cfg.get("initial_capacity", 1000000)
        self.config.BLOOM_ERROR_RATE = bloom_cfg.get("error_rate", 0.001)
        
        # 规则长度限制（validation_rules定义）
        self.config.MAX_RULE_LENGTH = self.validation_rules.get("max_rule_length", 4096)
        self.config.MIN_RULE_LENGTH = self.validation_rules.get("min_rule_length", 3)
        
        logger.debug(f"从数据库更新配置：布隆容量={self.config.BLOOM_CAPACITY}，规则长度限制={self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}")

    # 工具方法：供其他模块调用（完全依赖数据库）
    def get_platform_cfg(self, platform: str) -> Dict[str, Any]:
        """获取指定平台的完整配置（如supported_rule_types、rule_format）"""
        return self.platform_support.get(platform, {})

    def get_rule_action(self, rule_type: str) -> str:
        """获取规则类型对应的动作（blocking/exception/cosmetic等）"""
        return self.rule_types.get(rule_type, "unknown")

    def get_platform_rule_template(self, platform: str, rule_type: str) -> Optional[str]:
        """获取平台+规则类型的转换模板（如ABP的adblock_basic_domain_rule模板）"""
        return self.get_platform_cfg(platform).get("rule_format", {}).get(rule_type)

    def is_rule_supported(self, platform: str, rule_info: Dict[str, Any]) -> bool:
        """基于数据库判断规则是否被平台支持"""
        platform_cfg = self.get_platform_cfg(platform)
        if not platform_cfg:
            return False
        
        rule_type = rule_info["pattern_type"]
        rule_modifiers = rule_info["modifiers"]
        
        # 1. 检查规则类型支持
        supported_types = platform_cfg.get("supported_rule_types", [])
        unsupported_types = platform_cfg.get("unsupported_rule_types", [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False
        
        # 2. 检查修饰符支持
        unsupported_mods = platform_cfg.get("unsupported_modifiers", [])
        if any(mod in unsupported_mods for mod in rule_modifiers):
            return False
        
        # 3. 特殊限制（如Hosts不支持放行规则，数据库隐含）
        if platform == "hosts" and self.get_rule_action(rule_type) == "exception":
            return False
        
        return True

    def get_supported_platforms(self, rule_info: Dict[str, Any]) -> List[str]:
        """获取支持当前规则的所有平台"""
        return [p for p in self.config.TARGET_PLATFORMS if self.is_rule_supported(p, rule_info)]


class AdvancedRuleParser:
    """高级规则解析器 - 基于数据库解析Adblock基础+AdGuard全平台规则"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase):
        self.syntax_db = syntax_db
        self.config = syntax_db.config  # 修复：通过syntax_db访问config
        self.normalization_cfg = self.syntax_db.normalization_rules
        self.validation_cfg = self.syntax_db.validation_rules
        # 规则识别优先级（基于数据库syntax_patterns，确保AdGuard专属规则优先识别）
        self.rule_type_priority: List[str] = [
            "aglint_comment", "adblock_basic_comment",  # 注释优先
            "adguard_scriptlet", "ubo_scriptlet",       # 脚本规则
            "adguard_dns_rewrite", "adguard_home_dns_rewrite",  # DNS重写
            "adblock_basic_exception_rule",             # 放行规则
            "adblock_basic_element_hiding_exception",   # 元素隐藏放行
            "adblock_basic_element_hiding", "adguard_extended_css", "ubo_extended_css",  # 元素隐藏
            "adblock_basic_url_rule",                   # URL规则
            "regex_rule", "adblock_basic_regex_rule",   # 正则规则
            "adblock_basic_domain_rule", "adguard_domain_rule",  # 域名规则
            "hosts_rule", "pihole_domain"               # Hosts/Pi-hole规则
        ]
        # AGLint注释处理相关属性
        self.aglint_action = ""
        self.aglint_target = ""

    def parse_rule(self, raw_rule: str) -> Dict[str, Any]:
        """完整解析流程：清理→归一化→识别类型→提取内容→修饰符→验证→支持平台"""
        rule = raw_rule.strip()
        result: Dict[str, Any] = {
            "original": raw_rule,
            "normalized": self._apply_normalization(rule),
            "pattern_type": "unknown",
            "rule_action": "unknown",
            "content": "",          # 核心内容（如域名、CSS选择器）
            "domain": "",           # 提取的纯域名（无通配符）
            "modifiers": [],        # 修饰符列表（如domain, third-party）
            "modifier_details": {}, # 修饰符详情（如domain: ["example.com"]）
            "is_exception": False,  # 是否为放行规则
            "is_valid": False,      # 是否有效
            "validation_msg": "",   # 验证信息
            "supported_platforms": []# 支持的平台
        }

        # 1. 处理空行/注释（含aglint注释）
        if not result["normalized"]:
            result["pattern_type"] = "empty"
            result["is_valid"] = True
            return result
        if self._is_comment(result["normalized"]):
            result["is_valid"] = True  # 注释视为有效（不参与过滤）
            return result

        # 2. 识别规则类型（按优先级匹配数据库语法）
        self._identify_rule_type(result)

        # 3. 提取核心内容（按规则类型处理，如AdGuard DNS重写提取记录类型）
        self._extract_core_content(result)

        # 4. 提取修饰符（如$domain=example.com, $client=192.168.1.1）
        self._extract_modifiers(result)

        # 5. 确定规则动作和放行属性
        self._determine_action_and_exception(result)

        # 6. 验证规则有效性（基于数据库validation_rules）
        self._validate_rule(result)

        # 7. 获取支持的平台
        result["supported_platforms"] = self.syntax_db.get_supported_platforms(result)

        return result

    def _is_comment(self, rule: str) -> bool:
        """基于数据库判断是否为注释（含aglint注释）"""
        for comment_type in ["aglint_comment", "adblock_basic_comment"]:
            pattern = self.syntax_db.compiled_syntax.get(comment_type)
            if pattern and pattern.match(rule):
                self._set_comment_info(rule, comment_type)
                return True
        return False

    def _set_comment_info(self, rule: str, comment_type: str) -> None:
        """补充注释信息（如aglint的action和规则）"""
        if comment_type == "aglint_comment":
            # 解析aglint注释（如! aglint-disable-next-line invalid-modifiers）
            match = re.match(r'^!\s*aglint-(\w+)(?:-next-line)?(?:\s+(\w+))?', rule)
            if match:
                self.aglint_action = match.group(1)
                self.aglint_target = match.group(2) or ""

    def _apply_normalization(self, rule: str) -> str:
        """基于数据库归一化规则处理（如域名转小写、移除多余通配符）"""
        normalized = rule
        
        # 保留aglint注释（不进行域名转小写等处理）
        if re.match(r'^!\s*aglint-', normalized):
            return normalized
        
        # 域名转小写
        if self.normalization_cfg.get("domain_to_lowercase", True):
            normalized = normalized.lower()
        
        # 移除多余通配符（如||example.com^^→||example.com^）
        if self.normalization_cfg.get("remove_redundant_wildcards", True):
            normalized = re.sub(r'\^\^+', '^', normalized)
            normalized = re.sub(r'\|\|\|+', '||', normalized)
        
        # 移除尾随注释（如"||example.com^ # 广告域名"→"||example.com^"）
        if self.normalization_cfg.get("remove_trailing_comments", True):
            normalized = re.split(r'\s+#', normalized)[0]
        
        # 标准化空格
        if self.normalization_cfg.get("normalize_whitespace", True):
            normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized

    def _identify_rule_type(self, result: Dict[str, Any]) -> None:
        """按优先级匹配数据库语法，识别规则类型"""
        for rule_type in self.rule_type_priority:
            pattern = self.syntax_db.compiled_syntax.get(rule_type)
            if pattern and pattern.match(result["normalized"]):
                result["pattern_type"] = rule_type
                break

    def _extract_core_content(self, result: Dict[str, Any]) -> None:
        """按规则类型提取核心内容（完全依赖数据库语法定义）"""
        rule_type = result["pattern_type"]
        normalized = result["normalized"]
        content = normalized

        # 处理AdGuard专属规则
        if rule_type in ["adguard_dns_rewrite", "adguard_home_dns_rewrite"]:
            # 提取DNS重写记录（如$dnsrewrite=A 0.0.0.0）
            match = re.search(r'\$dnsrewrite=([^,]+)', normalized)
            content = match.group(1).strip() if match else ""
        # 处理脚本规则（AdGuard/UBO）
        elif rule_type in ["adguard_scriptlet", "ubo_scriptlet"]:
            # 提取脚本内容（如#%#//scriptlet("abort-on-property-read", "adTrack")）
            content = re.sub(r'^#%#//scriptlet\(', '', normalized).rstrip(')')
        # 处理元素隐藏规则
        elif rule_type in ["adblock_basic_element_hiding", "adblock_basic_element_hiding_exception"]:
            # 提取CSS选择器（如##.ad-banner→.ad-banner）
            content = re.sub(r'^#@?#', '', normalized)
        # 处理域名规则（Adblock基础/AdGuard）
        elif rule_type in ["adblock_basic_domain_rule", "adblock_basic_exception_rule"]:
            # 提取纯域名（如||example.com^→example.com）
            content = re.sub(r'^@@?\|\|', '', normalized).rstrip('^')
            result["domain"] = content  # 单独存储纯域名（用于转换）
        # 处理正则规则
        elif rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            # 提取正则表达式（如/example\.com\/ad\/→example\.com\/ad\/）
            content = re.sub(r'^\/|\/$', '', normalized)

        result["content"] = content.strip()

    def _extract_modifiers(self, result: Dict[str, Any]) -> None:
        """基于数据库修饰符定义，提取修饰符及详情"""
        if '$' not in result["normalized"]:
            return
        
        # 提取$后的修饰符部分（如"||example.com^$domain=abc.com,third-party"→"domain=abc.com,third-party"）
        modifier_part = result["normalized"].split('$', 1)[1]
        if not modifier_part:
            return
        
        # 遍历数据库修饰符，匹配并提取
        for mod_name, mod_pattern in self.syntax_db.compiled_modifiers.items():
            match = mod_pattern.search(modifier_part)
            if not match:
                continue
            
            result["modifiers"].append(mod_name)
            # 提取修饰符值（如domain=abc.com→["abc.com"]，third-party→True）
            if match.groups():
                mod_value = match.group(1).strip()
                # 处理多值（如domain=abc.com,def.com→["abc.com", "def.com"]）
                result["modifier_details"][mod_name] = mod_value.split(',') if ',' in mod_value else mod_value
            else:
                result["modifier_details"][mod_name] = True

    def _determine_action_and_exception(self, result: Dict[str, Any]) -> None:
        """基于数据库rule_types，确定规则动作和是否为放行规则"""
        rule_type = result["pattern_type"]
        # 获取规则动作（blocking/exception/cosmetic等）
        result["rule_action"] = self.syntax_db.get_rule_action(rule_type)
        # 放行规则判断（exception类型或动作含allow）
        result["is_exception"] = (
            rule_type.endswith("_exception") 
            or result["rule_action"] in ["exception", "allow", "cosmetic_exception"]
        )

    def _validate_rule(self, result: Dict[str, Any]) -> None:
        """基于数据库validation_rules验证规则有效性"""
        rule_type = result["pattern_type"]
        content = result["content"]
        modifiers = result["modifiers"]

        # 1. 长度验证（数据库定义的min/max）
        if len(result["normalized"]) < self.config.MIN_RULE_LENGTH:
            result["validation_msg"] = f"规则过短（<{self.config.MIN_RULE_LENGTH}字符）"
            return
        if len(result["normalized"]) > self.config.MAX_RULE_LENGTH:
            result["validation_msg"] = f"规则过长（>{self.config.MAX_RULE_LENGTH}字符）"
            return

        # 2. 域名规则验证（含AdGuard域名规则）
        if rule_type in ["adblock_basic_domain_rule", "adguard_domain_rule"]:
            valid_chars = self.validation_cfg.get("valid_domain_chars", "a-zA-Z0-9.-")
            if not re.match(f'^[{valid_chars}]+$', result["domain"]):
                result["validation_msg"] = f"域名含非法字符（仅允许：{valid_chars}）"
                return
            if '.' not in result["domain"]:
                result["validation_msg"] = "域名格式无效（缺少'.'，如example.com）"
                return

        # 3. 正则规则验证（数据库定义的语法和嵌套限制）
        if rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            # 语法验证
            try:
                re.compile(content)
            except re.error as e:
                result["validation_msg"] = f"正则语法无效：{e}"
                return
            # 嵌套层数验证（数据库regex_max_nesting=3）
            nest_count = self._count_regex_nesting(content)
            if nest_count > self.validation_cfg.get("regex_max_nesting", 3):
                result["validation_msg"] = f"正则嵌套过深（>{self.validation_cfg['regex_max_nesting']}层）"
                return

        # 4. 修饰符组合验证（数据库valid_modifier_combinations）
        valid_mod_combo = self.validation_cfg.get("valid_modifier_combinations", {}).get(rule_type, [])
        if valid_mod_combo and not all(mod in valid_mod_combo for mod in modifiers):
            invalid_mods = [mod for mod in modifiers if mod not in valid_mod_combo]
            result["validation_msg"] = f"规则类型[{rule_type}]不支持修饰符：{','.join(invalid_mods)}"
            return

        # 所有验证通过
        result["is_valid"] = True
        result["validation_msg"] = "验证通过"

    def _count_regex_nesting(self, regex: str) -> int:
        """统计正则表达式嵌套层数（用于验证）"""
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
    """智能转换器 - 基于数据库模板将Adblock/AdGuard规则转为目标平台规则"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase, config: UnifiedConfig):
        self.syntax_db = syntax_db
        self.config = config
        self.platform_templates: Dict[str, Dict[str, str]] = {}  # 平台→规则类型→模板
        self.abp_regex_convert = self.syntax_db.abp_specific.get("regex_support", False)  # ABP正则转基础规则开关
        
        # 加载各平台转换模板（从数据库）
        self._load_platform_templates()

    def _load_platform_templates(self) -> None:
        """从数据库platform_support加载各平台的规则转换模板"""
        for platform in self.config.TARGET_PLATFORMS:
            platform_cfg = self.syntax_db.get_platform_cfg(platform)
            self.platform_templates[platform] = platform_cfg.get("rule_format", {})
        logger.info(f"已加载{len(self.platform_templates)}个平台的转换模板（基于数据库v4.7.0）")

    def convert_rule(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """核心转换逻辑：基于数据库模板替换占位符，支持ABP正则转基础规则"""
        # 先检查规则是否被平台支持
        if not self.syntax_db.is_rule_supported(platform, rule_info):
            logger.debug(f"平台[{platform}]不支持规则[{rule_info['pattern_type']}]: {rule_info['original']}")
            return None
        
        rule_type = rule_info["pattern_type"]
        # 获取平台+规则类型的模板（无模板则用归一化规则）
        template = self.platform_templates[platform].get(rule_type, rule_info["normalized"])
        
        # 特殊处理：ABP不支持正则，转为基础域名/URL规则（数据库abp_specific_validation定义）
        if platform == "adblock_plus" and rule_type in ["regex_rule", "adblock_basic_regex_rule"]:
            converted = self._convert_regex_to_abp_basic(rule_info)
            return converted if converted else None
        
        # 替换模板占位符（如{domain}、{content}、{modifiers}）
        try:
            converted = self._replace_placeholders(template, rule_info, platform)
            return converted.strip() if converted else None
        except Exception as e:
            logger.error(f"转换失败 [{platform}/{rule_type}]: {rule_info['original']} → {e}")
            return None

    def _convert_regex_to_abp_basic(self, rule_info: Dict[str, Any]) -> Optional[str]:
        """将正则规则转为ABP支持的基础规则（数据库建议：如/ad\\.js/→||*/ad.js^）"""
        regex = rule_info["content"]
        # 匹配URL中的广告路径（如/ad.js、/advert/）
        url_path_match = re.search(r'\\\/([a-zA-Z0-9_-]+\.js|advert\/|ad\/)', regex)
        if url_path_match:
            path = url_path_match.group(1).replace('\\', '')
            return f"||*/{path}^"  # 转为基础URL规则
        # 匹配纯域名（如/example\\.com/→||example.com^）
        domain_match = re.search(r'([a-zA-Z0-9_-]+\.[a-zA-Z]{2,})', regex)
        if domain_match:
            domain = domain_match.group(1)
            return f"||{domain}^"  # 转为基础域名规则
        logger.debug(f"正则无法转为ABP基础规则: {rule_info['original']}")
        return None

    def _replace_placeholders(self, template: str, rule_info: Dict[str, Any], platform: str) -> str:
        """替换模板中的占位符（如{domain}、{modifiers}，基于数据库定义）"""
        # 提取模板中的占位符（如{domain}→["domain"]）
        placeholders = re.findall(r'\{([a-zA-Z0-9_/]+)\}', template)
        if not placeholders:
            return template
        
        converted = template
        for placeholder in placeholders:
            if placeholder == "domain":
                # 纯域名（如example.com）
                value = rule_info.get("domain", "").strip()
            elif placeholder == "content":
                # 核心内容（如CSS选择器、DNS重写记录）
                value = rule_info.get("content", "").strip()
            elif placeholder == "modifiers":
                # 格式化修饰符（如domain=example.com,third-party）
                value = self._format_modifiers(rule_info, platform)
            elif placeholder == "ip":
                # Hosts/Pi-hole的IP（默认0.0.0.0，数据库hosts_rule模板）
                value = "0.0.0.0" if platform == "hosts" else ""
            else:
                # 未知占位符（默认空值）
                logger.warning(f"未知占位符[{placeholder}]，模板：{template}")
                value = ""
            
            # 替换占位符
            converted = converted.replace(f"{{{placeholder}}}", value)
        
        return converted

    def _format_modifiers(self, rule_info: Dict[str, Any], platform: str) -> str:
        """按平台格式格式化修饰符（基于数据库supported_modifiers）"""
        if not self.config.ENABLE_ADVANCED_MODIFIERS:
            return ""
        
        modifiers = rule_info["modifiers"]
        mod_details = rule_info["modifier_details"]
        if not modifiers:
            return ""
        
        # 获取平台支持的修饰符（过滤不支持的）
        platform_supported_mods = self.syntax_db.get_platform_cfg(platform).get("supported_modifiers", [])
        valid_mods = [mod for mod in modifiers if mod in platform_supported_mods]
        if not valid_mods:
            return ""
        
        # 格式化修饰符（如domain=abc.com, third-party→"domain=abc.com,third-party"）
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
    """统一转换入口 - 整合解析、转换、过滤、保存流程"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        # 初始化核心依赖（语法数据库+解析器+转换器）
        self.syntax_db = EnhancedSyntaxDatabase(config)
        self.parser = AdvancedRuleParser(self.syntax_db)
        self.converter = SmartPlatformConverter(self.syntax_db, config)
        # 白名单过滤器（基于输入的allow_adg.txt）
        self.whitelist_filter = self._init_whitelist_filter()
        # 去重布隆过滤器（从数据库加载配置）
        self.bloom_filters: Dict[str, Dict[str, ScalableBloomFilter]] = {}
        if self.config.ENABLE_DEDUPLICATION:
            self._init_bloom_filters()
        # 统计信息
        self.stats = self._init_stats()

    def _init_whitelist_filter(self) -> Set[str]:
        """初始化白名单过滤器（加载allow_adg.txt中的放行域名）"""
        whitelist = set()
        if not self.config.INPUT_ALLOW.exists():
            logger.warning(f"白名单文件不存在: {self.config.INPUT_ALLOW}")
            return whitelist
        
        try:
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parser.parse_rule(line)
                    if parsed["is_valid"] and parsed["is_exception"] and parsed["domain"]:
                        whitelist.add(parsed["domain"])
            logger.info(f"加载白名单域名: {len(whitelist)}个")
        except Exception as e:
            logger.error(f"白名单加载失败: {str(e)}")
        return whitelist

    def _init_bloom_filters(self) -> None:
        """初始化各平台的布隆过滤器（去重）"""
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
        """初始化统计信息"""
        return {
            "total_processed": 0, "valid_rules": 0, "invalid_rules": 0,
            "duplicates_removed": 0, "whitelist_filtered": 0,
            "platforms": {p: {"block": 0, "allow": 0, "unsupported": 0} for p in self.config.TARGET_PLATFORMS}
        }

    def run(self):
        """主执行流程：输入→解析→过滤→转换→保存→统计"""
        logger.info("="*80)
        logger.info("统一规则转换器（基于语法数据库v4.7.0）")
        logger.info("输入：Adblock基础语法规则 + AdGuard全平台规则")
        logger.info("输出：UBO、ABP、Pi-hole、Surge、Clash、Mihomo、Hosts")
        logger.info("="*80)

        try:
            # 1. 加载输入规则（Adblock基础+AdGuard全平台）
            input_rules = self._load_input_rules()
            if not input_rules:
                logger.critical("无有效输入规则，终止转换")
                sys.exit(1)

            # 2. 初始化平台规则存储（按平台+规则类型）
            platform_rules: Dict[str, Dict[str, List[str]]] = {
                p: {"block": [], "allow": []} for p in self.config.TARGET_PLATFORMS
            }

            # 3. 批量解析+转换+去重
            self._process_rules_batch(input_rules, platform_rules)

            # 4. 应用白名单过滤（仅拦截规则）
            if self.config.ENABLE_WHITELIST_FILTERING:
                platform_rules = self._apply_whitelist(platform_rules)

            # 5. 保存各平台规则文件
            self._save_platform_rules(platform_rules)

            # 6. Mihomo规则编译（基于Clash规则）
            if self.config.ENABLE_MIHOMO and "mihomo" in platform_rules:
                self._compile_mihomo_rules(platform_rules["mihomo"]["block"])

            # 7. 输出统计报告
            self._print_stats()

            logger.info("\n" + "="*80)
            logger.info("转换完成！所有规则均基于语法数据库v4.7.0定义生成")
            logger.info("="*80)

        except Exception as e:
            logger.error(f"转换流程异常终止: {str(e)}", exc_info=True)
            sys.exit(1)

    def _load_input_rules(self) -> List[str]:
        """加载输入规则（adblock_adg.txt + allow_adg.txt）"""
        input_rules = []
        # 加载拦截规则（Adblock基础+AdGuard全平台）
        if self.config.INPUT_BLOCK.exists():
            with open(self.config.INPUT_BLOCK, 'r', encoding='utf-8', errors='ignore') as f:
                input_rules.extend([line.strip() for line in f if line.strip()])
            logger.info(f"加载拦截规则: {self.config.INPUT_BLOCK} → {len(input_rules)}条")
        else:
            logger.warning(f"拦截规则文件不存在: {self.config.INPUT_BLOCK}")
        
        # 加载放行规则（Adblock基础+AdGuard全平台）
        if self.config.INPUT_ALLOW.exists():
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                allow_rules = [line.strip() for line in f if line.strip()]
                input_rules.extend(allow_rules)
            logger.info(f"加载放行规则: {self.config.INPUT_ALLOW} → {len(allow_rules)}条")
        else:
            logger.warning(f"放行规则文件不存在: {self.config.INPUT_ALLOW}")
        
        return input_rules

    def _process_rules_batch(self, input_rules: List[str], platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """批量处理规则：解析→转换→去重→分发到平台"""
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
                    # 转换规则
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

        logger.info(f"批量处理完成：总规则{self.stats['total_processed']} → 有效{self.stats['valid_rules']} → 无效{self.stats['invalid_rules']}")

    def _is_duplicate(self, platform: str, rule_class: str, rule: str) -> bool:
        """基于布隆过滤器检查规则是否重复"""
        # 归一化规则（确保相同规则不同格式视为重复）
        normalized = self.parser._apply_normalization(rule)
        rule_hash = hashlib.md5(normalized.encode('utf-8')).hexdigest()
        
        bloom = self.bloom_filters[platform][rule_class]
        if rule_hash in bloom:
            return True
        bloom.add(rule_hash)
        return False

    def _apply_whitelist(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
        """应用白名单过滤：移除所有平台的白名单匹配拦截规则"""
        if not self.whitelist_filter:
            return platform_rules
        
        logger.info("开始应用白名单过滤...")
        total_filtered = 0
        for platform in self.config.TARGET_PLATFORMS:
            original_block = platform_rules[platform]["block"].copy()
            # 过滤拦截规则中包含白名单域名的规则
            filtered_block = [
                rule for rule in original_block
                if not self._rule_matches_whitelist(rule)
            ]
            # 更新规则列表和统计
            filtered_count = len(original_block) - len(filtered_block)
            platform_rules[platform]["block"] = filtered_block
            total_filtered += filtered_count
            self.stats["whitelist_filtered"] += filtered_count
        
        logger.info(f"白名单过滤完成：共移除{total_filtered}条拦截规则")
        return platform_rules

    def _rule_matches_whitelist(self, rule: str) -> bool:
        """判断规则是否匹配白名单（基于域名）"""
        # 解析规则提取域名
        parsed = self.parser.parse_rule(rule)
        if not parsed["domain"]:
            return False
        # 检查域名是否在白名单中（含子域名，如sub.example.com匹配example.com）
        domain = parsed["domain"]
        return any(
            whitelist_domain in domain or domain.endswith(f".{whitelist_domain}")
            for whitelist_domain in self.whitelist_filter
        )

    def _save_platform_rules(self, platform_rules: Dict[str, Dict[str, List[str]]]) -> None:
        """保存各平台规则文件（基于config.OUTPUT_FILES）"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n开始保存规则文件到：{self.config.OUTPUT_DIR}")

        for platform in self.config.TARGET_PLATFORMS:
            # 获取平台输出文件名配置
            platform_output = self.config.OUTPUT_FILES.get(platform, {})
            if not platform_output:
                logger.debug(f"平台[{platform}]无输出配置，跳过")
                continue
            
            # 处理拦截/放行规则
            for rule_class in ["block", "allow"]:
                rules = platform_rules[platform][rule_class]
                # 跳过无规则或无输出文件名的情况（如Hosts无放行规则）
                if not rules or rule_class not in platform_output:
                    continue
                
                # 去重并排序（确保规则唯一）
                unique_rules = sorted(list(set(rules)))
                # 生成平台特定格式（如Clash的RULE-SET头部）
                output_content = self._get_platform_specific_content(platform, rule_class, unique_rules)
                # 保存文件
                output_path = self.config.OUTPUT_DIR / platform_output[rule_class]
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(output_content))
                    logger.info(f"保存[{platform}/{rule_class}]：{output_path} → {len(unique_rules)}条")
                except Exception as e:
                    logger.error(f"保存失败 [{output_path}]: {str(e)}")

    def _get_platform_specific_content(self, platform: str, rule_class: str, rules: List[str]) -> List[str]:
        """生成平台特定格式的内容（如Clash/Surge的规则集头部）"""
        # Clash：RULE-SET格式（数据库clash_rule_set_header定义）
        if platform == "clash":
            action = "REJECT" if rule_class == "block" else "DIRECT"
            ruleset_name = f"adblock_clash_{rule_class}"
            return [
                f"#RULE-SET,{ruleset_name},{action}",
                "payload:",
                *[f"  - '{rule}'" for rule in rules]
            ]
        # Surge：DOMAIN-SET格式（数据库surge_domain_set_header定义）
        elif platform == "surge":
            action = "REJECT" if rule_class == "block" else "DIRECT"
            ruleset_name = f"adblock_surge_{rule_class}"
            return [
                f"#DOMAIN-SET,{ruleset_name},{action}",
                *rules
            ]
        # 其他平台：纯规则（无头部，如UBO、ABP、Pi-hole、Hosts）
        else:
            return rules

    def _compile_mihomo_rules(self, clash_rules: List[str]) -> None:
        """编译Mihomo规则（基于Clash规则，使用mihomo-tool）"""
        if not clash_rules:
            logger.warning("无Clash规则可编译为Mihomo格式")
            return
        
        # 获取Mihomo输出路径
        mihomo_output = self.config.OUTPUT_FILES.get("mihomo", {}).get("block")
        if not mihomo_output:
            logger.error("Mihomo输出文件名未配置")
            return
        output_path = self.config.OUTPUT_DIR / mihomo_output

        # 创建临时Clash规则文件（Mihomo兼容Clash格式）
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.yaml', delete=False) as temp_f:
            temp_content = [
                "#RULE-SET,adblock_mihomo_block,REJECT",
                "payload:",
                *[f"  - '{rule}'" for rule in clash_rules]
            ]
            temp_f.write("\n".join(temp_content))
            temp_path = temp_f.name

        try:
            # 执行Mihomo编译命令
            compile_cmd = ["mihomo-tool", "compile", temp_path, str(output_path)]
            logger.info(f"执行Mihomo编译：{' '.join(compile_cmd)}")
            result = subprocess.run(
                compile_cmd, capture_output=True, text=True, check=True
            )
            logger.info(f"Mihomo规则编译完成：{output_path} → {len(clash_rules)}条规则")
        except subprocess.CalledProcessError as e:
            logger.error(f"Mihomo编译失败（返回码{e.returncode}）：{e.stderr}")
            # 降级：保存Clash兼容格式
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}")
        except FileNotFoundError:
            logger.error("未找到mihomo-tool（需安装并加入环境变量）")
            # 降级保存
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(temp_content))
            logger.warning(f"降级保存Clash格式到：{output_path}")
        finally:
            # 删除临时文件
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def _print_stats(self) -> None:
        """打印转换统计报告"""
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
        # 平台统计
        logger.info(f"\n2. 各平台规则分布")
        for platform in sorted(self.config.TARGET_PLATFORMS):
            stats = self.stats["platforms"][platform]
            total = stats["block"] + stats["allow"]
            if total == 0:
                continue
            logger.info(f"   - {platform:15}：拦截{stats['block']:6} | 放行{stats['allow']:6} | 不支持{stats['unsupported']:4}")


def main():
    # 初始化配置
    config = UnifiedConfig()
    # 启动统一转换器
    converter = UnifiedConverter(config)
    converter.run()


if __name__ == "__main__":
    main()