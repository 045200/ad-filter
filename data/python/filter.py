#!/usr/bin/env python3
"""
统一规则转换器 - 基于语法数据库v4.3的多平台规则转换
支持平台：Clash, Surge, Mihomo, Pi-hole, uBlock Origin, Adblock Plus, Hosts
增强版：完全兼容AdGuard语法，支持高级修饰符转换
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
from datetime import datetime
from pybloom_live import ScalableBloomFilter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass
class UnifiedConfig:
    """配置类 - 基于语法数据库v4.3"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    
    # 输入文件（脚本1的输出）
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"
    
    # 输出配置（基于platform_support）
    OUTPUT_DIR: Path = BASE_DIR
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {"block": "adblock_clash.yaml", "allow": "allow_clash.yaml"},
        "surge": {"block": "adblock_surge.txt", "allow": "allow_surge.txt"},
        "pihole": {"block": "adblock_pihole.txt", "allow": "allow_pihole.txt"},
        "ublock_origin": {"block": "adblock_ubo.txt", "allow": "allow_ubo.txt"},
        "adblock_plus": {"block": "adblock_abp.txt", "allow": "allow_abp.txt"},
        "hosts": {"block": "hosts.txt"},
        "mihomo": {"block": "adb.mrs"},
        "adguard_home": {"block": "adguard_home.txt", "allow": "allow_adguard_home.txt"},
        "adguard_browser": {"block": "adguard_browser.txt", "allow": "allow_adguard_browser.txt"}
    })
    
    # 语法数据库路径
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    
    # 功能开关
    ENABLE_MIHOMO: bool = os.getenv('ENABLE_MIHOMO', 'true').lower() == 'true'
    ENABLE_DEDUPLICATION: bool = os.getenv('ENABLE_DEDUPE', 'true').lower() == 'true'
    ENABLE_WHITELIST_FILTERING: bool = os.getenv('ENABLE_WHITELIST', 'true').lower() == 'true'
    ENABLE_ADVANCED_MODIFIERS: bool = os.getenv('ENABLE_ADVANCED_MODIFIERS', 'true').lower() == 'true'
    
    # 性能配置
    BATCH_SIZE: int = 1000
    BLOOM_CAPACITY: int = 1000000
    BLOOM_ERROR_RATE: float = 0.001
    
    # 平台过滤
    TARGET_PLATFORMS: List[str] = field(default_factory=lambda: [
        "clash", "surge", "pihole", "ublock_origin", "adblock_plus", 
        "hosts", "mihomo", "adguard_home", "adguard_browser"
    ])
    
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'


class EnhancedSyntaxDatabase:
    """增强版语法数据库 - 与第一个脚本保持一致"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.db_data = {}
        self.platform_support = {}
        self.rule_types = {}
        self.syntax_patterns = {}
        self.modifiers = {}
        self.common_patterns = {}
        self.load_database()

    def load_database(self):
        """加载语法数据库"""
        possible_paths = [
            self.config.SYNTAX_DB_FILE,
            self.config.BASE_DIR / "adblock_syntax_db.json",
            Path(__file__).parent / "adblock_syntax_db.json"
        ]
        
        db_path = None
        for path in possible_paths:
            if path.exists():
                db_path = path
                break
                
        if not db_path:
            logger.warning("未找到语法数据库，使用内置默认配置")
            self._setup_default_config()
            return

        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                self.db_data = json.load(f)
                
            self._validate_database()
            self._extract_sections()
            logger.info(f"语法数据库v{self.db_data.get('version', '未知')}加载成功")
            
        except Exception as e:
            logger.error(f"数据库加载失败: {e}")
            self._setup_default_config()

    def _setup_default_config(self):
        """默认配置"""
        self.platform_support = {
            "clash": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule"],
                "rule_format": {
                    "domain_rule": "+.{domain}",
                    "adguard_domain_rule": "+.{domain}", 
                    "exception_rule": "-.{domain}"
                }
            },
            "surge": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule"],
                "rule_format": {
                    "domain_rule": ".{domain}",
                    "adguard_domain_rule": ".{domain}",
                    "exception_rule": "@.{domain}"
                }
            },
            "pihole": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule"],
                "rule_format": {
                    "domain_rule": "{domain}",
                    "adguard_domain_rule": "{domain}",
                    "exception_rule": "@@{domain}"
                }
            },
            "ublock_origin": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule"],
                "rule_format": {
                    "domain_rule": "||{domain}^",
                    "adguard_domain_rule": "||{domain}^",
                    "exception_rule": "@@||{domain}^"
                }
            },
            "adblock_plus": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule"],
                "rule_format": {
                    "domain_rule": "||{domain}^",
                    "adguard_domain_rule": "||{domain}^", 
                    "exception_rule": "@@||{domain}^"
                }
            },
            "hosts": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule"],
                "rule_format": {
                    "domain_rule": "0.0.0.0 {domain}",
                    "adguard_domain_rule": "0.0.0.0 {domain}"
                }
            },
            "adguard_home": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule", 
                                       "adguard_dns_rewrite", "adguard_home_dns_rewrite"],
                "rule_format": {
                    "domain_rule": "||{domain}^",
                    "adguard_domain_rule": "||{domain}^",
                    "exception_rule": "@@||{domain}^",
                    "adguard_dns_rewrite": "{original}",
                    "adguard_home_dns_rewrite": "{original}"
                }
            },
            "adguard_browser": {
                "supported_rule_types": ["domain_rule", "adguard_domain_rule", "exception_rule",
                                       "element_hiding_basic", "element_hiding_exception"],
                "rule_format": {
                    "domain_rule": "||{domain}^",
                    "adguard_domain_rule": "||{domain}^",
                    "exception_rule": "@@||{domain}^",
                    "element_hiding_basic": "##{content}",
                    "element_hiding_exception": "#@#{content}"
                }
            }
        }

    def _validate_database(self):
        """验证数据库完整性"""
        required_fields = ["platform_support", "syntax_patterns", "rule_types", "modifiers"]
        missing = [f for f in required_fields if f not in self.db_data]
        if missing:
            logger.warning(f"数据库缺少字段: {missing}")

    def _extract_sections(self):
        """提取数据库各章节"""
        self.platform_support = self.db_data.get("platform_support", {})
        self.rule_types = self.db_data.get("rule_types", {})
        self.syntax_patterns = self.db_data.get("syntax_patterns", {})
        self.modifiers = self.db_data.get("modifiers", {})
        self.common_patterns = self.db_data.get("common_patterns", {})

    def get_platform_config(self, platform: str) -> Dict:
        """获取平台配置"""
        return self.platform_support.get(platform, {})

    def get_rule_format(self, platform: str, rule_type: str) -> Optional[str]:
        """获取规则格式模板"""
        platform_cfg = self.get_platform_config(platform)
        formats = platform_cfg.get("rule_format", {})
        return formats.get(rule_type)

    def is_rule_supported(self, platform: str, rule_info: Dict) -> bool:
        """检查规则是否被平台支持"""
        platform_cfg = self.get_platform_config(platform)
        if not platform_cfg:
            return False
            
        rule_type = rule_info.get("pattern_type", "unknown")
        modifiers = rule_info.get("modifiers", [])
        
        supported_types = platform_cfg.get("supported_rule_types", [])
        unsupported_types = platform_cfg.get("unsupported_rule_types", [])
        
        if rule_type in unsupported_types:
            return False
        if supported_types and rule_type not in supported_types:
            return False
            
        # 检查修饰符支持
        unsupported_mods = platform_cfg.get("unsupported_modifiers", [])
        if any(mod in unsupported_mods for mod in modifiers):
            return False
            
        # 特殊平台限制
        if platform == "hosts" and rule_info.get("is_exception"):
            return False  # Hosts不支持例外规则
            
        return True

    def get_supported_platforms(self, rule_info: Dict) -> List[str]:
        """获取支持该规则的平台列表"""
        return [platform for platform in self.platform_support.keys() 
                if self.is_rule_supported(platform, rule_info)]


class AdvancedRuleParser:
    """高级规则解析器 - 完全兼容AdGuard语法"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase):
        self.syntax_db = syntax_db
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, Pattern]:
        """编译语法模式"""
        patterns = {}
        for name, pattern_str in self.syntax_db.syntax_patterns.items():
            try:
                # 确保模式是完整的正则表达式
                if not pattern_str.startswith('^'):
                    pattern_str = '^' + pattern_str
                if not pattern_str.endswith('$'):
                    pattern_str = pattern_str + '$'
                    
                patterns[name] = re.compile(pattern_str)
            except re.error as e:
                logger.warning(f"模式编译失败 {name}: {e}")
        return patterns

    def parse_rule(self, rule: str) -> Dict[str, Any]:
        """解析单条AdGuard规则"""
        result = {
            "original": rule,
            "normalized": rule.strip(),
            "pattern_type": "unknown",
            "content": "",
            "domain": "",
            "modifiers": [],
            "modifier_details": {},
            "is_exception": rule.startswith("@@"),
            "is_valid": False,
            "validation_msg": ""
        }

        # 跳过注释和空行
        if not rule.strip() or rule.strip().startswith(('#', '!', ';')):
            result["type"] = "comment"
            return result

        # 基本清理
        clean_rule = rule.strip()
        
        # 识别规则类型
        self._identify_rule_type(clean_rule, result)
        
        # 提取修饰符
        self._extract_modifiers_advanced(clean_rule, result)
        
        # 提取域名
        self._extract_domain_advanced(result)
        
        # 验证规则
        self._validate_rule(result)
        
        return result

    def _identify_rule_type(self, rule: str, result: Dict[str, Any]):
        """识别规则类型"""
        # 按优先级匹配规则类型
        rule_patterns = [
            ("adguard_dns_rewrite", r'.*\$dnsrewrite='),
            ("adguard_home_dns_rewrite", r'.*\$dnsrewrite=.*;.*;'),
            ("adguard_domain_rule", r'^\|\|[a-zA-Z0-9.-]+\^'),
            ("element_hiding_basic", r'^##'),
            ("element_hiding_exception", r'^#@#'),
            ("extended_css", r'^#\?#'),
            ("adguard_scriptlet", r'^#%#'),
            ("exception_rule", r'^@@'),
            ("domain_rule", r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            ("hosts_rule", r'^\d+\.\d+\.\d+\.\d+\s+'),
            ("regex_rule", r'^/.*/$')
        ]
        
        for pattern_type, pattern in rule_patterns:
            if re.search(pattern, rule):
                result["pattern_type"] = pattern_type
                result["content"] = self._extract_content(rule, pattern_type)
                break

    def _extract_content(self, rule: str, pattern_type: str) -> str:
        """提取规则内容"""
        if pattern_type == "adguard_domain_rule":
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^', rule)
            return match.group(1) if match else ""
        elif pattern_type in ["element_hiding_basic", "element_hiding_exception"]:
            return rule[3:]  # 移除 ## 或 #@#
        elif pattern_type == "exception_rule":
            return rule[2:]  # 移除 @@
        elif pattern_type == "domain_rule":
            return rule.split('$')[0]  # 移除修饰符
        else:
            return rule

    def _extract_modifiers_advanced(self, rule: str, result: Dict[str, Any]):
        """高级修饰符提取"""
        if '$' not in rule:
            return
            
        # 分离模式和修饰符
        parts = rule.split('$', 1)
        modifier_str = parts[1]
        
        # 匹配各种修饰符格式
        modifier_patterns = {
            'domain': r'domain=([^,\s]+)',
            'client': r'client=([^,\s]+)',
            'dnstype': r'dnstype=([^,\s]+)',
            'denyallow': r'denyallow=([^,\s]+)',
            'dnsrewrite': r'dnsrewrite=([^,\s]+)',
            'important': r'\bimportant\b',
            'badfilter': r'\bbadfilter\b',
            'third-party': r'\bthird-party\b',
            'script': r'\bscript\b',
            'image': r'\bimage\b',
            'stylesheet': r'\bstylesheet\b',
            'redirect': r'redirect=([^,\s]+)',
            'removeparam': r'removeparam=([^,\s]+)',
            'csp': r'csp=([^,\s]+)',
            'cookie': r'cookie=([^,\s]+)',
            'generichide': r'\bgenerichide\b',
            'stealth': r'\bstealth\b',
            'header': r'header=([^,\s]+)',
            'jsonprune': r'jsonprune=([^,\s]+)'
        }
        
        for mod_name, pattern in modifier_patterns.items():
            matches = re.findall(pattern, modifier_str)
            if matches:
                result["modifiers"].append(mod_name)
                if mod_name in ['domain', 'client', 'dnstype', 'denyallow', 'dnsrewrite', 
                               'redirect', 'removeparam', 'csp', 'cookie', 'header', 'jsonprune']:
                    result["modifier_details"][mod_name] = matches
                else:
                    result["modifier_details"][mod_name] = True

    def _extract_domain_advanced(self, result: Dict[str, Any]):
        """高级域名提取"""
        if result["pattern_type"] in ["adguard_domain_rule", "domain_rule"]:
            result["domain"] = result["content"].lower()
        elif result["pattern_type"] == "adguard_dns_rewrite":
            # 从DNS重写规则中提取域名
            match = re.search(r'\|\|([a-zA-Z0-9.-]+)\^', result["original"])
            if match:
                result["domain"] = match.group(1).lower()
        elif "domain" in result["modifier_details"]:
            # 从domain修饰符中提取
            domains = result["modifier_details"]["domain"]
            if domains:
                result["domain"] = domains[0].lower()

    def _validate_rule(self, result: Dict[str, Any]):
        """规则验证"""
        if result["pattern_type"] == "unknown":
            result["is_valid"] = False
            result["validation_msg"] = "未知规则类型"
            return
            
        # 基本长度验证
        if len(result["normalized"]) < 3:
            result["is_valid"] = False
            result["validation_msg"] = "规则过短"
            return
            
        # 域名规则验证
        if result["pattern_type"] in ["adguard_domain_rule", "domain_rule"]:
            if not result["domain"] or '.' not in result["domain"]:
                result["is_valid"] = False
                result["validation_msg"] = "无效域名"
                return
                
        result["is_valid"] = True
        result["validation_msg"] = "验证通过"


class SmartPlatformConverter:
    """智能平台转换器"""
    def __init__(self, syntax_db: EnhancedSyntaxDatabase, config: UnifiedConfig):
        self.syntax_db = syntax_db
        self.config = config
        self.conversion_rules = self._build_conversion_rules()

    def _build_conversion_rules(self) -> Dict[str, Dict[str, Any]]:
        """构建转换规则"""
        return {
            "clash": {
                "domain_rule": lambda r: f"+.{r['domain']}",
                "adguard_domain_rule": lambda r: f"+.{r['domain']}",
                "exception_rule": lambda r: f"-.{r['domain']}",
                "fallback": lambda r: f"+.{r['domain']}" if r['domain'] else None
            },
            "surge": {
                "domain_rule": lambda r: f".{r['domain']}",
                "adguard_domain_rule": lambda r: f".{r['domain']}",
                "exception_rule": lambda r: f"@.{r['domain']}",
                "fallback": lambda r: f".{r['domain']}" if r['domain'] else None
            },
            "pihole": {
                "domain_rule": lambda r: r['domain'],
                "adguard_domain_rule": lambda r: r['domain'],
                "exception_rule": lambda r: f"@@{r['domain']}",
                "fallback": lambda r: r['domain'] if r['domain'] else None
            },
            "ublock_origin": {
                "domain_rule": lambda r: f"||{r['domain']}^",
                "adguard_domain_rule": lambda r: f"||{r['domain']}^",
                "exception_rule": lambda r: f"@@||{r['domain']}^",
                "element_hiding_basic": lambda r: r['original'],
                "element_hiding_exception": lambda r: r['original'],
                "fallback": lambda r: f"||{r['domain']}^" if r['domain'] else r['original']
            },
            "adblock_plus": {
                "domain_rule": lambda r: f"||{r['domain']}^",
                "adguard_domain_rule": lambda r: f"||{r['domain']}^",
                "exception_rule": lambda r: f"@@||{r['domain']}^",
                "element_hiding_basic": lambda r: r['original'],
                "element_hiding_exception": lambda r: r['original'],
                "fallback": lambda r: f"||{r['domain']}^" if r['domain'] else r['original']
            },
            "hosts": {
                "domain_rule": lambda r: f"0.0.0.0 {r['domain']}",
                "adguard_domain_rule": lambda r: f"0.0.0.0 {r['domain']}",
                "fallback": lambda r: f"0.0.0.0 {r['domain']}" if r['domain'] else None
            },
            "adguard_home": {
                "domain_rule": lambda r: f"||{r['domain']}^",
                "adguard_domain_rule": lambda r: f"||{r['domain']}^",
                "exception_rule": lambda r: f"@@||{r['domain']}^",
                "adguard_dns_rewrite": lambda r: r['original'],
                "adguard_home_dns_rewrite": lambda r: r['original'],
                "fallback": lambda r: r['original']
            },
            "adguard_browser": {
                "domain_rule": lambda r: f"||{r['domain']}^",
                "adguard_domain_rule": lambda r: f"||{r['domain']}^",
                "exception_rule": lambda r: f"@@||{r['domain']}^",
                "element_hiding_basic": lambda r: r['original'],
                "element_hiding_exception": lambda r: r['original'],
                "fallback": lambda r: r['original']
            }
        }

    def convert_rule(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """转换规则到指定平台"""
        if not self.syntax_db.is_rule_supported(platform, rule_info):
            return None

        try:
            platform_rules = self.conversion_rules.get(platform, {})
            rule_type = rule_info["pattern_type"]
            
            # 优先使用特定规则类型的转换器
            if rule_type in platform_rules:
                result = platform_rules[rule_type](rule_info)
                if result:
                    return result
            
            # 使用fallback转换器
            if "fallback" in platform_rules:
                result = platform_rules["fallback"](rule_info)
                if result:
                    return result
                    
            # 最终fallback：返回原始规则
            return rule_info["original"]
            
        except Exception as e:
            logger.warning(f"规则转换失败 {platform}: {rule_info['original']} - {e}")
            return None

    def convert_modifiers(self, rule_info: Dict[str, Any], platform: str) -> str:
        """转换修饰符（高级功能）"""
        if not self.config.ENABLE_ADVANCED_MODIFIERS:
            return ""
            
        modifiers = rule_info.get("modifiers", [])
        if not modifiers:
            return ""
            
        # 平台特定的修饰符处理
        modifier_handlers = {
            "adguard_home": self._handle_adguard_home_modifiers,
            "adguard_browser": self._handle_adguard_browser_modifiers,
            "ublock_origin": self._handle_ubo_modifiers
        }
        
        handler = modifier_handlers.get(platform)
        if handler:
            return handler(rule_info)
            
        return ""

    def _handle_adguard_home_modifiers(self, rule_info: Dict[str, Any]) -> str:
        """处理AdGuard Home修饰符"""
        modifiers = []
        details = rule_info.get("modifier_details", {})
        
        if "client" in details:
            modifiers.append(f"client={','.join(details['client'])}")
        if "dnstype" in details:
            modifiers.append(f"dnstype={','.join(details['dnstype'])}")
        if "denyallow" in details:
            modifiers.append(f"denyallow={','.join(details['denyallow'])}")
        if "important" in details:
            modifiers.append("important")
            
        return ','.join(modifiers)

    def _handle_adguard_browser_modifiers(self, rule_info: Dict[str, Any]) -> str:
        """处理AdGuard浏览器修饰符"""
        modifiers = []
        details = rule_info.get("modifier_details", {})
        
        # 内容类型修饰符
        content_mods = ["script", "image", "stylesheet", "object", "xmlhttprequest"]
        for mod in content_mods:
            if mod in details:
                modifiers.append(mod)
                
        # 高级修饰符
        if "important" in details:
            modifiers.append("important")
        if "third-party" in details:
            modifiers.append("third-party")
        if "redirect" in details:
            modifiers.append(f"redirect={','.join(details['redirect'])}")
            
        return ','.join(modifiers)

    def _handle_ubo_modifiers(self, rule_info: Dict[str, Any]) -> str:
        """处理uBlock Origin修饰符"""
        modifiers = []
        details = rule_info.get("modifier_details", {})
        
        # uBO支持的修饰符有限
        if "important" in details:
            modifiers.append("important")
        if "third-party" in details:
            modifiers.append("third-party")
            
        return ','.join(modifiers)


class EnhancedWhitelistFilter:
    """增强版白名单过滤器"""
    def __init__(self, allow_file: Path):
        self.whitelist_domains = self._load_whitelist(allow_file)
        self.whitelist_patterns = self._build_whitelist_patterns()

    def _load_whitelist(self, allow_file: Path) -> Set[str]:
        """加载白名单域名"""
        domains = set()
        if not allow_file.exists():
            return domains
            
        try:
            with open(allow_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = self._extract_domain_from_rule(line.strip())
                    if domain:
                        domains.add(domain)
        except Exception as e:
            logger.error(f"白名单加载失败: {e}")
            
        logger.info(f"加载白名单域名: {len(domains)}个")
        return domains

    def _extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从规则提取域名"""
        if rule.startswith('@@'):
            rule = rule[2:]
        if rule.startswith('||'):
            rule = rule[2:].rstrip('^')
        
        # 提取基础域名
        domain_match = re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', rule)
        return domain_match.group(1).lower() if domain_match else None

    def _build_whitelist_patterns(self) -> List[Pattern]:
        """构建白名单匹配模式"""
        patterns = []
        for domain in self.whitelist_domains:
            try:
                # 精确匹配域名及其子域名
                pattern = re.compile(r'^(.*\.)?' + re.escape(domain) + r'$')
                patterns.append(pattern)
            except re.error:
                continue
        return patterns

    def filter_rules(self, rules: List[str], rule_type: str = "domain") -> Tuple[List[str], int]:
        """过滤规则（移除白名单匹配项）"""
        if not self.whitelist_domains:
            return rules, 0
            
        filtered = []
        removed_count = 0
        
        for rule in rules:
            if not self._is_whitelisted(rule, rule_type):
                filtered.append(rule)
            else:
                removed_count += 1
                
        return filtered, removed_count

    def _is_whitelisted(self, rule: str, rule_type: str) -> bool:
        """检查规则是否在白名单中"""
        domain = self._extract_domain_from_rule(rule)
        if not domain:
            return False
            
        # 检查精确匹配
        if domain in self.whitelist_domains:
            return True
            
        # 检查模式匹配
        for pattern in self.whitelist_patterns:
            if pattern.match(domain):
                return True
                
        return False


class UnifiedConverter:
    """统一转换器"""
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.syntax_db = EnhancedSyntaxDatabase(config)
        self.parser = AdvancedRuleParser(self.syntax_db)
        self.converter = SmartPlatformConverter(self.syntax_db, config)
        self.whitelist_filter = EnhancedWhitelistFilter(config.INPUT_ALLOW)
        
        # 去重过滤器
        self.bloom_filters = {}
        self._init_bloom_filters()
        
        # 统计信息
        self.stats = {
            "total_processed": 0, "valid_rules": 0, "invalid_rules": 0,
            "duplicates_removed": 0, "whitelist_filtered": 0,
            "platforms": {}, "rule_types": {}
        }
        
        self._init_stats()

    def _init_bloom_filters(self):
        """初始化布隆过滤器"""
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

    def _init_stats(self):
        """初始化统计信息"""
        for platform in self.config.TARGET_PLATFORMS:
            self.stats["platforms"][platform] = {
                "block": 0, "allow": 0, "unsupported": 0
            }
        
        # 初始化规则类型统计
        for rule_type in ["domain_rule", "adguard_domain_rule", "exception_rule", 
                         "element_hiding_basic", "adguard_dns_rewrite", "other"]:
            self.stats["rule_types"][rule_type] = 0

    def run(self):
        """主转换流程"""
        logger.info("=== 开始统一规则转换 ===")
        
        try:
            # 1. 处理输入文件
            platform_rules = self._process_input_files()
            
            # 2. 应用白名单过滤（Mihomo专用）
            if self.config.ENABLE_WHITELIST_FILTERING:
                platform_rules = self._apply_whitelist_filtering(platform_rules)
            
            # 3. 保存各平台规则
            self._save_platform_rules(platform_rules)
            
            # 4. 特殊处理：Mihomo编译
            if self.config.ENABLE_MIHOMO and "mihomo" in platform_rules:
                self._compile_mihomo_rules(platform_rules["mihomo"]["block"])
                
            # 5. 输出统计报告
            self._print_statistics()
            
        except Exception as e:
            logger.error(f"转换失败: {e}")
            raise

    def _process_input_files(self) -> Dict[str, Dict[str, List[str]]]:
        """处理输入文件"""
        platform_rules = {
            platform: {"block": [], "allow": []} 
            for platform in self.config.TARGET_PLATFORMS
        }

        # 处理黑名单文件
        if self.config.INPUT_BLOCK.exists():
            logger.info(f"处理黑名单文件: {self.config.INPUT_BLOCK}")
            self._process_single_file(self.config.INPUT_BLOCK, platform_rules, "block")
        else:
            logger.warning(f"黑名单文件不存在: {self.config.INPUT_BLOCK}")
            
        # 处理白名单文件  
        if self.config.INPUT_ALLOW.exists():
            logger.info(f"处理白名单文件: {self.config.INPUT_ALLOW}")
            self._process_single_file(self.config.INPUT_ALLOW, platform_rules, "allow")
        else:
            logger.warning(f"白名单文件不存在: {self.config.INPUT_ALLOW}")
            
        return platform_rules

    def _process_single_file(self, file_path: Path, platform_rules: Dict, rule_class: str):
        """处理单个文件"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            batch = []
            for line in f:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    continue
                    
                batch.append(line)
                if len(batch) >= self.config.BATCH_SIZE:
                    self._process_batch(batch, platform_rules, rule_class)
                    batch = []
                    
            if batch:
                self._process_batch(batch, platform_rules, rule_class)

    def _process_batch(self, batch: List[str], platform_rules: Dict, rule_class: str):
        """处理批次规则"""
        for rule in batch:
            self.stats["total_processed"] += 1
            
            parsed = self.parser.parse_rule(rule)
            if not parsed["is_valid"]:
                self.stats["invalid_rules"] += 1
                continue
                
            self.stats["valid_rules"] += 1
            self._update_rule_type_stats(parsed["pattern_type"])
            self._distribute_rule(parsed, platform_rules, rule_class)

    def _update_rule_type_stats(self, rule_type: str):
        """更新规则类型统计"""
        if rule_type in self.stats["rule_types"]:
            self.stats["rule_types"][rule_type] += 1
        else:
            self.stats["rule_types"]["other"] += 1

    def _distribute_rule(self, rule_info: Dict, platform_rules: Dict, input_class: str):
        """分发规则到各平台"""
        # 确定目标类别（基于规则本身或输入文件）
        target_class = "allow" if rule_info["is_exception"] or input_class == "allow" else "block"
        
        for platform in self.config.TARGET_PLATFORMS:
            converted_rule = self.converter.convert_rule(rule_info, platform)
            if not converted_rule:
                self.stats["platforms"][platform]["unsupported"] += 1
                continue
                
            # 去重检查
            if self._is_duplicate(platform, target_class, converted_rule):
                self.stats["duplicates_removed"] += 1
                continue
                
            platform_rules[platform][target_class].append(converted_rule)
            self.stats["platforms"][platform][target_class] += 1

    def _is_duplicate(self, platform: str, rule_class: str, rule: str) -> bool:
        """检查重复规则"""
        if not self.config.ENABLE_DEDUPLICATION:
            return False
            
        rule_hash = hashlib.md5(rule.encode('utf-8')).hexdigest()
        bloom_filter = self.bloom_filters[platform][rule_class]
        
        if rule_hash in bloom_filter:
            return True
            
        bloom_filter.add(rule_hash)
        return False

    def _apply_whitelist_filtering(self, platform_rules: Dict) -> Dict:
        """应用白名单过滤"""
        if "mihomo" not in platform_rules:
            return platform_rules
            
        original_count = len(platform_rules["mihomo"]["block"])
        filtered_rules, filtered_count = self.whitelist_filter.filter_rules(
            platform_rules["mihomo"]["block"]
        )
        
        platform_rules["mihomo"]["block"] = filtered_rules
        self.stats["whitelist_filtered"] = filtered_count
        
        logger.info(f"Mihomo白名单过滤: {original_count} -> {len(filtered_rules)} 条规则")
        return platform_rules

    def _save_platform_rules(self, platform_rules: Dict):
        """保存各平台规则"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        for platform, rules in platform_rules.items():
            for rule_type in ["block", "allow"]:
                if not rules[rule_type]:
                    continue
                    
                output_file = self.config.OUTPUT_FILES.get(platform, {}).get(rule_type)
                if not output_file:
                    continue
                    
                output_path = self.config.OUTPUT_DIR / output_file
                content = self._format_platform_output(platform, rule_type, rules[rule_type])
                
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    logger.info(f"保存 {platform} {rule_type}: {output_path} ({len(rules[rule_type])}条)")
                except Exception as e:
                    logger.error(f"保存失败 {platform} {rule_type}: {e}")

    def _format_platform_output(self, platform: str, rule_type: str, rules: List[str]) -> str:
        """格式化平台输出"""
        if platform == "clash":
            return self._format_clash_output(rules, rule_type)
        elif platform == "surge":
            return self._format_surge_output(rules, rule_type)
        else:
            return "\n".join(rules)

    def _format_clash_output(self, rules: List[str], rule_type: str) -> str:
        """格式化Clash输出"""
        ruleset_name = "allow_clash" if rule_type == "allow" else "adblock_clash"
        action = "DIRECT" if rule_type == "allow" else "REJECT"
        
        lines = [f"# {ruleset_name} ruleset", f"# Generated: {datetime.now().isoformat()}"]
        lines.append(f"#RULE-SET,{ruleset_name},{action}")
        lines.append("payload:")
        lines.extend([f"  - '{rule}'" for rule in sorted(set(rules))])
        
        return "\n".join(lines)

    def _format_surge_output(self, rules: List[str], rule_type: str) -> str:
        """格式化Surge输出"""
        ruleset_name = "adblock_surge"
        action = "REJECT"
        
        lines = [f"# {ruleset_name} ruleset", f"# Generated: {datetime.now().isoformat()}"]
        lines.append(f"#DOMAIN-SET,{ruleset_name},{action}")
        lines.extend(sorted(set(rules)))
        
        return "\n".join(lines)

    def _compile_mihomo_rules(self, mihomo_rules: List[str]):
        """编译Mihomo规则"""
        if not mihomo_rules:
            logger.warning("无Mihomo规则可编译")
            return
            
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo"]["block"]
        
        # 创建临时Clash格式文件
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.yaml', delete=False) as f:
                f.write(self._format_clash_output(mihomo_rules, "block"))
                temp_file = f.name

            # 调用Mihomo编译工具（需要根据实际环境调整）
            self._execute_mihomo_compile(temp_file, output_path)
            
        except Exception as e:
            logger.error(f"Mihomo编译失败: {e}")
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    def _execute_mihomo_compile(self, input_file: str, output_file: Path):
        """执行Mihomo编译"""
        # 这里需要根据实际的Mihomo编译工具调整命令
        # 示例命令（需要安装mihomo-tool）：
        # cmd = ["mihomo-tool", "compile", input_file, str(output_file)]
        
        # 临时方案：直接复制Clash规则（实际使用时需要替换为真正的编译命令）
        try:
            with open(input_file, 'r', encoding='utf-8') as f_in:
                content = f_in.read()
            
            with open(output_file, 'w', encoding='utf-8') as f_out:
                f_out.write(f"# Mihomo规则（从Clash转换）\n")
                f_out.write(f"# 注意：需要安装mihomo-tool进行真正编译\n")
                f_out.write(content)
                
            logger.info(f"Mihomo规则已保存（需要手动编译）: {output_file}")
            
        except Exception as e:
            logger.error(f"Mihomo规则保存失败: {e}")

    def _print_statistics(self):
        """打印统计信息"""
        logger.info("\n" + "="*60)
        logger.info("规则转换统计报告")
        logger.info("="*60)
        
        logger.info(f"总处理规则: {self.stats['total_processed']}")
        logger.info(f"有效规则: {self.stats['valid_rules']}")
        logger.info(f"无效规则: {self.stats['invalid_rules']}")
        logger.info(f"重复规则移除: {self.stats['duplicates_removed']}")
        logger.info(f"白名单过滤: {self.stats['whitelist_filtered']}")
        
        logger.info("\n规则类型分布:")
        for rule_type, count in self.stats["rule_types"].items():
            if count > 0:
                logger.info(f"  {rule_type}: {count}")
        
        logger.info("\n各平台规则统计:")
        for platform, stats in self.stats["platforms"].items():
            total = stats["block"] + stats["allow"]
            if total > 0:
                logger.info(f"  {platform}: 拦截{stats['block']}, 放行{stats['allow']}, 不支持{stats['unsupported']}")


def main():
    config = UnifiedConfig()
    logger.info("=== 统一规则转换器（增强版）===")
    logger.info(f"目标平台: {', '.join(config.TARGET_PLATFORMS)}")
    
    try:
        converter = UnifiedConverter(config)
        converter.run()
        logger.info("规则转换完成！")
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()