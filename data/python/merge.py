#!/usr/bin/env python3
"""
AdGuard规则合并器 - 完全覆盖AdGuard/AdGuard Home语法v4.3
支持AdGuard全平台兼容（浏览器扩展/Home/Windows/Mac/Android/iOS）
输出纯净语法规则，无文件头信息
"""

import os
import re
import json
import hashlib
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional, Any
from pybloom_live import ScalableBloomFilter
from dataclasses import dataclass, field
import logging
import sys
from datetime import datetime

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass
class AdGuardConfig:
    """配置类 - 基于语法数据库v4.3"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"
    OUTPUT_DIR: Path = BASE_DIR

    # 核心功能开关
    STRICT_RFC_VALIDATION: bool = os.getenv('STRICT_RFC_VALIDATION', 'true').lower() == 'true'
    AUTO_FIX_RFC_VIOLATIONS: bool = os.getenv('AUTO_FIX_RFC_VIOLATIONS', 'true').lower() == 'true'
    AUTO_CONVERT_PURE_DOMAINS: bool = os.getenv('AUTO_CONVERT_PURE_DOMAINS', 'true').lower() == 'true'

    # 输出配置 - 纯净规则，无文件头
    OUTPUT_ALLOW: str = 'allow_adg.txt'
    OUTPUT_BLOCK: str = 'adblock_adg.txt'
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter', '*.list'])
    
    # 语法数据库路径
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    
    # 性能配置
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))
    
    # AdGuard全平台兼容性
    ENABLE_ADGUARD_COMPATIBILITY: bool = True
    TARGET_PLATFORM: str = os.getenv('TARGET_PLATFORM', 'adguard_home')  # adguard_home, adguard_browser等
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'


class AdGuardSyntaxDatabase:
    """语法数据库加载器 - 基于v4.3规范"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.db_data = {}
        self.platform_config = {}
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载语法数据库v4.3"""
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
            
            self._setup_platform_config()
            logger.info(f"语法数据库v{self.db_data.get('version', '未知')}加载完成")
            logger.info(f"目标平台: {self.config.TARGET_PLATFORM}")
            
        except Exception as e:
            logger.error(f"数据库加载失败: {e}")
            self._setup_default_config()

    def _setup_default_config(self):
        """默认配置 - 完整AdGuard语法支持"""
        self.platform_config = {
            "supported_rule_types": [
                "domain_rule", "adguard_domain_rule", "exception_rule", 
                "adguard_dns_rewrite", "adguard_home_dns_rewrite", 
                "adguard_home_client", "adguard_home_dnstype", "hosts_rule",
                "element_hiding_basic", "element_hiding_exception", "extended_css",
                "adguard_scriptlet", "adguard_redirect", "adguard_removeparam",
                "adguard_csp", "adguard_stealth_rule", "adguard_cookie_rule",
                "adguard_header", "adguard_jsonprune", "adguard_denyallow",
                "regex_rule", "url_rule"
            ],
            "supported_modifiers": [
                "domain", "client", "dnstype", "denyallow", "dnsrewrite", 
                "important", "badfilter", "third-party", "script", "image",
                "stylesheet", "object", "xmlhttprequest", "subdocument", 
                "document", "elemhide", "other", "match-case", "collapse",
                "donottrack", "websocket", "webrtc", "empty", "mp4",
                "redirect", "removeparam", "csp", "cookie", "generichide",
                "specifichide", "stealth", "app", "content", "popup",
                "header", "jsonprune", "hls", "all"
            ],
            "validation_rules": {
                "max_rule_length": 2000,
                "min_rule_length": 3
            }
        }

    def _setup_platform_config(self):
        """设置目标平台配置"""
        platform_support = self.db_data.get('platform_support', {})
        self.platform_config = platform_support.get(self.config.TARGET_PLATFORM, {})
        
        if not self.platform_config:
            logger.warning(f"未找到平台 {self.config.TARGET_PLATFORM} 的配置，使用adguard_home默认配置")
            self.platform_config = platform_support.get('adguard_home', {})

    def is_rule_supported(self, rule_type: str, modifiers: List[str]) -> bool:
        """检查规则是否被目标平台支持"""
        if not self.config.ENABLE_ADGUARD_COMPATIBILITY:
            return True
            
        supported_types = self.platform_config.get('supported_rule_types', [])
        unsupported_types = self.platform_config.get('unsupported_rule_types', [])
        
        # 检查规则类型
        if rule_type in unsupported_types:
            return False
        if supported_types and rule_type not in supported_types:
            return False
            
        # 检查修饰符
        supported_mods = self.platform_config.get('supported_modifiers', [])
        unsupported_mods = self.platform_config.get('unsupported_modifiers', [])
        
        # 检查不支持的修饰符
        for mod in modifiers:
            if mod in unsupported_mods:
                return False
                
        # 平台特定验证
        if self.config.TARGET_PLATFORM == 'adguard_home':
            return self._validate_adguard_home_rule(rule_type, modifiers)
        elif self.config.TARGET_PLATFORM == 'adguard_browser_extension':
            return self._validate_adguard_browser_rule(rule_type, modifiers)
            
        return True

    def _validate_adguard_home_rule(self, rule_type: str, modifiers: List[str]) -> bool:
        """验证AdGuard Home规则"""
        # AdGuard Home不支持浏览器相关的规则类型
        unsupported_for_home = [
            'element_hiding_basic', 'element_hiding_exception', 'extended_css',
            'adguard_scriptlet', 'adguard_redirect', 'adguard_removeparam',
            'adguard_csp', 'adguard_stealth_rule'
        ]
        
        if rule_type in unsupported_for_home:
            return False
            
        # 检查修饰符兼容性
        for mod in modifiers:
            if mod in ['script', 'image', 'stylesheet', 'elemhide']:
                return False
                
        return True

    def _validate_adguard_browser_rule(self, rule_type: str, modifiers: List[str]) -> bool:
        """验证AdGuard浏览器扩展规则"""
        # 浏览器扩展不支持DNS相关的规则类型
        unsupported_for_browser = [
            'adguard_home_dns_rewrite', 'adguard_home_client', 'adguard_home_dnstype',
            'hosts_rule'
        ]
        
        if rule_type in unsupported_for_browser:
            return False
            
        return True

    def validate_rule_length(self, rule: str) -> Tuple[bool, str]:
        """验证规则长度"""
        validation_rules = self.db_data.get('validation_rules', {})
        max_len = validation_rules.get('max_rule_length', self.config.MAX_RULE_LENGTH)
        min_len = validation_rules.get('min_rule_length', self.config.MIN_RULE_LENGTH)
        
        if len(rule) < min_len:
            return False, f"规则长度{len(rule)}小于最小值{min_len}"
        if len(rule) > max_len:
            return False, f"规则长度{len(rule)}大于最大值{max_len}"
        return True, "合规"

    def get_dns_record_types(self) -> List[str]:
        """获取支持的DNS记录类型"""
        common_patterns = self.db_data.get('common_patterns', {})
        return common_patterns.get('adguard_home_dns_rewrite_types', 
                                  ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS', 'HTTPS', 'SVCB'])

    def get_redirect_resources(self) -> List[str]:
        """获取支持的重定向资源"""
        common_patterns = self.db_data.get('common_patterns', {})
        return common_patterns.get('adguard_redirect_resources', 
                                  ['nooptext', 'noopcss', 'noophtml', 'noopjs', 'noopframe', 
                                   'noopmp3', 'noopmp4', 'noopttf', 'noopjson', 'noopico'])


class EnhancedBloomFilter:
    """增强版布隆过滤器"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.bloom = ScalableBloomFilter(
            initial_capacity=config.BLOOM_INIT_CAP,
            error_rate=config.BLOOM_ERROR_RATE,
            mode=ScalableBloomFilter.LARGE_SET_GROWTH
        )
        self.hash_set = set()

    def add(self, item: str) -> bool:
        """添加规则并返回是否重复"""
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        if item_hash in self.hash_set:
            return True
            
        self.bloom.add(item)
        self.hash_set.add(item_hash)
        return False

    def __contains__(self, item: str) -> bool:
        return hashlib.md5(item.encode('utf-8')).hexdigest() in self.hash_set


class AdGuardRuleProcessor:
    """AdGuard规则处理器 - 完全覆盖AdGuard语法"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)
        
        # 规则存储
        self.allow_rules = []
        self.block_rules = []
        
        # 统计数据
        self.stats = {
            "total_processed": 0, "invalid_rules": 0, "unsupported_rules": 0,
            "fixed_rules_count": 0, "pure_domains_converted": 0,
            "platform_specific": {
                "dns_rewrite": 0, "client_rules": 0, "dnstype_rules": 0,
                "denyallow_rules": 0, "element_hiding": 0, "scriptlet": 0,
                "redirect": 0, "removeparam": 0, "csp": 0, "header": 0,
                "jsonprune": 0, "cookie": 0, "stealth": 0
            },
            "allow": {"processed": 0, "valid": 0, "duplicates": 0},
            "block": {"processed": 0, "valid": 0, "duplicates": 0}
        }
        
        # 去重过滤器
        self.allow_bloom = EnhancedBloomFilter(config)
        self.block_bloom = EnhancedBloomFilter(config)

    # -------------------------- 国际标准验证逻辑 --------------------------
    def validate_domain(self, domain: str) -> Tuple[bool, str]:
        """RFC合规域名验证"""
        domain = domain.strip().lstrip('*.@|').rstrip('^')
        if not domain:
            return False, "域名为空"
        if len(domain) > 253:
            return False, f"域名长度{len(domain)}>253"
            
        # RFC 1035合规验证
        labels = domain.split('.')
        for i, label in enumerate(labels):
            if len(label) == 0:
                return False, "域名标签不能为空"
            if len(label) > 63:
                return False, f"标签[{label}]长度{len(label)}>63"
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False, f"标签[{label}]含非法字符"
            if label.startswith('-') or label.endswith('-'):
                return False, f"标签[{label}]不能以连字符开头或结尾"
                
        # 顶级域名验证
        tld = labels[-1]
        if len(tld) < 2:
            return False, "顶级域名太短"
        if not re.match(r'^[a-zA-Z]{2,}$', tld):
            return False, "顶级域名格式错误"
            
        return True, "RFC合规"

    def validate_ipv4(self, ip: str) -> Tuple[bool, str]:
        """RFC合规IPv4验证"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(pattern, ip):
            return False, "IPv4格式错误"
        
        # 检查保留地址
        octets = list(map(int, ip.split('.')))
        if (octets[0] == 0 or 
            octets[0] == 127 or  # 环回
            (octets[0] == 10) or  # 私有A类
            (octets[0] == 172 and 16 <= octets[1] <= 31) or  # 私有B类
            (octets[0] == 192 and octets[1] == 168) or  # 私有C类
            (octets[0] == 169 and octets[1] == 254) or  # 链路本地
            (octets[0] >= 224)):  # 组播/保留
            return True, "RFC合规(保留地址)"
            
        return True, "RFC合规"

    def validate_ipv6(self, ip: str) -> Tuple[bool, str]:
        """RFC合规IPv6验证"""
        # 简化IPv6验证
        if '::' in ip:
            if ip.count('::') > 1:
                return False, "IPv6格式错误(多个::)"
            parts = ip.split('::')
            if len(parts) != 2:
                return False, "IPv6格式错误"
                
        # 基本格式检查
        if not re.match(r'^[0-9a-fA-F:]+$', ip.replace('::', '')):
            return False, "IPv6格式错误(非法字符)"
            
        return True, "RFC合规"

    # -------------------------- 自动修复逻辑 --------------------------
    def auto_fix_domain(self, domain: str) -> Tuple[str, str]:
        """自动修复域名格式问题"""
        original = domain
        domain = domain.strip()
        
        # 移除非法前缀
        domain = re.sub(r'^[*.@|]+', '', domain)
        
        # 移除非法后缀
        domain = re.sub(r'[\^|]+$', '', domain)
        
        # 转换为小写
        domain = domain.lower()
        
        # 修复连续的连字符
        domain = re.sub(r'-{2,}', '-', domain)
        
        # 移除开头和结尾的连字符
        domain = domain.strip('-')
        
        # 验证修复后的域名
        is_valid, msg = self.validate_domain(domain)
        if is_valid:
            return domain, f"自动修复: {original} -> {domain}"
        else:
            return original, f"修复失败: {msg}"

    def auto_fix_rule_format(self, rule: str) -> Tuple[str, str]:
        """自动修复规则格式"""
        original = rule
        
        # 修复多余的空格
        rule = re.sub(r'\s+', ' ', rule.strip())
        
        # 修复修饰符格式
        if '$' in rule:
            parts = rule.split('$', 1)
            pattern = parts[0].strip()
            modifiers = parts[1].strip()
            
            # 修复修饰符中的空格
            modifiers = re.sub(r',\s+', ',', modifiers)
            modifiers = re.sub(r'\s+,', ',', modifiers)
            
            rule = f"{pattern}${modifiers}"
        
        return rule, f"格式修复: {original} -> {rule}"

    # -------------------------- 完整AdGuard语法分析 --------------------------
    def analyze_rule(self, rule: str, is_allow_file: bool = False) -> Dict[str, Any]:
        """完整AdGuard语法分析"""
        result = {
            'original': rule,
            'normalized': rule.strip(),
            'type': 'unknown',
            'pattern_type': 'unknown',
            'modifiers': [],
            'modifier_details': {},
            'is_allow': is_allow_file,
            'is_valid': False,
            'is_supported': True,
            'validation_msg': "",
            'needs_fix': False,
            'fix_suggestion': ""
        }
        
        # 跳过注释和空行
        if not rule.strip() or rule.strip().startswith(('#', '!', ';')):
            result['type'] = 'comment'
            return result
            
        rule_clean = rule.strip()
        
        # 检查规则长度
        length_ok, length_msg = self.syntax_db.validate_rule_length(rule_clean)
        if not length_ok:
            result['validation_msg'] = length_msg
            return result

        # 识别规则类型和修饰符
        self._classify_rule_comprehensive(rule_clean, result)
        
        # 验证规则有效性
        self._validate_rule_comprehensive(result)
        
        # 自动修复建议
        if not result['is_valid'] and self.config.AUTO_FIX_RFC_VIOLATIONS:
            self._suggest_fixes(result)
        
        # 检查平台支持
        result['is_supported'] = self.syntax_db.is_rule_supported(
            result['pattern_type'], result['modifiers']
        )
        
        return result

    def _classify_rule_comprehensive(self, rule: str, result: Dict[str, Any]):
        """全面分类AdGuard规则类型"""
        # 检查是否为允许规则
        if rule.startswith('@@'):
            result['is_allow'] = True
            rule_body = rule[2:]
        else:
            rule_body = rule

        # 提取修饰符
        modifier_part = ""
        if '$' in rule_body:
            parts = rule_body.split('$', 1)
            rule_pattern = parts[0]
            modifier_part = parts[1]
            self._extract_modifiers_comprehensive(modifier_part, result)
        else:
            rule_pattern = rule_body

        # 识别基本规则类型
        self._identify_basic_rule_type(rule_pattern, result)
        
        # 根据修饰符进一步分类
        self._classify_by_modifiers(result)

    def _extract_modifiers_comprehensive(self, modifier_str: str, result: Dict[str, Any]):
        """全面提取AdGuard修饰符"""
        # AdGuard完整修饰符列表
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
            'object': r'\bobject\b',
            'xmlhttprequest': r'\bxmlhttprequest\b',
            'subdocument': r'\bsubdocument\b',
            'document': r'\bdocument\b',
            'elemhide': r'\belemhide\b',
            'other': r'\bother\b',
            'match-case': r'\bmatch-case\b',
            'collapse': r'\bcollapse\b',
            'donottrack': r'\bdonottrack\b',
            'websocket': r'\bwebsocket\b',
            'webrtc': r'\bwebrtc\b',
            'empty': r'\bempty\b',
            'mp4': r'\bmp4\b',
            'redirect': r'redirect=([^,\s]+)',
            'removeparam': r'removeparam=([^,\s]+)',
            'csp': r'csp=([^,\s]+)',
            'cookie': r'cookie=([^,\s]+)',
            'generichide': r'\bgenerichide\b',
            'specifichide': r'\bspecifichide\b',
            'stealth': r'\bstealth\b',
            'app': r'app=([^,\s]+)',
            'content': r'\bcontent\b',
            'popup': r'\bpopup\b',
            'header': r'header=([^,\s]+)',
            'jsonprune': r'jsonprune=([^,\s]+)',
            'hls': r'\bhls\b',
            'all': r'\ball\b'
        }
        
        for mod_name, pattern in modifier_patterns.items():
            matches = re.findall(pattern, modifier_str)
            if matches:
                result['modifiers'].append(mod_name)
                if mod_name in ['domain', 'client', 'dnstype', 'denyallow', 'dnsrewrite', 
                               'redirect', 'removeparam', 'csp', 'cookie', 'app', 'header', 'jsonprune']:
                    result['modifier_details'][mod_name] = matches
                else:
                    result['modifier_details'][mod_name] = True

    def _identify_basic_rule_type(self, rule_pattern: str, result: Dict[str, Any]):
        """识别基本规则类型"""
        # AdGuard域名规则
        if re.match(r'^\|\|[a-zA-Z0-9.-]+\^$', rule_pattern):
            result['pattern_type'] = 'adguard_domain_rule'
        # 元素隐藏规则
        elif rule_pattern.startswith('##'):
            result['pattern_type'] = 'element_hiding_basic'
        elif rule_pattern.startswith('#@#'):
            result['pattern_type'] = 'element_hiding_exception'
        elif rule_pattern.startswith('#?#'):
            result['pattern_type'] = 'extended_css'
        elif rule_pattern.startswith('#%#'):
            result['pattern_type'] = 'adguard_scriptlet'
        # 纯域名规则
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule_pattern):
            result['pattern_type'] = 'domain_rule'
        # Hosts规则
        elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+[^\s]+', rule_pattern):
            result['pattern_type'] = 'hosts_rule'
        # URL规则
        elif rule_pattern.startswith('|http') or rule_pattern.startswith('|https'):
            result['pattern_type'] = 'url_rule'
        # 正则规则
        elif rule_pattern.startswith('/') and rule_pattern.endswith('/'):
            result['pattern_type'] = 'regex_rule'
        else:
            result['pattern_type'] = 'unknown'

    def _classify_by_modifiers(self, result: Dict[str, Any]):
        """根据修饰符进一步分类"""
        modifiers = result['modifiers']
        
        if 'dnsrewrite' in modifiers:
            result['pattern_type'] = 'adguard_dns_rewrite'
        elif 'client' in modifiers and 'dnstype' in modifiers:
            result['pattern_type'] = 'adguard_home_client_dnstype'
        elif 'client' in modifiers:
            result['pattern_type'] = 'adguard_home_client'
        elif 'dnstype' in modifiers:
            result['pattern_type'] = 'adguard_home_dnstype'
        elif 'denyallow' in modifiers:
            result['pattern_type'] = 'adguard_denyallow'
        elif 'redirect' in modifiers:
            result['pattern_type'] = 'adguard_redirect'
        elif 'removeparam' in modifiers:
            result['pattern_type'] = 'adguard_removeparam'
        elif 'csp' in modifiers:
            result['pattern_type'] = 'adguard_csp'
        elif 'cookie' in modifiers:
            result['pattern_type'] = 'adguard_cookie_rule'
        elif 'stealth' in modifiers:
            result['pattern_type'] = 'adguard_stealth_rule'
        elif 'header' in modifiers:
            result['pattern_type'] = 'adguard_header'
        elif 'jsonprune' in modifiers:
            result['pattern_type'] = 'adguard_jsonprune'

    def _validate_rule_comprehensive(self, result: Dict[str, Any]):
        """全面验证规则有效性"""
        rule = result['normalized']
        pattern_type = result['pattern_type']
        
        try:
            if pattern_type == 'adguard_domain_rule':
                self._validate_adguard_domain_rule(rule, result)
            elif pattern_type == 'domain_rule':
                self._validate_domain_rule(rule, result)
            elif pattern_type == 'element_hiding_basic':
                self._validate_element_hiding_rule(rule, result)
            elif pattern_type == 'adguard_dns_rewrite':
                self._validate_dns_rewrite_rule(rule, result)
            elif pattern_type == 'hosts_rule':
                self._validate_hosts_rule(rule, result)
            elif pattern_type == 'adguard_redirect':
                self._validate_redirect_rule(rule, result)
            elif pattern_type == 'adguard_removeparam':
                self._validate_removeparam_rule(rule, result)
            elif pattern_type == 'adguard_csp':
                self._validate_csp_rule(rule, result)
            elif pattern_type == 'adguard_home_client':
                self._validate_client_rule(rule, result)
            elif pattern_type == 'adguard_home_dnstype':
                self._validate_dnstype_rule(rule, result)
            else:
                # 对于未知类型，进行基本验证
                result['is_valid'] = len(rule) >= self.config.MIN_RULE_LENGTH
                result['validation_msg'] = "基本验证通过" if result['is_valid'] else "规则过短"
                
        except Exception as e:
            result['is_valid'] = False
            result['validation_msg'] = f"验证异常: {str(e)}"

    def _validate_adguard_domain_rule(self, rule: str, result: Dict[str, Any]):
        """验证AdGuard域名规则"""
        domain_match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^$', rule.split('$')[0])
        if not domain_match:
            result['is_valid'] = False
            result['validation_msg'] = "AdGuard域名规则格式错误"
            return
            
        domain = domain_match.group(1)
        is_valid, msg = self.validate_domain(domain)
        result['is_valid'] = is_valid
        result['validation_msg'] = f"AdGuard域名规则: {msg}"

    def _validate_domain_rule(self, rule: str, result: Dict[str, Any]):
        """验证纯域名规则"""
        domain = rule.split('$')[0]  # 移除修饰符部分
        is_valid, msg = self.validate_domain(domain)
        result['is_valid'] = is_valid
        result['validation_msg'] = f"域名规则: {msg}"

    def _validate_element_hiding_rule(self, rule: str, result: Dict[str, Any]):
        """验证元素隐藏规则"""
        # 基本CSS选择器验证
        selector = rule[2:]  # 移除##前缀
        if len(selector) < 1:
            result['is_valid'] = False
            result['validation_msg'] = "元素选择器为空"
        else:
            result['is_valid'] = True
            result['validation_msg'] = "元素隐藏规则有效"

    def _validate_dns_rewrite_rule(self, rule: str, result: Dict[str, Any]):
        """验证DNS重写规则"""
        match = re.search(r'\$dnsrewrite=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "DNS重写规则格式错误"
            return
            
        rewrite_content = match.group(1)
        parts = rewrite_content.split(';')
        if len(parts) < 3:
            result['is_valid'] = False
            result['validation_msg'] = "DNS重写参数不足"
            return
            
        record_type, domain, value = parts[0].upper(), parts[1], parts[2]
        allowed_types = self.syntax_db.get_dns_record_types()
        
        if record_type not in allowed_types:
            result['is_valid'] = False
            result['validation_msg'] = f"不支持的DNS记录类型: {record_type}"
            return
            
        domain_valid = self.validate_domain(domain)[0]
        if not domain_valid:
            result['is_valid'] = False
            result['validation_msg'] = "域名格式错误"
            return
            
        # 记录类型特定验证
        if record_type in ['A', 'AAAA']:
            ip_valid = self.validate_ipv4(value)[0] if record_type == 'A' else self.validate_ipv6(value)[0]
            result['is_valid'] = ip_valid
            result['validation_msg'] = "DNS重写规则有效" if ip_valid else f"{record_type}记录值无效"
        else:
            result['is_valid'] = True
            result['validation_msg'] = "DNS重写规则有效"

    def _validate_hosts_rule(self, rule: str, result: Dict[str, Any]):
        """验证Hosts规则"""
        parts = rule.split()
        if len(parts) < 2:
            result['is_valid'] = False
            result['validation_msg'] = "Hosts规则格式错误"
            return
            
        ip_valid = self.validate_ipv4(parts[0])[0] or self.validate_ipv6(parts[0])[0]
        domain_valid = self.validate_domain(parts[1])[0]
        result['is_valid'] = ip_valid and domain_valid
        result['validation_msg'] = "Hosts规则有效" if result['is_valid'] else "Hosts规则无效"

    def _validate_redirect_rule(self, rule: str, result: Dict[str, Any]):
        """验证重定向规则"""
        match = re.search(r'\$redirect=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "重定向规则格式错误"
            return
            
        redirect_resource = match.group(1)
        allowed_resources = self.syntax_db.get_redirect_resources()
        
        result['is_valid'] = redirect_resource in allowed_resources
        result['validation_msg'] = "重定向规则有效" if result['is_valid'] else f"不支持的重定向资源: {redirect_resource}"

    def _validate_removeparam_rule(self, rule: str, result: Dict[str, Any]):
        """验证移除参数规则"""
        match = re.search(r'\$removeparam=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "移除参数规则格式错误"
            return
            
        param_pattern = match.group(1)
        # 基本参数模式验证
        if len(param_pattern) < 1:
            result['is_valid'] = False
            result['validation_msg'] = "参数模式为空"
        else:
            result['is_valid'] = True
            result['validation_msg'] = "移除参数规则有效"

    def _validate_csp_rule(self, rule: str, result: Dict[str, Any]):
        """验证CSP规则"""
        match = re.search(r'\$csp=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "CSP规则格式错误"
            return
            
        csp_policy = match.group(1)
        # 基本CSP策略验证
        if len(csp_policy) < 1:
            result['is_valid'] = False
            result['validation_msg'] = "CSP策略为空"
        else:
            result['is_valid'] = True
            result['validation_msg'] = "CSP规则有效"

    def _validate_client_rule(self, rule: str, result: Dict[str, Any]):
        """验证客户端规则"""
        match = re.search(r'\$client=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "客户端规则格式错误"
            return
            
        client_spec = match.group(1)
        # 客户端规格验证 (IP, MAC, 或客户端名称)
        ip_valid = self.validate_ipv4(client_spec)[0] or self.validate_ipv6(client_spec)[0]
        mac_valid = re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_spec)
        name_valid = re.match(r'^[a-zA-Z0-9.-]+$', client_spec)
        
        result['is_valid'] = ip_valid or mac_valid or name_valid
        result['validation_msg'] = "客户端规则有效" if result['is_valid'] else "客户端规格无效"

    def _validate_dnstype_rule(self, rule: str, result: Dict[str, Any]):
        """验证DNS类型规则"""
        match = re.search(r'\$dnstype=([^,\s]+)', rule)
        if not match:
            result['is_valid'] = False
            result['validation_msg'] = "DNS类型规则格式错误"
            return
            
        dnstype = match.group(1).upper()
        allowed_types = self.syntax_db.get_dns_record_types() + ['ANY']
        
        result['is_valid'] = dnstype in allowed_types
        result['validation_msg'] = "DNS类型规则有效" if result['is_valid'] else f"不支持的DNS类型: {dnstype}"

    def _suggest_fixes(self, result: Dict[str, Any]):
        """提供自动修复建议"""
        rule = result['normalized']
        pattern_type = result['pattern_type']
        
        if pattern_type in ['adguard_domain_rule', 'domain_rule']:
            domain_part = rule.split('$')[0]
            if pattern_type == 'adguard_domain_rule':
                domain_match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^$', domain_part)
                if domain_match:
                    domain = domain_match.group(1)
                    fixed_domain, fix_msg = self.auto_fix_domain(domain)
                    if fixed_domain != domain:
                        result['needs_fix'] = True
                        result['fix_suggestion'] = f"||{fixed_domain}^" + rule[len(domain_part):]
                        result['validation_msg'] += f" | {fix_msg}"
            else:
                fixed_domain, fix_msg = self.auto_fix_domain(domain_part)
                if fixed_domain != domain_part:
                    result['needs_fix'] = True
                    result['fix_suggestion'] = fixed_domain + rule[len(domain_part):]
                    result['validation_msg'] += f" | {fix_msg}"
        
        # 通用格式修复
        fixed_rule, format_msg = self.auto_fix_rule_format(rule)
        if fixed_rule != rule:
            result['needs_fix'] = True
            if not result['fix_suggestion']:
                result['fix_suggestion'] = fixed_rule
            result['validation_msg'] += f" | {format_msg}"

    # -------------------------- 规则处理逻辑 --------------------------
    def process_rule(self, rule: str, is_allow_file: bool = False):
        """处理单个规则"""
        self.stats["total_processed"] += 1
        rule_type = "allow" if is_allow_file else "block"
        self.stats[rule_type]["processed"] += 1

        analysis = self.analyze_rule(rule, is_allow_file)
        
        if not analysis['is_valid']:
            self.stats["invalid_rules"] += 1
            logger.debug(f"无效规则: {rule} - {analysis['validation_msg']}")
            return
            
        if not analysis['is_supported']:
            self.stats["unsupported_rules"] += 1
            logger.debug(f"不支持的规则: {rule} - 类型: {analysis['pattern_type']}")
            return

        # 应用自动修复
        normalized_rule = self._normalize_rule_with_fixes(analysis)
        if not normalized_rule:
            return

        self._store_rule(normalized_rule, analysis)

    def _normalize_rule_with_fixes(self, analysis: Dict[str, Any]) -> Optional[str]:
        """应用修复并标准化规则"""
        rule = analysis['normalized']
        
        # 应用自动修复
        if analysis['needs_fix'] and analysis['fix_suggestion']:
            rule = analysis['fix_suggestion']
            self.stats['fixed_rules_count'] += 1
            logger.debug(f"规则已修复: {analysis['original']} -> {rule}")

        # 纯域名转换
        if (analysis['pattern_type'] == 'domain_rule' and 
            self.config.AUTO_CONVERT_PURE_DOMAINS and
            not analysis['modifiers']):  # 只有纯域名且无修饰符时才转换
            
            domain = analysis['normalized'].split('$')[0]
            if analysis['is_allow']:
                rule = f"@@||{domain}^"
            else:
                rule = f"||{domain}^"
            self.stats['pure_domains_converted'] += 1

        # 确保允许规则有正确前缀
        if analysis['is_allow'] and not rule.startswith('@@'):
            if analysis['pattern_type'] in ['adguard_domain_rule', 'domain_rule']:
                if rule.startswith('||'):
                    rule = '@@' + rule
                else:
                    domain = rule.split('$')[0]
                    rule = f"@@||{domain}^" + rule[len(domain):]

        # 标准化修饰符顺序
        if '$' in rule:
            rule = self._normalize_modifiers_order(rule)

        return rule

    def _normalize_modifiers_order(self, rule: str) -> str:
        """标准化修饰符顺序"""
        parts = rule.split('$', 1)
        if len(parts) == 2:
            pattern = parts[0]
            modifiers = [m.strip() for m in parts[1].split(',')]
            
            # 分类修饰符
            important_mods = [m for m in modifiers if 'important' in m]
            domain_mods = [m for m in modifiers if m.startswith('domain=')]
            client_mods = [m for m in modifiers if m.startswith('client=')]
            dnstype_mods = [m for m in modifiers if m.startswith('dnstype=')]
            dnsrewrite_mods = [m for m in modifiers if m.startswith('dnsrewrite=')]
            denyallow_mods = [m for m in modifiers if m.startswith('denyallow=')]
            
            # 其他修饰符
            other_mods = [m for m in modifiers if m not in 
                         important_mods + domain_mods + client_mods + 
                         dnstype_mods + dnsrewrite_mods + denyallow_mods]
            
            # 排序顺序：重要修饰符 -> 域名相关 -> 客户端相关 -> DNS相关 -> 其他
            sorted_mods = (important_mods + domain_mods + client_mods + 
                          dnstype_mods + dnsrewrite_mods + denyallow_mods + 
                          sorted(other_mods))
            
            rule = pattern + '$' + ','.join(sorted_mods)
        return rule

    def _store_rule(self, rule: str, analysis: Dict[str, Any]):
        """存储规则"""
        if analysis['is_allow']:
            bloom = self.allow_bloom
            rules_list = self.allow_rules
            stats_key = "allow"
        else:
            bloom = self.block_bloom
            rules_list = self.block_rules
            stats_key = "block"

        if bloom.add(rule):
            self.stats[stats_key]["duplicates"] += 1
            return

        rules_list.append(rule)
        self.stats[stats_key]["valid"] += 1
        
        # 统计平台特定规则
        pattern_type = analysis['pattern_type']
        if 'dns_rewrite' in pattern_type:
            self.stats['platform_specific']['dns_rewrite'] += 1
        elif 'client' in pattern_type:
            self.stats['platform_specific']['client_rules'] += 1
        elif 'dnstype' in pattern_type:
            self.stats['platform_specific']['dnstype_rules'] += 1
        elif 'denyallow' in pattern_type:
            self.stats['platform_specific']['denyallow_rules'] += 1
        elif 'element_hiding' in pattern_type:
            self.stats['platform_specific']['element_hiding'] += 1
        elif 'scriptlet' in pattern_type:
            self.stats['platform_specific']['scriptlet'] += 1
        elif 'redirect' in pattern_type:
            self.stats['platform_specific']['redirect'] += 1
        elif 'removeparam' in pattern_type:
            self.stats['platform_specific']['removeparam'] += 1
        elif 'csp' in pattern_type:
            self.stats['platform_specific']['csp'] += 1
        elif 'header' in pattern_type:
            self.stats['platform_specific']['header'] += 1
        elif 'jsonprune' in pattern_type:
            self.stats['platform_specific']['jsonprune'] += 1
        elif 'cookie' in pattern_type:
            self.stats['platform_specific']['cookie'] += 1
        elif 'stealth' in pattern_type:
            self.stats['platform_specific']['stealth'] += 1

    def process_files(self):
        """处理所有输入文件"""
        input_files = self._get_input_files()
        if not input_files:
            logger.warning("未找到输入文件")
            return
            
        logger.info(f"开始处理 {len(input_files)} 个文件...")
        
        for file_path, is_allow_file in input_files:
            try:
                self._process_single_file(file_path, is_allow_file)
                logger.info(f"处理完成: {file_path.name} (允许规则: {is_allow_file})")
            except Exception as e:
                logger.error(f"文件处理失败: {file_path.name} - {e}")

    def _get_input_files(self) -> List[Tuple[Path, bool]]:
        """获取输入文件列表"""
        if not self.config.INPUT_DIR.exists():
            logger.warning(f"输入目录不存在: {self.config.INPUT_DIR}")
            return []
            
        input_files = []
        for pattern in self.config.ADBLOCK_PATTERNS:
            for file_path in self.config.INPUT_DIR.rglob(pattern):
                if file_path.is_file():
                    is_allow = 'allow' in file_path.name.lower()
                    input_files.append((file_path, is_allow))
                    
        logger.info(f"找到 {len(input_files)} 个输入文件")
        return input_files

    def _process_single_file(self, file_path: Path, is_allow_file: bool):
        """处理单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line_num, line in enumerate(f, 1):
                    clean_line = line.strip()
                    if clean_line:  # 跳过空行
                        batch.append(clean_line)
                    
                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        for rule in batch:
                            self.process_rule(rule, is_allow_file)
                        batch = []
                        
                # 处理剩余批次
                if batch:
                    for rule in batch:
                        self.process_rule(rule, is_allow_file)
                        
        except UnicodeDecodeError:
            # 尝试其他编码
            with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                for line in f:
                    self.process_rule(line.strip(), is_allow_file)

    def save_results(self):
        """保存纯净规则文件 - 无文件头"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # 保存允许规则 - 纯净输出
        if self.allow_rules:
            allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ALLOW
            with open(allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.allow_rules))))
            logger.info(f"允许规则已保存 ({len(set(self.allow_rules))}条): {allow_path}")
        
        # 保存拦截规则 - 纯净输出
        if self.block_rules:
            block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_BLOCK
            with open(block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.block_rules))))
            logger.info(f"拦截规则已保存 ({len(set(self.block_rules))}条): {block_path}")
            
        self._print_statistics()

    def _print_statistics(self):
        """打印详细统计信息"""
        logger.info("\n" + "="*60)
        logger.info("AdGuard规则处理统计摘要")
        logger.info("="*60)
        logger.info(f"总处理规则数: {self.stats['total_processed']}")
        logger.info(f"有效允许规则: {len(set(self.allow_rules))}")
        logger.info(f"有效拦截规则: {len(set(self.block_rules))}")
        logger.info(f"无效规则: {self.stats['invalid_rules']}")
        logger.info(f"不支持的规则: {self.stats['unsupported_rules']}")
        logger.info(f"重复规则: {self.stats['allow']['duplicates'] + self.stats['block']['duplicates']}")
        logger.info(f"自动修复规则: {self.stats['fixed_rules_count']}")
        logger.info(f"纯域名转换: {self.stats['pure_domains_converted']}")
        
        # 平台特定规则统计
        platform_stats = self.stats['platform_specific']
        if any(platform_stats.values()):
            logger.info("\n平台特定规则统计:")
            for rule_type, count in platform_stats.items():
                if count > 0:
                    logger.info(f"  {rule_type}: {count}")


def main():
    config = AdGuardConfig()
    logger.info("=== AdGuard规则合并器（完全覆盖AdGuard语法v4.3）===")
    logger.info(f"目标平台: {config.TARGET_PLATFORM}")
    logger.info(f"输入目录: {config.INPUT_DIR}")
    logger.info(f"输出目录: {config.OUTPUT_DIR}")
    
    try:
        processor = AdGuardRuleProcessor(config)
        processor.process_files()
        processor.save_results()
        logger.info("处理完成！输出纯净AdGuard语法规则")
        return 0
    except Exception as e:
        logger.error(f"执行失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())