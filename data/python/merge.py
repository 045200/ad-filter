#!/usr/bin/env python3
"""
AdGuard规则合并器 - 支持多语法输入转AdGuard（含AdGuard Home）语法
输入支持：AdGuard规则、AdGuard Home规则、Hosts规则、纯Domains域名；输出为AdGuard（含AdGuard Home）标准语法
支持RFC 1034/1035/1123/2181（域名）、RFC 791（IPv4）、RFC 2373/5952（IPv6）
【核心功能】纯Domains自动转AdGuard格式、RFC违规修复、AdGuard Home兼容性过滤
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
    """配置类 - 新增纯Domains转换开关"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"
    OUTPUT_DIR: Path = BASE_DIR

    # 核心功能开关
    STRICT_RFC_VALIDATION: bool = os.getenv('STRICT_RFC_VALIDATION', 'true').lower() == 'true'
    AUTO_FIX_RFC_VIOLATIONS: bool = os.getenv('AUTO_FIX_RFC_VIOLATIONS', 'true').lower() == 'true'
    AUTO_CONVERT_PURE_DOMAINS: bool = os.getenv('AUTO_CONVERT_PURE_DOMAINS', 'true').lower() == 'true'  # 纯Domains转换开关

    # 允许的DNS重写记录类型（AdGuard Home支持）
    ALLOWED_DNS_RECORD_TYPES: List[str] = field(default_factory=lambda: ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS'])

    # 原有配置保留
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter', '*.list'])  # 支持更多输入文件后缀
    OUTPUT_ADG: str = 'adguard_home_compatible.txt'  # 合并输出AdGuard（含AdGuard Home）规则
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))
    ENABLE_ADGUARD_HOME_COMPATIBILITY: bool = True  # 强制开启AdGuard Home兼容性
    NORMALIZE_DOMAINS: bool = True


class AdGuardSyntaxDatabase:
    """语法数据库 - 强化AdGuard Home支持规则"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.rule_types = {}
        self.modifiers = {}
        self.adguard_home_specific = {}  # AdGuard Home专属配置
        self.performance_config = {}
        self.db_path = None
        self.version = "未知"
        self.allowed_dns_record_types = []
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载数据库 - 优先读取AdGuard Home支持规则"""
        possible_paths = [
            self.config.SYNTAX_DB_FILE,
            self.config.BASE_DIR / "adblock_syntax_db.json",
            Path(__file__).parent / "adblock_syntax_db.json"
        ]
        for path in possible_paths:
            if path.exists():
                self.db_path = path
                break
        if not self.db_path:
            # 无数据库时使用默认AdGuard Home支持规则（兜底）
            self.allowed_dns_record_types = self.config.ALLOWED_DNS_RECORD_TYPES
            self.adguard_home_specific = {
                "supported_rule_types": ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"],
                "unsupported_rule_types": ["unknown_rule", "invalid_rule"],
                "unsupported_modifiers": ["app", "extension"]  # AdGuard Home不支持的修饰符
            }
            logger.warning("未找到语法数据库，使用默认AdGuard Home支持规则")
            return

        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                db_data = json.load(f)
            self.validate_database_integrity(db_data)
            
            self.rule_types = db_data.get('rule_types', {})
            self.modifiers = db_data.get('modifiers', {})
            self.version = db_data.get('version', '未知')
            # 读取AdGuard Home支持配置
            self.adguard_home_specific = db_data.get('platform_support', {}).get('adguard_home', {}) or {
                "supported_rule_types": ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"],
                "unsupported_rule_types": ["unknown_rule", "invalid_rule"],
                "unsupported_modifiers": ["app", "extension"]
            }
            # 读取允许的DNS记录类型
            self.allowed_dns_record_types = db_data.get(
                'common_patterns', {}
            ).get('adguard_home_dns_rewrite_types', self.config.ALLOWED_DNS_RECORD_TYPES)
            self.config.ALLOWED_DNS_RECORD_TYPES = self.allowed_dns_record_types
            
            # 布隆过滤器配置同步
            self.performance_config = db_data.get(
                'performance_optimization', {}
            ).get('bloom_filter_config', {})
            if self.performance_config:
                self.config.BLOOM_INIT_CAP = self.performance_config.get(
                    'initial_capacity', self.config.BLOOM_INIT_CAP
                )
                self.config.BLOOM_ERROR_RATE = self.performance_config.get(
                    'error_rate', self.config.BLOOM_ERROR_RATE
                )
                
            logger.info(f"数据库加载完成（版本: {self.version}），AdGuard Home支持DNS类型: {self.allowed_dns_record_types}")
        except Exception as e:
            logger.error(f"数据库加载失败，使用默认配置: {e}")
            self.allowed_dns_record_types = self.config.ALLOWED_DNS_RECORD_TYPES
            self.adguard_home_specific = {
                "supported_rule_types": ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"],
                "unsupported_rule_types": ["unknown_rule", "invalid_rule"],
                "unsupported_modifiers": ["app", "extension"]
            }

    def validate_database_integrity(self, db_data: Dict) -> bool:
        """验证数据库核心字段"""
        required_fields = ["platform_support", "common_patterns"]
        missing_fields = [f for f in required_fields if f not in db_data]
        if missing_fields:
            logger.warning(f"数据库缺少字段: {missing_fields}，使用默认值")
        # 验证AdGuard Home配置格式
        if not isinstance(self.adguard_home_specific.get('supported_rule_types', []), list):
            self.adguard_home_specific['supported_rule_types'] = ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"]
        return True

    def is_adguard_home_compatible(self, rule_type: str, modifiers: List[str]) -> bool:
        """严格校验AdGuard Home兼容性"""
        if not self.config.ENABLE_ADGUARD_HOME_COMPATIBILITY:
            return True
        # 校验规则类型
        supported_types = self.adguard_home_specific.get('supported_rule_types', [])
        unsupported_types = self.adguard_home_specific.get('unsupported_rule_types', [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False
        # 校验修饰符
        unsupported_modifiers = self.adguard_home_specific.get('unsupported_modifiers', [])
        return not any(mod in modifiers for mod in unsupported_modifiers)


class EnhancedBloomFilter:
    """布隆过滤器 - 去重优化"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.bloom = ScalableBloomFilter(
            initial_capacity=config.BLOOM_INIT_CAP,
            error_rate=config.BLOOM_ERROR_RATE,
            mode=ScalableBloomFilter.LARGE_SET_GROWTH
        )
        self.hash_set = set()
        self.false_positive_count = 0

    def add(self, item: str) -> bool:
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        if item in self.bloom:
            if item_hash not in self.hash_set:
                self.false_positive_count += 1
                return False
            return True
        self.bloom.add(item)
        self.hash_set.add(item_hash)
        return False

    def __contains__(self, item: str) -> bool:
        return hashlib.md5(item.encode('utf-8')).hexdigest() in self.hash_set

    def get_stats(self) -> Dict[str, Any]:
        total = len(self.hash_set)
        return {
            "total_items": total,
            "false_positive_count": self.false_positive_count,
            "false_positive_rate": self.false_positive_count / total if total > 0 else 0
        }


class AdGuardConverter:
    """核心转换器 - 新增纯Domains转换+多语法适配"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)
        self.adguard_filter = EnhancedBloomFilter(config)
        
        # 规则存储与统计（新增纯Domains转换统计）
        self.adguard_rules = []  # 合并存储AdGuard（含AdGuard Home）规则
        self.stats = {
            "total_processed": 0, "valid_rules": 0, "duplicates": 0,
            "invalid_rules": 0, "rfc_violation_rules": 0, "fixed_rules_count": 0,
            "pure_domains_converted": 0,  # 纯Domains转换数量
            "adhome_compatible_rules": 0, "adhome_incompatible_rules": 0
        }
        self.fixed_records = []  # 修复/转换记录
        self.file_stats = {"total_files": 0, "processed_files": 0}

    def github_log(self, level: str, message: str):
        """日志适配GitHub Actions"""
        if self.config.GITHUB_ACTIONS:
            gh_level = {"warning": "warning", "error": "error", "debug": "debug"}.get(level, "notice")
            print(f"::{gh_level} ::{message}")
        else:
            getattr(logger, level)(message)

    # -------------------------- 基础验证：RFC标准（保留并优化） --------------------------
    def validate_domain(self, domain: str) -> Tuple[bool, str]:
        """域名验证（RFC 1034/1035/1123/2181）"""
        domain = domain.strip().lstrip('*.@|').rstrip('^')
        if not domain:
            return False, "域名为空"
        if len(domain) > 253:
            return False, f"域名长度{len(domain)}>253（RFC 1035）"
        labels = domain.split('.')
        for idx, label in enumerate(labels):
            if len(label) == 0 or len(label) > 63:
                return False, f"标签[{label}]长度{len(label)}（需1-63，RFC 1035）"
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False, f"标签[{label}]含非法字符（仅字母/数字/-，RFC 1123）"
            if idx == len(labels)-1 and label.isdigit():
                return False, f"顶级域名[{label}]为纯数字（RFC 2181）"
        if '--' in domain:
            return False, f"域名含连续连字符（RFC 2181）"
        return True, "合规"

    def validate_ipv4(self, ipv4: str) -> Tuple[bool, str]:
        """IPv4验证（RFC 791）"""
        ipv4 = ipv4.strip()
        pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if not pattern.match(ipv4):
            return False, f"IPv4[{ipv4}]格式错误（需点分十进制，每段0-255，RFC 791）"
        if ipv4 in ['0.0.0.0', '255.255.255.255']:
            return False, "IPv4为无效地址（0.0.0.0/广播地址，RFC 791）"
        return True, "合规"

    def validate_ipv6(self, ipv6: str) -> Tuple[bool, str]:
        """IPv6验证（RFC 2373/RFC 5952）"""
        ipv6 = ipv6.strip()
        try:
            if '::' in ipv6:
                if ipv6.count('::') > 1:
                    return False, "IPv6含多个零压缩标记（::只能一次，RFC 5952）"
                left, right = ipv6.split('::')
                left_segs = left.split(':') if left else []
                right_segs = right.split(':') if right else []
                if len(left_segs) + len(right_segs) > 8:
                    return False, "IPv6段数超过8（RFC 2373）"
                for seg in left_segs + right_segs:
                    if seg and (len(seg) > 4 or not re.match(r'^[0-9a-fA-F]+$', seg)):
                        return False, f"IPv6段[{seg}]非法（需1-4位十六进制，RFC 5952）"
            else:
                segs = ipv6.split(':')
                if len(segs) != 8:
                    return False, f"IPv6段数{len(segs)}（需8段，无压缩时，RFC 2373）"
                for seg in segs:
                    if len(seg) > 4 or not re.match(r'^[0-9a-fA-F]+$', seg):
                        return False, f"IPv6段[{seg}]非法（需1-4位十六进制，RFC 5952）"
            if ipv6 in ['::', '::/128']:
                return False, "IPv6为无效地址（RFC 2373）"
        except Exception:
            return False, f"IPv6[{ipv6}]格式错误（RFC 2373/5952）"
        return True, "合规"

    def validate_dns_rewrite(self, rewrite_rule: str) -> Tuple[bool, str]:
        """DNS重写规则验证（AdGuard Home支持，RFC 1035）"""
        match = re.search(r'\$dnsrewrite=([^,\s]+)', rewrite_rule)
        if not match:
            return False, "DNS重写规则格式错误（需$dnsrewrite=类型;域名;值，如$dnsrewrite=A;example.com;127.0.0.1）"
        rewrite_content = match.group(1).strip()
        parts = rewrite_content.split(';')
        if len(parts) < 3:
            return False, "DNS重写参数不足（需类型;目标域名;解析值，RFC 1035）"
        
        record_type, target_domain, resolve_value = parts[0].upper(), parts[1].strip(), parts[2].strip()
        allowed_types = self.config.ALLOWED_DNS_RECORD_TYPES
        
        if record_type not in allowed_types:
            return False, f"DNS记录类型[{record_type}]不允许（AdGuard Home仅支持{allowed_types}，RFC 1035）"
        
        domain_valid, domain_msg = self.validate_domain(target_domain)
        if not domain_valid:
            return False, f"DNS重写目标域名违规：{domain_msg}"
        
        if record_type == 'A':
            return self.validate_ipv4(resolve_value)
        elif record_type == 'AAAA':
            return self.validate_ipv6(resolve_value)
        elif record_type == 'CNAME':
            return self.validate_domain(resolve_value)
        elif record_type in ['TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS']:
            if not resolve_value or re.search(r'[\s;$]', resolve_value):
                return False, f"DNS[{record_type}]解析值含非法字符（RFC 1035）"
            return True, "合规"
        else:
            return False, f"未实现DNS[{record_type}]记录验证（RFC 1035）"

    # -------------------------- 核心改进1：规则分析新增纯Domains识别 --------------------------
    def analyze_rule_syntax(self, rule: str, is_allow_file: bool) -> Dict[str, Any]:
        """规则分析 - 新增纯Domains（pure_domain_rule）类型识别"""
        result = {
            'type': 'unknown', 'pattern_type': 'unknown', 'modifiers': [],
            'is_valid': False, 'normalized': rule.strip(), 'is_allow': is_allow_file,  # 允许文件中的规则默认标记为允许
            'adhome_compatible': True, 'rfc_violation_msg': ""
        }
        
        # 跳过注释/空行
        if re.match(r'^[!#;]', rule) or not rule.strip():
            result['type'] = 'comment'
            return result
        
        rule_clean = rule.strip()
        # 长度检查
        if len(rule_clean) < self.config.MIN_RULE_LENGTH or len(rule_clean) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            result['rfc_violation_msg'] = f"规则长度{len(rule_clean)}（需{self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}字符）"
            return result

        # 允许规则标记（无论是否在允许文件，@@开头均为允许）
        if rule_clean.startswith('@@'):
            result['is_allow'] = True
            rule_clean = rule_clean.lstrip('@@')  # 临时剥离@@，便于后续分析

        # 修饰符提取
        if '$' in rule_clean:
            rule_body, modifiers_str = rule_clean.split('$', 1)
            rule_clean = rule_body.strip()  # 分离规则体与修饰符
            for mod_name, mod_pattern in self.syntax_db.modifiers.items():
                try:
                    if re.search(mod_pattern, modifiers_str.strip()):
                        result['modifiers'].append(mod_name)
                except re.error as e:
                    self.github_log('debug', f"修饰符正则错误: {mod_name} - {e}")
            result['modifiers'].sort()

        # 核心：多语法识别与分类
        # 1. Hosts规则（IP + 域名，AdGuard Home原生支持）
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}\s+[^#\s]+', rule_clean) or re.match(r'^([0-9a-fA-F:]+)\s+[^#\s]+', rule_clean):
            result['pattern_type'] = 'hosts_rule'
            result['type'] = 'allow' if result['is_allow'] else 'block'
            ip_match = re.match(r'^([0-9a-fA-F:.]+\s+)([^#\s]+)', rule_clean)
            if ip_match:
                ip_str, domain_str = ip_match.group(1).strip(), ip_match.group(2).strip()
                if '.' in ip_str:
                    ip_valid, ip_msg = self.validate_ipv4(ip_str)
                else:
                    ip_valid, ip_msg = self.validate_ipv6(ip_str)
                domain_valid, domain_msg = self.validate_domain(domain_str)
                if not ip_valid:
                    result['is_valid'] = False
                    result['rfc_violation_msg'] = f"Hosts规则IP违规：{ip_msg}"
                elif not domain_valid:
                    result['is_valid'] = False
                    result['rfc_violation_msg'] = f"Hosts规则域名违规：{domain_msg}"
                else:
                    result['is_valid'] = True
                    result['normalized'] = f"@@{ip_str} {domain_str}" if result['is_allow'] else f"{ip_str} {domain_str}"  # 恢复允许标记
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = "Hosts规则格式错误（需IP + 域名，如127.0.0.1 example.com）"

        # 2. AdGuard标准域名规则（||domain.com^）
        elif re.match(r'^\|\|(?:\*\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^', rule_clean):
            result['pattern_type'] = 'adguard_domain_rule'
            result['type'] = 'allow' if result['is_allow'] else 'block'
            domain_str = rule_clean.lstrip('||*.' ).rstrip('^').strip()
            domain_valid, domain_msg = self.validate_domain(domain_str)
            if domain_valid:
                result['is_valid'] = True
                result['normalized'] = f"@@{rule_clean}" if result['is_allow'] else rule_clean  # 恢复允许标记
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 3. 纯Domains（无任何前缀，如example.com）- 新增类型
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule_clean) and not re.search(r'[\s$/]', rule_clean):
            result['pattern_type'] = 'pure_domain_rule'  # 纯Domains类型
            result['type'] = 'allow' if result['is_allow'] else 'block'
            domain_valid, domain_msg = self.validate_domain(rule_clean)
            if domain_valid:
                result['is_valid'] = True
                # 暂存纯域名，后续标准化时转换
                result['normalized'] = rule_clean
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 4. DNS重写规则（$dnsrewrite）
        elif '$dnsrewrite' in rule:  # 不剥离$dnsrewrite，直接匹配
            result['pattern_type'] = 'adguard_dns_rewrite'
            result['type'] = 'dns_rewrite'
            dns_valid, dns_msg = self.validate_dns_rewrite(rule)
            if dns_valid:
                result['is_valid'] = True
                result['normalized'] = rule  # DNS重写规则保留原始格式
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = dns_msg

        # 5. 正则规则（/regex/）
        elif re.match(r'^/[^/]+/$', rule_clean):
            result['pattern_type'] = 'regex_rule'
            result['type'] = 'allow' if result['is_allow'] else 'block'
            regex_content = rule_clean.strip('/')
            domain_matches = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', regex_content)
            ipv4_matches = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', regex_content)
            ipv6_matches = re.findall(r'[0-9a-fA-F:]+:{1,2}[0-9a-fA-F:]+', regex_content)
            
            violations = []
            for domain in domain_matches:
                if not self.validate_domain(domain)[0]:
                    violations.append(f"域名[{domain}]违规")
            for ipv4 in ipv4_matches:
                if not self.validate_ipv4(ipv4)[0]:
                    violations.append(f"IPv4[{ipv4}]违规")
            for ipv6 in ipv6_matches:
                if not self.validate_ipv6(ipv6)[0]:
                    violations.append(f"IPv6[{ipv6}]违规")
            
            if violations:
                result['is_valid'] = False
                result['rfc_violation_msg'] = f"正则规则含违规内容：{'; '.join(violations)}"
            else:
                result['is_valid'] = True
                result['normalized'] = f"@@{rule_clean}" if result['is_allow'] else rule_clean  # 恢复允许标记

        # 6. 其他规则（默认无效）
        else:
            result['is_valid'] = False
            result['rfc_violation_msg'] = f"未识别规则类型（输入语法需为：AdGuard/Hosts/纯Domains/DNS重写）"

        # 统计RFC违规
        if not result['is_valid'] and result['rfc_violation_msg']:
            self.stats['rfc_violation_rules'] += 1
        # AdGuard Home兼容性校验
        result['adhome_compatible'] = self.syntax_db.is_adguard_home_compatible(result['pattern_type'], result['modifiers'])
        return result

    # -------------------------- 核心改进2：纯Domains强制转换为AdGuard格式 --------------------------
    def normalize_rule(self, rule: str, analysis: Dict[str, Any]) -> Optional[str]:
        """规则标准化 - 新增纯Domains→AdGuard格式转换"""
        # 先尝试修复RFC违规
        if not analysis['is_valid'] and analysis['rfc_violation_msg'] and self.config.AUTO_FIX_RFC_VIOLATIONS:
            fixed_rule = self.fix_rfc_violation(rule, analysis)
            if fixed_rule:
                analysis['normalized'] = fixed_rule
                analysis['is_valid'] = True  # 修复后标记为有效

        if not analysis['is_valid']:
            return None

        normalized = analysis['normalized']
        # 1. 纯Domains转换（核心改进）
        if analysis['pattern_type'] == 'pure_domain_rule' and self.config.AUTO_CONVERT_PURE_DOMAINS:
            original_domain = normalized
            # 转换为AdGuard标准格式：允许→@@||domain.com^，拦截→||domain.com^
            if analysis['is_allow']:
                normalized = f"@@||{original_domain}^"
            else:
                normalized = f"||{original_domain}^"
            # 记录转换
            self.stats['pure_domains_converted'] += 1
            self.fixed_records.append(f"纯Domains转换: {original_domain} → {normalized}")
            self.github_log('debug', f"纯Domains转换完成: {original_domain} → {normalized}")

        # 2. Hosts规则标准化（仅统一IP与域名间距）
        elif analysis['pattern_type'] == 'hosts_rule':
            # 允许规则的Hosts格式：@@IP 域名（AdGuard Home支持）
            if analysis['is_allow']:
                normalized = re.sub(r'\s+', ' ', normalized.lstrip('@@'))
                normalized = f"@@{normalized}"
            else:
                normalized = re.sub(r'\s+', ' ', normalized)

        # 3. AdGuard域名规则标准化（小写+补全^）
        elif analysis['pattern_type'] == 'adguard_domain_rule':
            normalized = normalized.lower()
            if not normalized.endswith('^'):
                normalized = f"{normalized.rstrip('^')}^"
            # 修复连续连字符
            if '--' in normalized:
                normalized = re.sub(r'--+', '-', normalized)
                self.fixed_records.append(f"连字符修复: {analysis['normalized']} → {normalized}")
                self.stats['fixed_rules_count'] += 1

        # 4. DNS重写规则标准化（记录类型大写）
        elif analysis['pattern_type'] == 'adguard_dns_rewrite':
            normalized = re.sub(r'(\$dnsrewrite=)([a-z]+)', lambda m: f"{m.group(1)}{m.group(2).upper()}", normalized)

        # 5. 允许规则格式补全（确保@@前缀）
        if analysis['is_allow'] and not normalized.startswith('@@'):
            normalized = f"@@{normalized}"

        return normalized

    # -------------------------- RFC违规修复（保留并适配转换） --------------------------
    def fix_rfc_violation(self, rule: str, analysis: Dict[str, Any]) -> Optional[str]:
        """RFC违规修复 - 支持纯Domains外的其他场景"""
        rule_clean = rule.strip()
        fixed_rule = rule_clean
        fix_reason = ""

        # 修复连续连字符（如do--main.com → do-main.com）
        if "连续连字符" in analysis['rfc_violation_msg'] and analysis['pattern_type'] in [
            'domain_rule', 'adguard_domain_rule', 'hosts_rule'
        ]:
            if analysis['pattern_type'] == 'hosts_rule':
                ip_part, domain_part = re.split(r'\s+', rule_clean, maxsplit=1)
                fixed_domain = re.sub(r'--+', '-', domain_part)
                fixed_rule = f"{ip_part.strip()} {fixed_domain}"
            else:
                fixed_rule = re.sub(r'--+', '-', rule_clean)
            fix_reason = "域名连续连字符→单连字符"

        # 修复Hosts多空格（IP与域名间单空格）
        elif analysis['pattern_type'] == 'hosts_rule' and re.search(r'\s{2,}', rule_clean):
            fixed_rule = re.sub(r'\s+', ' ', rule_clean)
            fix_reason = "Hosts多空格→单空格"

        # 修复DNS记录类型小写（如$dnsrewrite=a→$dnsrewrite=A）
        elif analysis['pattern_type'] == 'adguard_dns_rewrite' and re.search(r'\$dnsrewrite=[a-z]', rule_clean):
            fixed_rule = re.sub(
                r'(\$dnsrewrite=)([a-z]+)',
                lambda m: f"{m.group(1)}{m.group(2).upper()}",
                rule_clean
            )
            fix_reason = "DNS记录类型小写→大写"

        # 修复后验证
        if fix_reason:
            fixed_analysis = self.analyze_rule_syntax(fixed_rule, analysis['is_allow'])
            if fixed_analysis['is_valid']:
                log_origin = rule_clean[:50] + "..." if len(rule_clean) > 50 else rule_clean
                log_fixed = fixed_rule[:50] + "..." if len(fixed_rule) > 50 else fixed_rule
                self.fixed_records.append(f"RFC修复: {log_origin} → {log_fixed}（{fix_reason}）")
                self.stats["fixed_rules_count"] += 1
                return fixed_rule
        return None

    # -------------------------- 批次处理（整合转换逻辑） --------------------------
    def process_batch(self, batch: List[str], is_allow_file: bool):
        """批次处理 - 确保所有规则转换为AdGuard（含AdGuard Home）格式"""
        for rule in batch:
            self.stats["total_processed"] += 1
            if not rule or re.match(r'^[!#;]', rule):
                continue

            # 规则分析（含纯Domains识别）
            analysis = self.analyze_rule_syntax(rule, is_allow_file)
            if not analysis['is_valid']:
                self.stats["invalid_rules"] += 1
                log_rule = rule[:50] + "..." if len(rule) > 50 else rule
                self.github_log('debug', f"无效规则（跳过）: {log_rule} → 原因：{analysis['rfc_violation_msg']}")
                continue

            # 标准化（含纯Domains转换）
            normalized_rule = self.normalize_rule(rule, analysis)
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                self.github_log('debug', f"标准化失败（跳过）: {rule[:50]}...")
                continue

            # 去重
            if self.adguard_filter.add(normalized_rule):
                self.stats["duplicates"] += 1
                continue

            # 兼容性过滤（仅保留AdGuard Home支持的规则）
            if analysis['adhome_compatible']:
                self.adguard_rules.append(normalized_rule)
                self.stats["valid_rules"] += 1
                self.stats["adhome_compatible_rules"] += 1
            else:
                self.stats["adhome_incompatible_rules"] += 1
                self.github_log('debug', f"AdGuard Home不支持（跳过）: {normalized_rule[:50]}...")

    # -------------------------- 文件处理与结果保存 --------------------------
    def get_input_files(self, directory: Path) -> List[Tuple[Path, bool]]:
        """获取输入文件 - 标记允许文件（文件名含allow）"""
        if not directory.exists():
            self.github_log('warning', f"输入目录不存在，自动创建: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
            return []

        input_files = []
        for pattern in self.config.ADBLOCK_PATTERNS:
            for file in directory.rglob(pattern):
                if not file.is_file():
                    continue
                fname = file.name.lower()
                is_allow_file = 'allow' in fname  # 文件名含allow视为允许文件
                input_files.append((file, is_allow_file))

        self.file_stats = {
            "total_files": len(input_files),
            "processed_files": len(input_files),
            "allow_files": sum(1 for _, is_allow in input_files if is_allow),
            "block_files": sum(1 for _, is_allow in input_files if not is_allow)
        }
        return input_files

    def process_files(self):
        """处理所有输入文件"""
        input_files = self.get_input_files(self.config.INPUT_DIR)
        logger.info(f"\n=== 文件统计 ===")
        logger.info(f"总文件数: {self.file_stats['total_files']}（允许文件: {self.file_stats['allow_files']}，拦截文件: {self.file_stats['block_files']}）")
        
        if not input_files:
            self.github_log('warning', "未找到输入规则文件，跳过处理")
            return

        for file, is_allow_file in input_files:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    batch = []
                    for line in f:
                        batch.append(line.strip())
                        if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                            self.process_batch(batch, is_allow_file)
                            batch = []
                    if batch:
                        self.process_batch(batch, is_allow_file)
                logger.info(f"处理完成: {file.name}（允许规则: {is_allow_file}）")
            except Exception as e:
                self.github_log('error', f"文件处理失败: {file.name} - {str(e)}")
                self.file_stats["processed_files"] -= 1

        self.stats["bloom_false_positives"] = self.adguard_filter.false_positive_count

    def save_results(self):
        """保存转换后的AdGuard（含AdGuard Home）规则"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG

        # 排序并去重（双重保障）
        unique_rules = sorted(list(set(self.adguard_rules)))
        with open(output_path, 'w', encoding='utf-8') as f:
            # 写入头部说明
            f.write(f"# AdGuard（含AdGuard Home）兼容规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 规则来源: {self.config.INPUT_DIR}\n")
            f.write(f"# 规则数量: {len(unique_rules)}（纯Domains转换: {self.stats['pure_domains_converted']}条）\n")
            f.write(f"# 支持语法: AdGuard域名规则、Hosts规则、DNS重写规则\n\n")
            # 写入规则
            f.write('\n'.join(unique_rules))

        logger.info(f"\n=== 结果保存 ===")
        logger.info(f"输出文件: {output_path}")
        logger.info(f"有效规则数: {len(unique_rules)}（AdGuard Home兼容）")
        self.print_statistics()

    def print_statistics(self):
        """打印详细统计"""
        logger.info(f"\n=== 处理统计报告 ===")
        logger.info(f"1. 总体统计")
        logger.info(f"   - 总处理规则: {self.stats['total_processed']}")
        logger.info(f"   - 有效规则: {self.stats['valid_rules']}（{self.stats['valid_rules']/self.stats['total_processed']:.2%}）")
        logger.info(f"   - 无效规则: {self.stats['invalid_rules']}（含RFC违规: {self.stats['rfc_violation_rules']}条）")
        logger.info(f"   - 重复规则: {self.stats['duplicates']}")
        logger.info(f"   - AdGuard Home不支持: {self.stats['adhome_incompatible_rules']}条")
        
        logger.info(f"\n2. 转换/修复统计")
        logger.info(f"   - 纯Domains转换: {self.stats['pure_domains_converted']}条（转为AdGuard标准格式）")
        logger.info(f"   - RFC违规修复: {self.stats['fixed_rules_count']}条（连字符/格式补全等）")
        logger.info(f"   - 布隆过滤器误报率: {self.adguard_filter.get_stats()['false_positive_rate']:.6f}")
        
        logger.info(f"\n3. 文件统计")
        logger.info(f"   - 总文件数: {self.file_stats['total_files']}（处理完成: {self.file_stats['processed_files']}）")
        logger.info(f"   - 允许文件: {self.file_stats['allow_files']}个，拦截文件: {self.file_stats['block_files']}个")

        # 打印转换/修复示例（前5条）
        if self.fixed_records:
            logger.info(f"\n4. 转换/修复示例（前5条）")
            for idx, record in enumerate(self.fixed_records[:5]):
                logger.info(f"   {idx+1}. {record}")
            if len(self.fixed_records) > 5:
                logger.info(f"   ... 共{len(self.fixed_records)}条记录，剩余略")


def main():
    config = AdGuardConfig()
    logger.info(f"=== AdGuard规则转换器（支持AdGuard Home） ===")
    logger.info(f"运行配置: RFC严格验证={config.STRICT_RFC_VALIDATION}，纯Domains转换={config.AUTO_CONVERT_PURE_DOMAINS}")
    if config.GITHUB_ACTIONS:
        logger.info(f"运行环境: GitHub Actions")

    try:
        converter = AdGuardConverter(config)
        converter.process_files()
        converter.save_results()
        return 0
    except Exception as e:
        logger.error(f"执行失败: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
