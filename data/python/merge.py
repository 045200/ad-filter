#!/usr/bin/env python3
"""
AdGuard规则合并器 - 支持allow/adblock规则独立处理（纯净输出版）
输入支持：AdGuard规则、AdGuard Home规则、Hosts规则、纯Domains域名；
输出：独立的允许规则文件(allow_adg.txt)和拦截规则文件(adblock_adg.txt)，仅含纯净语法规则
支持RFC 1034/1035/1123/2181（域名）、RFC 791（IPv4）、RFC 2373/5952（IPv6）
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
    """配置类 - 独立输出文件配置"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"
    OUTPUT_DIR: Path = BASE_DIR

    # 核心功能开关
    STRICT_RFC_VALIDATION: bool = os.getenv('STRICT_RFC_VALIDATION', 'true').lower() == 'true'
    AUTO_FIX_RFC_VIOLATIONS: bool = os.getenv('AUTO_FIX_RFC_VIOLATIONS', 'true').lower() == 'true'
    AUTO_CONVERT_PURE_DOMAINS: bool = os.getenv('AUTO_CONVERT_PURE_DOMAINS', 'true').lower() == 'true'

    # 允许的DNS重写记录类型（AdGuard Home支持）
    ALLOWED_DNS_RECORD_TYPES: List[str] = field(default_factory=lambda: ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS'])

    # 独立输出文件配置（核心：分allow/adblock输出）
    OUTPUT_ALLOW: str = 'allow_adg.txt'    # 允许规则输出文件
    OUTPUT_BLOCK: str = 'adblock_adg.txt'  # 拦截规则输出文件
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter', '*.list'])
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))
    ENABLE_ADGUARD_HOME_COMPATIBILITY: bool = True  # 强制开启AdGuard Home兼容性
    NORMALIZE_DOMAINS: bool = True
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'


class AdGuardSyntaxDatabase:
    """语法数据库 - 强化AdGuard Home支持规则"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.rule_types = {}
        self.modifiers = {}
        self.adguard_home_specific = {}
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
            self.allowed_dns_record_types = self.config.ALLOWED_DNS_RECORD_TYPES
            self.adguard_home_specific = {
                "supported_rule_types": ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"],
                "unsupported_rule_types": ["unknown_rule", "invalid_rule"],
                "unsupported_modifiers": ["app", "extension"]
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
            self.adguard_home_specific = db_data.get('platform_support', {}).get('adguard_home', {}) or {
                "supported_rule_types": ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"],
                "unsupported_rule_types": ["unknown_rule", "invalid_rule"],
                "unsupported_modifiers": ["app", "extension"]
            }
            self.allowed_dns_record_types = db_data.get(
                'common_patterns', {}
            ).get('adguard_home_dns_rewrite_types', self.config.ALLOWED_DNS_RECORD_TYPES)
            self.config.ALLOWED_DNS_RECORD_TYPES = self.allowed_dns_record_types
            
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
        if not isinstance(self.adguard_home_specific.get('supported_rule_types', []), list):
            self.adguard_home_specific['supported_rule_types'] = ["adguard_domain_rule", "hosts_rule", "adguard_dns_rewrite", "regex_rule"]
        return True

    def is_adguard_home_compatible(self, rule_type: str, modifiers: List[str]) -> bool:
        """严格校验AdGuard Home兼容性"""
        if not self.config.ENABLE_ADGUARD_HOME_COMPATIBILITY:
            return True
        supported_types = self.adguard_home_specific.get('supported_rule_types', [])
        unsupported_types = self.adguard_home_specific.get('unsupported_rule_types', [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False
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
    """核心转换器 - allow/adblock规则独立存储+纯净输出"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)
        
        # 分允许/拦截规则独立存储
        self.allow_rules = []   # 仅存储允许规则
        self.block_rules = []   # 仅存储拦截规则
        
        # 分类型统计数据
        self.stats = {
            "total_processed": 0, "invalid_rules": 0, "rfc_violation_rules": 0, 
            "fixed_rules_count": 0, "pure_domains_converted": 0,
            # allow规则统计
            "allow": {"processed": 0, "valid": 0, "duplicates": 0, "incompatible": 0},
            # block规则统计
            "block": {"processed": 0, "valid": 0, "duplicates": 0, "incompatible": 0}
        }
        
        # 分类型去重（避免allow/block规则互相干扰）
        self.allow_bloom = EnhancedBloomFilter(config)  # allow规则去重
        self.block_bloom = EnhancedBloomFilter(config)  # block规则去重
        
        self.fixed_records = []  # 修复/转换记录
        self.file_stats = {"total_files": 0, "processed_files": 0, "allow_files": 0, "block_files": 0}

    def github_log(self, level: str, message: str):
        """日志适配GitHub Actions"""
        if self.config.GITHUB_ACTIONS:
            gh_level = {"warning": "warning", "error": "error", "debug": "debug"}.get(level, "notice")
            print(f"::{gh_level} ::{message}")
        else:
            getattr(logger, level)(message)

    # -------------------------- 基础验证逻辑 --------------------------
    def validate_domain(self, domain: str) -> Tuple[bool, str]:
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
        ipv4 = ipv4.strip()
        pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if not pattern.match(ipv4):
            return False, f"IPv4[{ipv4}]格式错误（需点分十进制，每段0-255，RFC 791）"
        if ipv4 in ['0.0.0.0', '255.255.255.255']:
            return False, "IPv4为无效地址（0.0.0.0/广播地址，RFC 791）"
        return True, "合规"

    def validate_ipv6(self, ipv6: str) -> Tuple[bool, str]:
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
        match = re.search(r'\$dnsrewrite=([^,\s]+)', rewrite_rule)
        if not match:
            return False, "DNS重写规则格式错误（需$dnsrewrite=类型;域名;值）"
        rewrite_content = match.group(1).strip()
        parts = rewrite_content.split(';')
        if len(parts) < 3:
            return False, "DNS重写参数不足（需类型;目标域名;解析值，RFC 1035）"
        
        record_type, target_domain, resolve_value = parts[0].upper(), parts[1].strip(), parts[2].strip()
        allowed_types = self.config.ALLOWED_DNS_RECORD_TYPES
        
        if record_type not in allowed_types:
            return False, f"DNS记录类型[{record_type}]不允许（AdGuard Home仅支持{allowed_types}）"
        
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

    # -------------------------- 规则分析逻辑 --------------------------
    def analyze_rule_syntax(self, rule: str, is_allow_file: bool) -> Dict[str, Any]:
        result = {
            'type': 'unknown', 'pattern_type': 'unknown', 'modifiers': [],
            'is_valid': False, 'normalized': rule.strip(), 'is_allow': is_allow_file,
            'adhome_compatible': True, 'rfc_violation_msg': ""
        }
        
        if re.match(r'^[!#;]', rule) or not rule.strip():
            result['type'] = 'comment'
            return result
        
        rule_clean = rule.strip()
        if len(rule_clean) < self.config.MIN_RULE_LENGTH or len(rule_clean) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            result['rfc_violation_msg'] = f"规则长度{len(rule_clean)}（需{self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}字符）"
            return result

        if rule_clean.startswith('@@'):
            result['is_allow'] = True
            rule_clean = rule_clean.lstrip('@@')

        if '$' in rule_clean:
            rule_body, modifiers_str = rule_clean.split('$', 1)
            rule_clean = rule_body.strip()
            for mod_name, mod_pattern in self.syntax_db.modifiers.items():
                try:
                    if re.search(mod_pattern, modifiers_str.strip()):
                        result['modifiers'].append(mod_name)
                except re.error as e:
                    self.github_log('debug', f"修饰符正则错误: {mod_name} - {e}")
            result['modifiers'].sort()

        # 1. Hosts规则
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
                    result['normalized'] = f"@@{ip_str} {domain_str}" if result['is_allow'] else f"{ip_str} {domain_str}"
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = "Hosts规则格式错误（需IP + 域名）"

        # 2. AdGuard标准域名规则
        elif re.match(r'^\|\|(?:\*\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^', rule_clean):
            result['pattern_type'] = 'adguard_domain_rule'
            result['type'] = 'allow' if result['is_allow'] else 'block'
            domain_str = rule_clean.lstrip('||*.' ).rstrip('^').strip()
            domain_valid, domain_msg = self.validate_domain(domain_str)
            if domain_valid:
                result['is_valid'] = True
                result['normalized'] = f"@@{rule_clean}" if result['is_allow'] else rule_clean
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 3. 纯Domains规则
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule_clean) and not re.search(r'[\s$/]', rule_clean):
            result['pattern_type'] = 'pure_domain_rule'
            result['type'] = 'allow' if result['is_allow'] else 'block'
            domain_valid, domain_msg = self.validate_domain(rule_clean)
            if domain_valid:
                result['is_valid'] = True
                result['normalized'] = rule_clean
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 4. DNS重写规则
        elif '$dnsrewrite' in rule:
            result['pattern_type'] = 'adguard_dns_rewrite'
            result['type'] = 'dns_rewrite'
            dns_valid, dns_msg = self.validate_dns_rewrite(rule)
            if dns_valid:
                result['is_valid'] = True
                result['normalized'] = rule
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = dns_msg

        # 5. 正则规则
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
                result['normalized'] = f"@@{rule_clean}" if result['is_allow'] else rule_clean

        # 6. 其他规则
        else:
            result['is_valid'] = False
            result['rfc_violation_msg'] = f"未识别规则类型（支持：AdGuard/Hosts/纯Domains/DNS重写）"

        if not result['is_valid'] and result['rfc_violation_msg']:
            self.stats['rfc_violation_rules'] += 1
        result['adhome_compatible'] = self.syntax_db.is_adguard_home_compatible(result['pattern_type'], result['modifiers'])
        return result

    # -------------------------- 规则标准化逻辑 --------------------------
    def normalize_rule(self, rule: str, analysis: Dict[str, Any]) -> Optional[str]:
        if not analysis['is_valid'] and analysis['rfc_violation_msg'] and self.config.AUTO_FIX_RFC_VIOLATIONS:
            fixed_rule = self.fix_rfc_violation(rule, analysis)
            if fixed_rule:
                analysis['normalized'] = fixed_rule
                analysis['is_valid'] = True

        if not analysis['is_valid']:
            return None

        normalized = analysis['normalized']
        # 纯Domains转换
        if analysis['pattern_type'] == 'pure_domain_rule' and self.config.AUTO_CONVERT_PURE_DOMAINS:
            original_domain = normalized
            if analysis['is_allow']:
                normalized = f"@@||{original_domain}^"
            else:
                normalized = f"||{original_domain}^"
            self.stats['pure_domains_converted'] += 1
            self.fixed_records.append(f"纯Domains转换: {original_domain} → {normalized}")
            self.github_log('debug', f"纯Domains转换完成: {original_domain} → {normalized}")

        # Hosts规则标准化
        elif analysis['pattern_type'] == 'hosts_rule':
            if analysis['is_allow']:
                normalized = re.sub(r'\s+', ' ', normalized.lstrip('@@'))
                normalized = f"@@{normalized}"
            else:
                normalized = re.sub(r'\s+', ' ', normalized)

        # AdGuard域名规则标准化
        elif analysis['pattern_type'] == 'adguard_domain_rule':
            normalized = normalized.lower()
            if not normalized.endswith('^'):
                normalized = f"{normalized.rstrip('^')}^"
            if '--' in normalized:
                normalized = re.sub(r'--+', '-', normalized)
                self.fixed_records.append(f"连字符修复: {analysis['normalized']} → {normalized}")
                self.stats['fixed_rules_count'] += 1

        # DNS重写规则标准化
        elif analysis['pattern_type'] == 'adguard_dns_rewrite':
            normalized = re.sub(r'(\$dnsrewrite=)([a-z]+)', lambda m: f"{m.group(1)}{m.group(2).upper()}", normalized)

        # 允许规则格式补全
        if analysis['is_allow'] and not normalized.startswith('@@'):
            normalized = f"@@{normalized}"

        return normalized

    # -------------------------- RFC修复逻辑 --------------------------
    def fix_rfc_violation(self, rule: str, analysis: Dict[str, Any]) -> Optional[str]:
        rule_clean = rule.strip()
        fixed_rule = rule_clean
        fix_reason = ""

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

        elif analysis['pattern_type'] == 'hosts_rule' and re.search(r'\s{2,}', rule_clean):
            fixed_rule = re.sub(r'\s+', ' ', rule_clean)
            fix_reason = "Hosts多空格→单空格"

        elif analysis['pattern_type'] == 'adguard_dns_rewrite' and re.search(r'\$dnsrewrite=[a-z]', rule_clean):
            fixed_rule = re.sub(
                r'(\$dnsrewrite=)([a-z]+)',
                lambda m: f"{m.group(1)}{m.group(2).upper()}",
                rule_clean
            )
            fix_reason = "DNS记录类型小写→大写"

        if fix_reason:
            fixed_analysis = self.analyze_rule_syntax(fixed_rule, analysis['is_allow'])
            if fixed_analysis['is_valid']:
                log_origin = rule_clean[:50] + "..." if len(rule_clean) > 50 else rule_clean
                log_fixed = fixed_rule[:50] + "..." if len(fixed_rule) > 50 else fixed_rule
                self.fixed_records.append(f"RFC修复: {log_origin} → {log_fixed}（{fix_reason}）")
                self.stats["fixed_rules_count"] += 1
                return fixed_rule
        return None

    # -------------------------- 分类型批次处理 --------------------------
    def process_batch(self, batch: List[str], is_allow_file: bool):
        for rule in batch:
            self.stats["total_processed"] += 1
            rule_type_key = "allow" if is_allow_file else "block"
            self.stats[rule_type_key]["processed"] += 1

            if not rule or re.match(r'^[!#;]', rule):
                continue

            # 规则分析
            analysis = self.analyze_rule_syntax(rule, is_allow_file)
            if not analysis['is_valid']:
                self.stats["invalid_rules"] += 1
                log_rule = rule[:50] + "..." if len(rule) > 50 else rule
                self.github_log('debug', f"[{rule_type_key.upper()}]无效规则（跳过）: {log_rule} → 原因：{analysis['rfc_violation_msg']}")
                continue

            # 规则标准化
            normalized_rule = self.normalize_rule(rule, analysis)
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                self.github_log('debug', f"[{rule_type_key.upper()}]标准化失败（跳过）: {rule[:50]}...")
                continue

            # 分类型去重
            if analysis['is_allow']:
                if self.allow_bloom.add(normalized_rule):
                    self.stats["allow"]["duplicates"] += 1
                    continue
            else:
                if self.block_bloom.add(normalized_rule):
                    self.stats["block"]["duplicates"] += 1
                    continue

            # 分类型兼容性过滤与存储
            if analysis['adhome_compatible']:
                if analysis['is_allow']:
                    self.allow_rules.append(normalized_rule)
                    self.stats["allow"]["valid"] += 1
                else:
                    self.block_rules.append(normalized_rule)
                    self.stats["block"]["valid"] += 1
            else:
                self.stats[rule_type_key]["incompatible"] += 1
                self.github_log('debug', f"[{rule_type_key.upper()}]AdGuard Home不支持（跳过）: {normalized_rule[:50]}...")

    # -------------------------- 文件处理逻辑 --------------------------
    def get_input_files(self, directory: Path) -> List[Tuple[Path, bool]]:
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
                is_allow_file = 'allow' in fname  # 文件名含"allow"视为允许文件
                input_files.append((file, is_allow_file))

        self.file_stats = {
            "total_files": len(input_files),
            "processed_files": len(input_files),
            "allow_files": sum(1 for _, is_allow in input_files if is_allow),
            "block_files": sum(1 for _, is_allow in input_files if not is_allow)
        }
        return input_files

    def process_files(self):
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
                logger.info(f"处理完成: {file.name}（类型: {'允许规则' if is_allow_file else '拦截规则'}）")
            except Exception as e:
                self.github_log('error', f"文件处理失败: {file.name} - {str(e)}")
                self.file_stats["processed_files"] -= 1

    # -------------------------- 核心：纯净规则输出（无文件头元信息） --------------------------
    def save_results(self):
        """分允许/拦截规则独立保存，仅含纯净语法规则"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ALLOW
        block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_BLOCK

        # 1. 保存允许规则文件（仅纯净规则）
        unique_allow = sorted(list(set(self.allow_rules)))
        with open(allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_allow))

        # 2. 保存拦截规则文件（仅纯净规则）
        unique_block = sorted(list(set(self.block_rules)))
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_block))

        logger.info(f"\n=== 结果保存 ===")
        logger.info(f"允许规则文件: {allow_path}（{len(unique_allow)}条纯净规则）")
        logger.info(f"拦截规则文件: {block_path}（{len(unique_block)}条纯净规则）")
        self.print_statistics()

    # -------------------------- 统计报告打印 --------------------------
    def print_statistics(self):
        """打印分允许/拦截的详细统计报告"""
        logger.info(f"\n=== 处理统计报告 ===")
        logger.info(f"1. 总体统计")
        logger.info(f"   - 总处理规则: {self.stats['total_processed']}")
        logger.info(f"   - 无效规则: {self.stats['invalid_rules']}（含RFC违规: {self.stats['rfc_violation_rules']}条）")
        logger.info(f"   - RFC违规修复: {self.stats['fixed_rules_count']}条")
        logger.info(f"   - 纯Domains转换: {self.stats['pure_domains_converted']}条")
        
        logger.info(f"\n2. 允许规则统计")
        logger.info(f"   - 处理总数: {self.stats['allow']['processed']}")
        logger.info(f"   - 有效规则: {self.stats['allow']['valid']}（{self.stats['allow']['valid']/self.stats['allow']['processed']:.2%}）")
        logger.info(f"   - 重复规则: {self.stats['allow']['duplicates']}")
        logger.info(f"   - 不兼容规则: {self.stats['allow']['incompatible']}")
        logger.info(f"   - 去重误报率: {self.allow_bloom.get_stats()['false_positive_rate']:.6f}")
        
        logger.info(f"\n3. 拦截规则统计")
        logger.info(f"   - 处理总数: {self.stats['block']['processed']}")
        logger.info(f"   - 有效规则: {self.stats['block']['valid']}（{self.stats['block']['valid']/self.stats['block']['processed']:.2%}）")
        logger.info(f"   - 重复规则: {self.stats['block']['duplicates']}")
        logger.info(f"   - 不兼容规则: {self.stats['block']['incompatible']}")
        logger.info(f"   - 去重误报率: {self.block_bloom.get_stats()['false_positive_rate']:.6f}")
        
        logger.info(f"\n4. 文件统计")
        logger.info(f"   - 总文件数: {self.file_stats['total_files']}（处理完成: {self.file_stats['processed_files']}）")
        logger.info(f"   - 允许文件: {self.file_stats['allow_files']}个，拦截文件: {self.file_stats['block_files']}个")

        if self.fixed_records:
            logger.info(f"\n5. 转换/修复示例（前5条）")
            for idx, record in enumerate(self.fixed_records[:5]):
                logger.info(f"   {idx+1}. {record}")
            if len(self.fixed_records) > 5:
                logger.info(f"   ... 共{len(self.fixed_records)}条记录，剩余略")


def main():
    config = AdGuardConfig()
    logger.info(f"=== AdGuard规则转换器（allow/adblock纯净输出版） ===")
    logger.info(f"运行配置: RFC严格验证={config.STRICT_RFC_VALIDATION}，纯Domains转换={config.AUTO_CONVERT_PURE_DOMAINS}")
    logger.info(f"输出配置: 允许规则→{config.OUTPUT_ALLOW}，拦截规则→{config.OUTPUT_BLOCK}（均为纯净规则，无文件头）")
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
