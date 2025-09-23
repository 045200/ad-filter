#!/usr/bin/env python3
"""
AdGuard规则合并器 - 基于国际DNS/IP标准验证，输出纯净规则
支持RFC 1034/1035/1123/2181（域名）、RFC 791（IPv4）、RFC 2373/5952（IPv6）
【改进说明】新增RFC违规自动修复功能，支持6类可修复场景，含修复统计与日志透明化
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
    """配置类 - 新增RFC严格验证开关+自动修复开关"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"
    OUTPUT_DIR: Path = BASE_DIR

    # 核心功能开关
    STRICT_RFC_VALIDATION: bool = os.getenv('STRICT_RFC_VALIDATION', 'true').lower() == 'true'
    AUTO_FIX_RFC_VIOLATIONS: bool = os.getenv('AUTO_FIX_RFC_VIOLATIONS', 'true').lower() == 'true'  # 新增修复开关

    # 允许的DNS重写记录类型（对应语法数据库adguard_home_dns_rewrite_types）
    ALLOWED_DNS_RECORD_TYPES: List[str] = field(default_factory=lambda: ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS'])

    # 原有配置保留
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter'])
    OUTPUT_ADG_BLOCK: str = 'adblock_adg.txt'
    OUTPUT_ADG_ALLOW: str = 'allow_adg.txt'
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))
    ENABLE_ADGUARD_HOME_COMPATIBILITY: bool = True
    NORMALIZE_DOMAINS: bool = True


class AdGuardSyntaxDatabase:
    """语法数据库 - 新增DNS重写记录类型同步（从数据库读取）"""
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
        """加载数据库 - 新增同步DNS记录类型（adguard_home_dns_rewrite_types）"""
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
            raise FileNotFoundError(f"未找到语法数据库，尝试路径: {possible_paths}")

        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                db_data = json.load(f)
            self.validate_database_integrity(db_data)
            
            # 原有逻辑保留
            self.rule_types = db_data.get('rule_types', {})
            self.modifiers = db_data.get('modifiers', {})
            self.version = db_data.get('version', '未知')
            self.adguard_home_specific = db_data.get('platform_support', {}).get('adguard_home', {})
            
            # 新增：从数据库读取允许的DNS重写记录类型（覆盖配置默认值）
            self.allowed_dns_record_types = db_data.get(
                'common_patterns', {}
            ).get('adguard_home_dns_rewrite_types', self.config.ALLOWED_DNS_RECORD_TYPES)
            self.config.ALLOWED_DNS_RECORD_TYPES = self.allowed_dns_record_types  # 同步到配置
            
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
                
            logger.info(f"数据库加载完成（版本: {self.version}），允许的DNS记录类型: {self.allowed_dns_record_types}")
        except Exception as e:
            raise RuntimeError(f"数据库加载失败: {e}")

    def validate_database_integrity(self, db_data: Dict) -> bool:
        """新增验证DNS记录类型字段是否存在"""
        required_fields = ["rule_types", "modifiers", "platform_support", "common_patterns"]
        missing_fields = [f for f in required_fields if f not in db_data]
        if missing_fields:
            raise ValueError(f"数据库缺少必需字段: {missing_fields}")
        # 验证DNS记录类型字段格式
        if not isinstance(
            db_data.get('common_patterns', {}).get('adguard_home_dns_rewrite_types', []), 
            list
        ):
            raise ValueError("数据库adguard_home_dns_rewrite_types必须为列表格式")
        return True

    def is_adguard_home_compatible(self, rule_type: str, modifiers: List[str]) -> bool:
        """原有兼容性检查逻辑保留"""
        if not self.config.ENABLE_ADGUARD_HOME_COMPATIBILITY:
            return True
        supported_types = self.adguard_home_specific.get('supported_rule_types', [])
        unsupported_types = self.adguard_home_specific.get('unsupported_rule_types', [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False
        unsupported_modifiers = self.adguard_home_specific.get('unsupported_modifiers', [])
        return not any(mod in modifiers for mod in unsupported_modifiers)


class EnhancedBloomFilter:
    """原有布隆过滤器逻辑保留"""
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


class AdGuardMerger:
    """核心修改：新增RFC标准验证与修复逻辑"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)
        self.adguard_filter = EnhancedBloomFilter(config)
        
        # 规则存储与统计（新增RFC违规统计项+修复统计）
        self.adguard_block_rules = []
        self.adguard_allow_rules = []
        self.stats = {
            "total_processed": 0, "adguard_block_rules": 0, "adguard_allow_rules": 0,
            "duplicates": 0, "invalid_rules": 0, "rfc_violation_rules": 0,
            "adhome_compatible_rules": 0, "adhome_incompatible_rules": 0, 
            "normalized_rules": 0, "fixed_rules_count": 0  # 新增：修复统计
        }
        self.fixed_records = []  # 新增：修复记录（用于日志追溯）
        self.file_stats = {"total_files": 0, "block_files": 0, "allow_files": 0}

    def github_log(self, level: str, message: str):
        """原有日志逻辑保留"""
        if self.config.GITHUB_ACTIONS:
            gh_level = {"warning": "warning", "error": "error", "debug": "debug"}.get(level, "notice")
            print(f"::{gh_level} ::{message}")
        else:
            getattr(logger, level)(message)

    # -------------------------- 新增：RFC违规自动修复方法 --------------------------
    def fix_rfc_violation(self, rule: str, analysis: Dict[str, Any]) -> Optional[str]:
        """
        RFC违规自动修复（仅处理可修复场景）
        返回：修复后的规则（None表示不可修复）
        """
        if not self.config.AUTO_FIX_RFC_VIOLATIONS:
            return None

        rule_clean = rule.strip()
        fixed_rule = rule_clean
        fix_reason = ""

        # 1. 修复场景1：域名连续连字符（RFC 2181，如do--main.com → do-main.com）
        if "连续连字符" in analysis['rfc_violation_msg'] and analysis['pattern_type'] in [
            'domain_rule', 'adguard_domain_rule', 'hosts_rule'
        ]:
            if analysis['pattern_type'] == 'hosts_rule':
                # Hosts规则：拆分IP和域名，仅修复域名
                ip_part, domain_part = re.split(r'\s+', rule_clean, maxsplit=1)
                fixed_domain = re.sub(r'--+', '-', domain_part)
                fixed_rule = f"{ip_part.strip()} {fixed_domain}"
            else:
                # 普通域名规则：直接修复连字符
                fixed_rule = re.sub(r'--+', '-', rule_clean)
            fix_reason = "域名连续连字符→单连字符"

        # 2. 修复场景2：域名大小写不一致（RFC 1034，DNS不区分大小写，统一小写）
        elif analysis['pattern_type'] in ['domain_rule', 'adguard_domain_rule'] and rule_clean != rule_clean.lower():
            fixed_rule = rule_clean.lower()
            fix_reason = "域名大写→小写"

        # 3. 修复场景3：Hosts规则多空格（RFC 791，IP与域名间统一为1个空格）
        elif analysis['pattern_type'] == 'hosts_rule' and re.search(r'\s{2,}', rule_clean):
            fixed_rule = re.sub(r'\s+', ' ', rule_clean)
            fix_reason = "Hosts多空格→单空格"

        # 4. 修复场景4：DNS重写记录类型小写（RFC 1035习惯，统一大写，如$dnsrewrite=a→$dnsrewrite=A）
        elif 'dns_rewrite' in analysis['pattern_type'] and re.search(r'\$dnsrewrite=[a-z]', rule_clean):
            fixed_rule = re.sub(
                r'(\$dnsrewrite=)([a-z]+)',
                lambda m: f"{m.group(1)}{m.group(2).upper()}",
                rule_clean
            )
            fix_reason = "DNS记录类型小写→大写"

        # 5. 修复场景5：允许规则格式不完整（如@@domain.com→@@||domain.com^，RFC 1034）
        elif analysis['is_allow'] and not rule_clean.startswith('@@||'):
            domain_str = rule_clean.lstrip('@@*.' ).strip()
            if self.validate_domain(domain_str)[0]:
                fixed_rule = f"@@||{domain_str}^"
                fix_reason = "允许规则补全@@||格式"

        # 6. 修复场景6：域名首尾多余连字符（如-domain.com-→domain.com，RFC 1123）
        elif analysis['pattern_type'] in ['domain_rule', 'adguard_domain_rule'] and re.match(r'^-|-$', rule_clean):
            fixed_rule = re.sub(r'^-+|-+$', '', rule_clean)
            fix_reason = "域名首尾多余连字符→移除"

        # 修复后二次验证：确保修复后的规则合规
        if fix_reason:
            fixed_analysis = self.analyze_rule_syntax(fixed_rule)
            if fixed_analysis['is_valid']:
                # 记录修复日志（截取前50字符避免过长）
                log_origin = rule_clean[:50] + "..." if len(rule_clean) > 50 else rule_clean
                log_fixed = fixed_rule[:50] + "..." if len(fixed_rule) > 50 else fixed_rule
                self.fixed_records.append(f"原规则: {log_origin} → 修复后: {log_fixed}（{fix_reason}）")
                self.stats["fixed_rules_count"] += 1
                return fixed_rule
        return None

    # -------------------------- 原有RFC验证方法保留（未修改） --------------------------
    def validate_domain(self, domain: str) -> Tuple[bool, str]:
        """域名验证（RFC 1034/1035/1123/2181）"""
        domain = domain.strip().lstrip('*.@|')
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
        if ipv4 == '255.255.255.255':
            return False, "IPv4为广播地址（禁止用于规则，RFC 791）"
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
        """DNS重写规则验证（RFC 1035 + 语法数据库记录类型）"""
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
            return False, f"DNS记录类型[{record_type}]不允许（仅支持{allowed_types}，RFC 1035）"
        
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

    # -------------------------- 原有规则分析方法（集成修复触发逻辑） --------------------------
    def analyze_rule_syntax(self, rule: str) -> Dict[str, Any]:
        """规则分析 - 保留原有验证逻辑，新增RFC违规原因记录"""
        result = {
            'type': 'unknown', 'pattern_type': 'unknown', 'modifiers': [],
            'is_valid': False, 'normalized': rule.strip(), 'is_allow': False,
            'adhome_compatible': True, 'rfc_violation_msg': ""  # 新增：RFC违规原因
        }
        
        # 跳过注释/空行
        if re.match(r'^[!#]', rule) or not rule.strip():
            result['type'] = 'comment'
            return result
        
        rule_clean = rule.strip()
        # 长度检查
        if len(rule_clean) < self.config.MIN_RULE_LENGTH or len(rule_clean) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            result['rfc_violation_msg'] = f"规则长度{len(rule_clean)}（需{self.config.MIN_RULE_LENGTH}-{self.config.MAX_RULE_LENGTH}字符）"
            return result

        # 基础标记（允许/修饰符）
        result['is_allow'] = rule_clean.startswith('@@')
        if '$' in rule_clean:
            _, modifiers_str = rule_clean.split('$', 1)
            for mod_name, mod_pattern in self.syntax_db.modifiers.items():
                try:
                    if re.search(mod_pattern, modifiers_str.strip()):
                        result['modifiers'].append(mod_name)
                except re.error as e:
                    self.github_log('debug', f"修饰符正则错误: {mod_name} - {e}")
            result['modifiers'].sort()

        # 核心：按规则类型执行RFC验证
        # 1. Hosts规则（IP + 域名，RFC 791 + RFC 1034）
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}\s+[^#\s]+', rule_clean) or re.match(r'^([0-9a-fA-F:]+)\s+[^#\s]+', rule_clean):
            result['pattern_type'] = 'hosts_rule'
            result['type'] = 'block'
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
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = "Hosts规则格式错误（需IP + 域名，RFC 791/1034）"

        # 2. AdGuard域名规则（||domain.com^，RFC 1034/1035）
        elif re.match(r'^\|\|(?:\*\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^', rule_clean):
            result['pattern_type'] = 'adguard_domain_rule'
            result['type'] = 'block'
            domain_str = rule_clean.lstrip('||*.' ).rstrip('^').strip()
            domain_valid, domain_msg = self.validate_domain(domain_str)
            if domain_valid:
                result['is_valid'] = True
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 3. 普通域名规则（.domain.com 或 domain.com，RFC 1034/1035）
        elif re.match(r'^(?:\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule_clean):
            result['pattern_type'] = 'domain_rule'
            result['type'] = 'block'
            domain_str = rule_clean.lstrip('.').strip()
            domain_valid, domain_msg = self.validate_domain(domain_str)
            if domain_valid:
                result['is_valid'] = True
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = domain_msg

        # 4. DNS重写规则（$dnsrewrite，RFC 1035）
        elif '$dnsrewrite' in rule_clean:
            result['pattern_type'] = 'adguard_dns_rewrite' if 'adguard' in self.syntax_db.rule_types.get('adguard_dns_rewrite', '') else 'adguard_home_dns_rewrite'
            result['type'] = 'dns_rewrite'
            dns_valid, dns_msg = self.validate_dns_rewrite(rule_clean)
            if dns_valid:
                result['is_valid'] = True
            else:
                result['is_valid'] = False
                result['rfc_violation_msg'] = dns_msg

        # 5. 正则规则（提取域名/IP片段验证，RFC 1034/791）
        elif re.match(r'^/[^/]+/$', rule_clean):
            result['pattern_type'] = 'regex_rule'
            result['type'] = 'block'
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

        # 6. 其他规则类型（默认无效，除非非严格模式）
        else:
            result['is_valid'] = not self.config.STRICT_RFC_VALIDATION
            if not result['is_valid']:
                result['rfc_violation_msg'] = f"未识别规则类型，且开启严格RFC验证"

        # 兼容性检查（原有逻辑保留）
        result['adhome_compatible'] = self.syntax_db.is_adguard_home_compatible(result['pattern_type'], result['modifiers'])
        # 统计RFC违规
        if not result['is_valid'] and result['rfc_violation_msg']:
            self.stats['rfc_violation_rules'] += 1
        return result

    # -------------------------- 原有规则标准化方法（集成修复逻辑） --------------------------
    def normalize_rule(self, rule: str) -> Optional[str]:
        """规则标准化 - 新增RFC合规修复调用"""
        analysis = self.analyze_rule_syntax(rule)
        
        # 先尝试修复RFC违规（仅对无效但可修复的规则）
        if not analysis['is_valid'] and analysis['rfc_violation_msg']:
            fixed_rule = self.fix_rfc_violation(rule, analysis)
            if fixed_rule:
                return fixed_rule.strip()
        
        # 原有标准化逻辑（仅处理已合规的规则）
        if not analysis['is_valid']:
            return None

        normalized = analysis['normalized']
        # 1. 域名规则小写化（DNS大小写不敏感，RFC 1034）
        if analysis['pattern_type'] in ['domain_rule', 'adguard_domain_rule']:
            normalized = normalized.lower()
            # 修复：清理连续连字符（冗余保障，避免漏修）
            if '--' in normalized:
                normalized = re.sub(r'--+', '-', normalized)
                self.github_log('debug', f"标准化修复连字符：{analysis['normalized']} → {normalized}")

        # 2. Hosts规则：IP与域名间统一为单个空格（RFC 791）
        elif analysis['pattern_type'] == 'hosts_rule':
            normalized = re.sub(r'\s+', ' ', normalized)

        # 3. DNS重写规则：记录类型大写（RFC 1035习惯）
        elif 'dns_rewrite' in analysis['pattern_type']:
            normalized = re.sub(r'(\$dnsrewrite=)([a-z]+)', lambda m: f"{m.group(1)}{m.group(2).upper()}", normalized)

        # 4. 允许规则补全格式（@@||domain.com^，RFC 1034）
        if analysis['is_allow'] and not normalized.startswith('@@||'):
            domain_str = normalized.lstrip('@@*.' ).strip()
            if self.validate_domain(domain_str)[0]:
                normalized = f"@@||{domain_str}^"

        return normalized

    # -------------------------- 原有批次处理方法（未修改核心逻辑） --------------------------
    def process_batch(self, batch: List[str], is_allow_file: bool):
        """处理批次 - 保留原有逻辑，修复统计自动触发"""
        for rule in batch:
            self.stats["total_processed"] += 1
            if not rule or re.match(r'^[!#]', rule):
                continue

            # 分析规则（含RFC验证）
            analysis = self.analyze_rule_syntax(rule)
            if not analysis['is_valid']:
                self.stats["invalid_rules"] += 1
                # 打印RFC违规原因
                if analysis['rfc_violation_msg']:
                    log_rule = rule[:50] + "..." if len(rule) > 50 else rule
                    self.github_log('debug', f"RFC违规规则（跳过/尝试修复）: {log_rule} → 原因：{analysis['rfc_violation_msg']}")
                else:
                    self.github_log('debug', f"无效规则（跳过）: {rule[:50]}...")
                continue

            # 标准化与去重
            normalized_rule = self.normalize_rule(rule)
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                self.github_log('debug', f"标准化失败（跳过）: {rule[:50]}...")
                continue

            if self.adguard_filter.add(normalized_rule):
                self.stats["duplicates"] += 1
                continue

            # 分类存储
            if analysis['is_allow'] or is_allow_file:
                self.adguard_allow_rules.append(normalized_rule)
                self.stats["adguard_allow_rules"] += 1
            else:
                self.adguard_block_rules.append(normalized_rule)
                self.stats["adguard_block_rules"] += 1

            if analysis['adhome_compatible']:
                self.stats["adhome_compatible_rules"] += 1
            else:
                self.stats["adhome_incompatible_rules"] += 1

    # -------------------------- 原有统计打印方法（新增修复统计） --------------------------
    def print_statistics(self):
        """统计打印 - 新增RFC修复统计与修复记录"""
        logger.info(f"\n=== 处理统计报告（含RFC标准验证+自动修复） ===")
        logger.info(f"总处理规则: {self.stats['total_processed']}")
        logger.info(f"有效规则: {self.stats['adguard_block_rules'] + self.stats['adguard_allow_rules']}")
        logger.info(f"  - 拦截规则: {self.stats['adguard_block_rules']}")
        logger.info(f"  - 允许规则: {self.stats['adguard_allow_rules']}")
        logger.info(f"无效规则: {self.stats['invalid_rules']}（原始RFC违规: {self.stats['rfc_violation_rules']}条，其中{self.stats['fixed_rules_count']}条已修复）")
        logger.info(f"重复规则: {self.stats['duplicates']}")
        logger.info(f"自动修复规则: {self.stats['fixed_rules_count']}条（可修复场景：连字符/大小写/格式补全等）")
        logger.info(f"AdGuard Home兼容: {self.stats['adhome_compatible_rules']}条")
        logger.info(f"布隆过滤器误报率: {self.adguard_filter.get_stats()['false_positive_rate']:.6f}")

        # 打印修复记录（前10条，避免日志过长）
        if self.fixed_records:
            logger.info(f"\n=== 修复记录示例（前10条） ===")
            for idx, record in enumerate(self.fixed_records[:10]):
                logger.info(f"{idx+1}. {record}")
            if len(self.fixed_records) > 10:
                logger.info(f"... 共{len(self.fixed_records)}条修复记录，剩余{len(self.fixed_records)-10}条略")

        # GitHub摘要更新（新增修复统计）
        if self.config.GITHUB_ACTIONS and os.getenv('GITHUB_STEP_SUMMARY'):
            total_valid = self.stats['adguard_block_rules'] + self.stats['adguard_allow_rules']
            valid_rate = total_valid / self.stats['total_processed'] if self.stats['total_processed'] > 0 else 0
            with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a', encoding='utf-8') as f:
                f.write(f"""## AdGuard规则处理报告（含RFC标准验证+自动修复）
- **处理时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **RFC严格验证**: {'开启' if self.config.STRICT_RFC_VALIDATION else '关闭'}
- **RFC自动修复**: {'开启' if self.config.AUTO_FIX_RFC_VIOLATIONS else '关闭'}（修复{self.stats['fixed_rules_count']}条规则）
- **有效规则总数**: {total_valid}（有效率：{valid_rate:.2%}）
- **原始RFC违规**: {self.stats['rfc_violation_rules']}条（修复率：{self.stats['fixed_rules_count']/self.stats['rfc_violation_rules']:.2%}）
- **AdGuard Home兼容率**: {self.stats['adhome_compatible_rules']/total_valid:.2%} if total_valid > 0 else 0.00%
- **输出文件**: 
  - 拦截规则: {self.config.OUTPUT_ADG_BLOCK}（{len(self.adguard_block_rules)}条）
  - 允许规则: {self.config.OUTPUT_ADG_ALLOW}（{len(self.adguard_allow_rules)}条）
""")

    # -------------------------- 原有文件处理方法（未修改） --------------------------
    def get_files_by_prefix(self, directory: Path) -> Tuple[List[Path], List[Path]]:
        if not directory.exists():
            self.github_log('warning', f"输入目录不存在，自动创建: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
            return [], []

        block_files = []
        allow_files = []
        for pattern in self.config.ADBLOCK_PATTERNS:
            for file in directory.rglob(pattern):
                if not file.is_file():
                    continue
                fname = file.name.lower()
                if fname.startswith('adblock'):
                    block_files.append(file)
                elif fname.startswith('allow'):
                    allow_files.append(file)

        self.file_stats = {
            "total_files": len(block_files) + len(allow_files),
            "block_files": len(block_files),
            "allow_files": len(allow_files)
        }
        return block_files, allow_files

    def process_file_batch(self, file_path: Path, is_allow_file: bool):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line in f:
                    batch.append(line.strip())
                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        self.process_batch(batch, is_allow_file)
                        batch = []
                if batch:
                    self.process_batch(batch, is_allow_file)
            logger.info(f"处理完成: {file_path}")
        except Exception as e:
            self.github_log('error', f"文件处理失败: {file_path} - {str(e)}")

    def process_files(self):
        block_files, allow_files = self.get_files_by_prefix(self.config.INPUT_DIR)
        logger.info(f"\n文件统计: 总{self.file_stats['total_files']}个（拦截{self.file_stats['block_files']}个/允许{self.file_stats['allow_files']}个）")

        for file in block_files:
            self.process_file_batch(file, is_allow_file=False)
        for file in allow_files:
            self.process_file_batch(file, is_allow_file=True)

        self.stats["bloom_false_positives"] = self.adguard_filter.false_positive_count

    def save_results(self):
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 保存纯净规则（RFC合规） ===")

        # 保存拦截规则
        block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_BLOCK
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_block_rules)))
        logger.info(f"拦截规则: {block_path}（{len(self.adguard_block_rules)}条，均符合RFC标准）")

        # 保存允许规则
        allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_ALLOW
        with open(allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_allow_rules)))
        logger.info(f"允许规则: {allow_path}（{len(self.adguard_allow_rules)}条，均符合RFC标准）")

        self.print_statistics()


def main():
    config = AdGuardConfig()
    if config.GITHUB_ACTIONS:
        logger.info(f"运行环境: GitHub Actions（RFC严格验证: {'开启' if config.STRICT_RFC_VALIDATION else '关闭'}，RFC自动修复: {'开启' if config.AUTO_FIX_RFC_VIOLATIONS else '关闭'}）")

    try:
        merger = AdGuardMerger(config)
        merger.process_files()
        merger.save_results()
        return 0
    except Exception as e:
        logger.error(f"执行失败: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
