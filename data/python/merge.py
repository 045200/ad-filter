import os
import re
from pathlib import Path
from typing import List, Set, Pattern, Tuple, Optional
import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit
import logging
import ipaddress


# 全局配置
WORKING_DIR = Path('tmp')
TARGET_DIR = Path('/')
INPUT_DIR = Path('tmp')
WORKING_DIR.mkdir(exist_ok=True)
TARGET_DIR.mkdir(exist_ok=True)

@dataclass
class ProcessingConfig:
    """处理配置参数"""
    show_conflicts: int = 10
    keep_whitelist_in_blacklist: bool = True
    validate_dns: bool = True

class RuleValidator:
    """广告拦截规则验证器（支持多源格式）"""

    BASE_PATTERNS = {
        # 基础规则模式 [AdBlock/uBO/AdGuard/ABP]
        'domain': r'^\|\|[\w*.-]+\^(?:\$[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+)*)?$',
        'domain_suffix': r'^\|\|\*\.?[\w*.-]+\^',
        'exact_domain': r'^\|https?://[\w*.-]+/',
        'regex_domain': r'^/@\|\|[\w*.-]+\^/',
        'abp_specific': r'^[\w*.-]+\#\#[^#]+',

        # 元素规则
        'element_hiding': r'^##[^#\s\[].*',
        'extended_css': r'^#\?#[^#\s\[].*',
        'exception_hiding': r'^#@#.+',

        # 网络规则
        'regex': r'^/(?:[^/\\]|\\.)*/[gimsu]*$',
        'hosts': r'^\d+\.\d+\.\d+\.\d+\s+[\w*.-]+',
        'hosts_ipv6': r'^[0-9a-fA-F:]+(?:\s+[\w*.-]+)+',

        # DNS规则
        'dns_block': r'^\|\|[\w*.-]+\^\$dns',
        'dns_allow': r'^@@\|\|[\w*.-]+\^\$dns',
        'dns_rewrite': r'^\|\|[\w*.-]+\^\$dnsrewrite=',
    }

    @classmethod
    def compile_patterns(cls) -> Tuple[Pattern, Pattern]:
        """编译正则表达式模式"""
        block_parts = [
            cls.BASE_PATTERNS['domain'],
            cls.BASE_PATTERNS['domain_suffix'],
            cls.BASE_PATTERNS['element_hiding'],
            cls.BASE_PATTERNS['regex'],
            cls.BASE_PATTERNS['hosts'],
            cls.BASE_PATTERNS['dns_block'],
            cls.BASE_PATTERNS['dns_rewrite'],
        ]
        block_pattern = '|'.join(block_parts)
        allow_pattern = '|'.join([
            r'^@@\|\|[\w*.-]+\^',
            r'^@@##[^#\s]',
            r'^@@\|\|[\w*.-]+\^\$dns'
        ])
        return re.compile(block_pattern), re.compile(allow_pattern)

class DNSValidator:
    """DNS规则验证器"""
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_dns_rewrite(rule: str) -> bool:
        if '$dnsrewrite=' not in rule:
            return False

        try:
            parts = rule.split('$dnsrewrite=')[1].split(',')
            if len(parts) < 2:
                return False

            rewrite_type = parts[0].lower()
            if rewrite_type == 'a' or rewrite_type == 'aaaa':
                return DNSValidator.is_valid_ip(parts[1])
            elif rewrite_type == 'cname':
                return bool(re.match(r'^[a-zA-Z0-9.-]+$', parts[1].rstrip('.')))
            return True
        except:
            return False

class AdblockProcessor:
    """广告拦截规则处理器（简化版）"""

    def __init__(self, config: ProcessingConfig = ProcessingConfig()):
        self.config = config
        self.block_pattern, self.allow_pattern = RuleValidator.compile_patterns()
        self.seen_rules = set()
        self.domain_map = {}
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.stats = {
            'black_total': 0,
            'black_valid': 0,
            'black_skipped': 0,
            'white_total': 0,
            'white_valid': 0,
            'white_skipped': 0
        }

    def _check_input_files(self) -> bool:
        """检查输入文件是否存在"""
        adblock_files = list(INPUT_DIR.glob('*block*.txt'))
        if not adblock_files:
            self.logger.error("未找到任何广告拦截规则文件")
            return False
        self.logger.info(f"找到{len(adblock_files)}个拦截规则文件")
        return True

    def normalize_rule(self, rule: str) -> str:
        """标准化单个规则"""
        rule = rule.strip()
        if not rule or rule.startswith(('!', '#')):
            return rule

        # 统一域名格式
        if rule.startswith(('||', '@@||', '|http', '@@|http')):
            rule = rule.lower()

        # 标准化Hosts规则
        if re.match(r'^\d+\.\d+\.\d+\.\d+', rule):
            parts = re.split(r'\s+', rule)
            if len(parts) >= 2:
                return f"{parts[0]} {' '.join([d.lower() for d in parts[1:]])}"

        # 标准化修饰符
        if '$' in rule:
            parts = rule.split('$', 1)
            domain = parts[0]
            modifiers = '$' + parts[1].lower()

            if 'dnsrewrite=' in modifiers and self.config.validate_dns:
                if not DNSValidator.validate_dns_rewrite(rule):
                    self.logger.warning(f"无效DNS重写规则: {rule}")
                    return ""

            rule = domain + modifiers

        return rule

    def process_file(self, file_path: Path, rule_type: str) -> List[str]:
        """处理单个文件"""
        rules = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self.stats[f'{rule_type}_total'] += 1
                norm_line = self.normalize_rule(line)
                if not norm_line:
                    self.stats[f'{rule_type}_skipped'] += 1
                    continue

                if rule_type == 'black' and not self.block_pattern.search(norm_line):
                    self.stats[f'{rule_type}_skipped'] += 1
                    continue
                elif rule_type == 'white' and not self.allow_pattern.search(norm_line):
                    self.stats[f'{rule_type}_skipped'] += 1
                    continue

                domain = self.extract_domain(norm_line)
                if domain and domain in self.domain_map:
                    existing_rule = self.domain_map[domain]
                    if self.is_superior_rule(norm_line, existing_rule):
                        self.domain_map[domain] = norm_line
                        if existing_rule in rules:
                            rules[rules.index(existing_rule)] = norm_line
                        continue

                rule_hash = hashlib.sha256(norm_line.encode()).hexdigest()
                if rule_hash not in self.seen_rules:
                    self.seen_rules.add(rule_hash)
                    if domain:
                        self.domain_map[domain] = norm_line
                    rules.append(norm_line)
                    self.stats[f'{rule_type}_valid'] += 1

                if self.stats[f'{rule_type}_total'] % 1000 == 0:
                    self.logger.info(
                        f"处理{rule_type}规则: {self.stats[f'{rule_type}_total']} "
                        f"(有效: {self.stats[f'{rule_type}_valid']}, "
                        f"跳过: {self.stats[f'{rule_type}_skipped']})"
                    )
        return rules

    def process_files(self):
        """处理规则文件主流程"""
        if not self._check_input_files():
            return

        try:
            # 处理黑名单规则
            black_rules = []
            for file in INPUT_DIR.glob('*block*.txt'):
                self.logger.info(f"处理黑名单文件: {file.name}")
                black_rules.extend(self.process_file(file, 'black'))

            # 提取白名单规则
            allow_rules = [rule for rule in black_rules 
                         if rule.startswith('@@') and self.allow_pattern.search(rule)]
            black_rules = [rule for rule in black_rules if rule not in allow_rules]

            # 处理白名单文件
            for file in INPUT_DIR.glob('allow*.txt'):
                self.logger.info(f"处理白名单文件: {file.name}")
                allow_rules.extend(self.process_file(file, 'white'))

            # 写入文件
            with open(TARGET_DIR / 'adblock.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(black_rules))
                if self.config.keep_whitelist_in_blacklist and allow_rules:
                    f.write('\n' + '\n'.join(allow_rules))

            with open(TARGET_DIR / 'allow.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(allow_rules))

            # 输出统计
            self.log_stats(black_rules, allow_rules)

        except Exception as e:
            self.logger.error(f"处理失败: {str(e)}")
            raise

    def extract_domain(self, rule: str) -> Optional[str]:
        if rule.startswith('||'):
            return rule.split('^')[0].lower()
        elif rule.startswith('@@||'):
            return rule.split('^')[0][2:].lower()
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', rule):
            parts = re.split(r'\s+', rule)
            return parts[-1].lower() if len(parts) > 1 else None
        return None

    def is_superior_rule(self, new_rule: str, existing_rule: str) -> bool:
        if new_rule.startswith('@@') and not existing_rule.startswith('@@'):
            return True
        if '$dns' in new_rule.lower() and '$dns' not in existing_rule.lower():
            return True
        return len(new_rule) > len(existing_rule)

    def log_stats(self, block_rules: List[str], allow_rules: List[str]):
        """输出统计信息"""
        self.logger.info("\n规则统计:")
        self.logger.info(f"黑名单总数: {len(block_rules)}")
        self.logger.info(f"白名单总数: {len(allow_rules)}")
        
        self.logger.info("\n处理统计:")
        self.logger.info(f"处理的黑名单规则总数: {self.stats['black_total']}")
        self.logger.info(f"  ├─ 有效规则: {self.stats['black_valid']}")
        self.logger.info(f"  └─ 跳过规则: {self.stats['black_skipped']}")
        self.logger.info(f"处理的白名单规则总数: {self.stats['white_total']}")
        self.logger.info(f"  ├─ 有效规则: {self.stats['white_valid']}")
        self.logger.info(f"  └─ 跳过规则: {self.stats['white_skipped']}")

if __name__ == '__main__':
    processor = AdblockProcessor()
    processor.process_files()