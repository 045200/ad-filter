#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import logging
from pathlib import Path
from urllib.parse import urlparse
from typing import Set, List, Tuple, Optional

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 基础配置
GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
INPUT_DIR = Path(GITHUB_WORKSPACE) / "tmp"
OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_clash.yaml"
INPUT_FILE = INPUT_DIR / "adblock_merged.txt"

# 预编译正则表达式
ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|\$.*)?$')
ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|\$.*)?$')
HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
COMMENT = re.compile(r'^[!#]')
EMPTY_LINE = re.compile(r'^\s*$')
IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
DOMAIN_ONLY = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
WILDCARD_RULE = re.compile(r'^\*[^*]+\*$')
ELEMENT_HIDING = re.compile(r'^.*##[^#]+$')
ELEMENT_HIDING_EXCEPTION = re.compile(r'^.*#@#[^#]+$')
URL_RULE = re.compile(r'^https?://[^\s]+$')
GENERIC_RULE = re.compile(r'^\|\|.*\^$')
REGEX_RULE = re.compile(r'^/.*/$')
MODIFIER_RULE = re.compile(r'^.+\$.+$')
ADBLOCK_OPTIONS = re.compile(r'\$.+$')

# 域名黑名单
DOMAIN_BLACKLIST = {
    'localhost', 'localdomain', 'example.com', 'example.org', 
    'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
    '::1', '255.255.255.255', 'localhost.localdomain'
}

# 支持的Mihomo规则类型
MIHOMO_RULE_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
    'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'DST-PORT', 'SRC-PORT', 
    'PROCESS-NAME', 'PROCESS-PATH', 'MATCH', 'FINAL',
    'RULE-SET', 'SCRIPT', 'SUB-RULE', 'AND', 'OR', 'NOT'
}

class AdBlockToClashConverter:
    """将AdBlock规则转换为Clash/Mihomo规则的主要类"""
    
    def __init__(self):
        self.rules = set()
        self.rejected_rules = set()
        self.stats = {
            'total_processed': 0,
            'successful_conversions': 0,
            'whitelist_rules': 0,
            'element_hiding_rules': 0,
            'regex_rules': 0,
            'unsupported_rules': 0
        }
    
    def process_file(self) -> Set[str]:
        """处理输入文件并生成Clash/Mihomo规则"""
        if not INPUT_FILE.exists():
            logger.error(f"输入文件不存在: {INPUT_FILE}")
            return set()

        try:
            with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    self.stats['total_processed'] += 1
                    
                    # 跳过空行和注释
                    if not line or EMPTY_LINE.match(line) or COMMENT.match(line):
                        continue
                    
                    # 处理当前行
                    self.process_line(line, line_num)
            
            logger.info(f"处理完成: {self.stats}")
            return self.rules
            
        except Exception as e:
            logger.error(f"处理文件时出错: {e}")
            return set()
    
    def process_line(self, line: str, line_num: int):
        """处理单行规则"""
        try:
            # 跳过元素隐藏规则（Clash/Mihomo不支持）[citation:6]
            if ELEMENT_HIDING.match(line) or ELEMENT_HIDING_EXCEPTION.match(line):
                self.stats['element_hiding_rules'] += 1
                self.rejected_rules.add(f"Line {line_num}: 元素隐藏规则 (Clash不支持) - {line}")
                return

            # 处理白名单规则 (@@前缀)
            if line.startswith('@@'):
                self.process_whitelist_rule(line, line_num)
                return

            # 处理标准AdBlock规则
            if ADBLOCK_DOMAIN.match(line) or GENERIC_RULE.match(line):
                self.process_standard_rule(line, line_num)
                return

            # 处理Hosts规则
            if HOSTS_RULE.match(line):
                self.process_hosts_rule(line, line_num)
                return

            # 处理URL规则
            if URL_RULE.match(line):
                self.process_url_rule(line, line_num)
                return

            # 处理纯域名
            if DOMAIN_ONLY.match(line) and self.is_valid_domain(line):
                self.rules.add(f"DOMAIN-SUFFIX,{line},REJECT")
                self.stats['successful_conversions'] += 1
                return

            # 处理通配符规则
            if WILDCARD_RULE.match(line):
                self.process_wildcard_rule(line, line_num)
                return

            # 处理正则表达式规则 (Mihomo支持DOMAIN-REGEX)
            if REGEX_RULE.match(line):
                self.process_regex_rule(line, line_num)
                return

            # 处理修饰符规则 (包含$的规则)
            if MODIFIER_RULE.match(line):
                self.process_modifier_rule(line, line_num)
                return

            # 处理其他规则（如果包含IP地址）
            if self.process_ip_rule(line, line_num):
                return

            # 无法识别的规则
            self.stats['unsupported_rules'] += 1
            self.rejected_rules.add(f"Line {line_num}: 无法识别的规则格式 - {line}")
            
        except Exception as e:
            logger.error(f"处理行 {line_num} 时出错: {e}")
            self.rejected_rules.add(f"Line {line_num}: 处理错误 - {str(e)[:100]}")

    def process_whitelist_rule(self, line: str, line_num: int):
        """处理白名单规则"""
        # 移除选项参数[citation:6]
        clean_line = ADBLOCK_OPTIONS.sub('', line)
        
        # 处理不同类型的白名单规则
        if clean_line.startswith('@@||'):
            domain_match = re.match(r'^@@\|\|([\w.-]+)', clean_line)
            if domain_match and self.is_valid_domain(domain_match.group(1)):
                self.rules.add(f"DOMAIN-SUFFIX,{domain_match.group(1)},DIRECT")
                self.stats['whitelist_rules'] += 1
                self.stats['successful_conversions'] += 1
            else:
                self.rejected_rules.add(f"Line {line_num}: 无效白名单域名 - {line}")
        elif clean_line.startswith('@@|http'):
            domain_match = re.search(r'@@\|https?://([\w.-]+)', clean_line)
            if domain_match and self.is_valid_domain(domain_match.group(1)):
                self.rules.add(f"DOMAIN,{domain_match.group(1)},DIRECT")
                self.stats['whitelist_rules'] += 1
                self.stats['successful_conversions'] += 1
            else:
                self.rejected_rules.add(f"Line {line_num}: 无效白名单URL - {line}")
        else:
            self.rejected_rules.add(f"Line {line_num}: 无法处理的白名单格式 - {line}")

    def process_standard_rule(self, line: str, line_num: int):
        """处理标准AdBlock规则"""
        # 移除选项参数
        clean_line = ADBLOCK_OPTIONS.sub('', line)
        
        domain_match = re.search(r'\|\|([\w.-]+)', clean_line)
        if domain_match:
            domain = domain_match.group(1)
            if self.is_valid_domain(domain):
                self.rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                self.stats['successful_conversions'] += 1
            else:
                self.rejected_rules.add(f"Line {line_num}: 无效域名 - {line}")
        else:
            self.rejected_rules.add(f"Line {line_num}: 无法提取域名 - {line}")

    def process_hosts_rule(self, line: str, line_num: int):
        """处理Hosts规则"""
        hosts_match = HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self.is_valid_domain(domain):
                self.rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                self.stats['successful_conversions'] += 1
            else:
                self.rejected_rules.add(f"Line {line_num}: 无效hosts域名 - {line}")

    def process_url_rule(self, line: str, line_num: int):
        """处理URL规则"""
        domain_match = re.search(r'://([^/]+)', line)
        if domain_match:
            domain = domain_match.group(1).split(':')[0]  # 移除端口号
            if self.is_valid_domain(domain):
                self.rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                self.stats['successful_conversions'] += 1
            else:
                self.rejected_rules.add(f"Line {line_num}: URL规则中无效域名 - {line}")

    def process_wildcard_rule(self, line: str, line_num: int):
        """处理通配符规则"""
        converted = self.convert_wildcard_rule(line)
        if converted:
            self.rules.add(f"{converted},REJECT")
            self.stats['successful_conversions'] += 1
        else:
            self.rejected_rules.add(f"Line {line_num}: 无法处理的通配符规则 - {line}")

    def process_regex_rule(self, line: str, line_num: int):
        """处理正则表达式规则"""
        regex_pattern = line[1:-1]  # 移除前后的斜杠
        simplified_regex = self.simplify_regex(regex_pattern)
        if simplified_regex:
            self.rules.add(f"DOMAIN-REGEX,{simplified_regex},REJECT")
            self.stats['regex_rules'] += 1
            self.stats['successful_conversions'] += 1
        else:
            self.rejected_rules.add(f"Line {line_num}: 无法处理的正则规则 - {line}")

    def process_modifier_rule(self, line: str, line_num: int):
        """处理修饰符规则"""
        base_rule = line.split('$')[0]
        if base_rule and self.is_valid_rule(base_rule):
            if base_rule.startswith('||'):
                domain = base_rule[2:]
                if self.is_valid_domain(domain):
                    self.rules.add(f"DOMAIN-SUFFIX,{domain},REJECT")
                    self.stats['successful_conversions'] += 1
                    return
            elif base_rule.startswith('|http'):
                domain_match = re.search(r'://([^/]+)', base_rule)
                if domain_match:
                    domain = domain_match.group(1)
                    if self.is_valid_domain(domain):
                        self.rules.add(f"DOMAIN,{domain},REJECT")
                        self.stats['successful_conversions'] += 1
                        return
        
        self.rejected_rules.add(f"Line {line_num}: 无法处理的修饰符规则 - {line}")

    def process_ip_rule(self, line: str, line_num: int) -> bool:
        """处理IP规则，返回是否成功处理"""
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        if ip_match and IP_ADDRESS.match(ip_match.group(0)):
            self.rules.add(f"IP-CIDR,{ip_match.group(0)}/32,REJECT")
            self.stats['successful_conversions'] += 1
            return True
        return False

    def is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or domain in DOMAIN_BLACKLIST:
            return False

        # 检查是否是IP地址
        if IP_ADDRESS.match(domain):
            return False

        # 基本长度检查
        if len(domain) < 4 or len(domain) > 253:
            return False

        # 检查域名格式
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False

        # 检查TLD部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False

        tld = parts[-1]
        if len(tld) < 2 or len(tld) > 10:
            return False

        return True

    def is_valid_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        if not rule or len(rule) > 500:  # 稍微放宽长度限制
            return False

        # 检查是否包含潜在危险字符
        if re.search(r'[<>\"\']', rule):
            return False

        return True

    def convert_wildcard_rule(self, wildcard_rule: str) -> Optional[str]:
        """转换通配符规则为Clash兼容格式"""
        # 移除开头的*
        if wildcard_rule.startswith('*'):
            wildcard_rule = wildcard_rule[1:]

        # 移除结尾的*
        if wildcard_rule.endswith('*'):
            wildcard_rule = wildcard_rule[:-1]

        if not wildcard_rule:
            return None

        # 如果中间有*，转换为DOMAIN-KEYWORD规则
        if '*' in wildcard_rule:
            keyword = wildcard_rule.replace('*', '')
            if keyword and self.is_valid_rule(keyword):
                return f"DOMAIN-KEYWORD,{keyword}"

        # 否则转换为DOMAIN-SUFFIX规则
        if '.' in wildcard_rule and self.is_valid_domain(wildcard_rule):
            return f"DOMAIN-SUFFIX,{wildcard_rule}"
        elif wildcard_rule and self.is_valid_rule(wildcard_rule):
            return f"DOMAIN-KEYWORD,{wildcard_rule}"
        else:
            return None

    def simplify_regex(self, regex_pattern: str) -> Optional[str]:
        """简化正则表达式模式"""
        try:
            # 验证正则表达式有效性
            re.compile(regex_pattern)
            
            # 常见的AdBlock正则模式简化
            simplifications = {
                r'^.*\.example\.com$': r'\.example\.com$',
                r'^example\.com.*$': r'^example\.com',
                r'^*\.example\.com$': r'\.example\.com$',
                r'^example\.com*$': r'^example\.com',
            }
            
            # 检查是否可以直接简化
            for complex_pattern, simple_pattern in simplifications.items():
                if re.match(complex_pattern, regex_pattern):
                    return simple_pattern
            
            # 如果不能简化，返回原始模式（Mihomo支持正则）
            return regex_pattern
            
        except re.error:
            return None

def write_output(rules: Set[str], output_format: str = "yaml"):
    """写入输出文件，支持多种格式[citation:1]"""
    if not rules:
        logger.error("没有规则可输出")
        return

    # 将规则排序
    sorted_rules = sorted(rules)
    
    # 根据格式写入文件
    if output_format == "yaml":
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('payload:\n')
            for rule in sorted_rules:
                f.write(f"  - {rule}\n")
                
    elif output_format == "text":
        with open(OUTPUT_FILE.with_suffix('.txt'), 'w', encoding='utf-8') as f:
            for rule in sorted_rules:
                # 提取规则内容: DOMAIN-SUFFIX,example.com,REJECT → example.com
                parts = rule.split(',')
                if len(parts) >= 2:
                    f.write(f"{parts[1]}\n")
    
    logger.info(f"成功生成 {len(rules)} 条规则，格式: {output_format.upper()}")

def main():
    """主函数"""
    logger.info("开始转换AdBlock规则到Clash/Mihomo格式")
    
    # 确保输入目录存在
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    if not INPUT_FILE.exists():
        logger.error(f"输入文件不存在: {INPUT_FILE}")
        sys.exit(1)
    
    # 创建转换器并处理文件
    converter = AdBlockToClashConverter()
    rules = converter.process_file()
    
    # 输出被拒绝的规则信息
    if converter.rejected_rules:
        logger.warning(f"跳过 {len(converter.rejected_rules)} 条无法处理的规则")
        with open(INPUT_DIR / "rejected_rules.log", 'w', encoding='utf-8') as f:
            for rule in sorted(converter.rejected_rules):
                f.write(f"{rule}\n")
    
    # 写入输出文件
    write_output(rules, "yaml")
    
    # 可选: 也生成文本格式
    write_output(rules, "text")
    
    logger.info(f"转换完成! 输出文件: {OUTPUT_FILE}")

if __name__ == '__main__':
    main()