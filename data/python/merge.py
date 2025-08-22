#!/usr/bin/env python3
"""
高级广告规则合并去重脚本
支持AdBlock语法、AdGuard语法(含AdGuard Home)和hosts语法
针对中文区广告过滤优化，集成anti-AD项目最佳实践
"""

import os
import re
import sys
import glob
import logging
import hashlib
import ipaddress
import urllib.request
import json
from typing import Set, List, Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

# 尝试导入必要的第三方库
try:
    from pybloom_live import ScalableBloomFilter
except ImportError:
    # 如果没有pybloom_live，使用内置的set作为备选
    class ScalableBloomFilter:
        LARGE_SET_GROWTH = 1
        def __init__(self, initial_capacity=10000, error_rate=0.001, mode=None):
            self.set = set()
        def add(self, item):
            self.set.add(item)
        def __contains__(self, item):
            return item in self.set

# ==================== 配置区 ====================
class Config:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    CACHE_DIR = Path(os.getenv('CACHE_DIR', './data/cache'))
    
    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    
    # 输出文件名
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow.txt'
    OUTPUT_STATS = 'filter_stats.json'
    
    # 布隆过滤器配置
    BLOOM_INITIAL_CAPACITY = 200000
    BLOOM_ERROR_RATE = 0.001
    BLOOM_GROWTH_MODE = ScalableBloomFilter.LARGE_SET_GROWTH
    
    # Adblockparser开关 - 根据上游规则类型调整
    # True: 适用于标准AdBlock语法规则 (误判低)
    # False: 适用于AdGuard/AdGuard Home语法规则 (误判高)
    USE_ADBLOCKPARSER = False
    
    # 规则优化配置
    REMOVE_BROAD_RULES = True  # 移除过于宽泛的规则
    BROAD_RULE_PATTERNS = [
        r'^[^/*|]+\.[^/*|]+$',  # 简单域名规则
        r'^[^/*|]+\.[^/*|]+\.[^/*|]+$',  # 二级域名规则
        r'^\|\|[a-zA-Z0-9.-]+\^$',  # 基础域名拦截
    ]
    
    # 中文区重要域名保护列表（主域名，不拦截）
    CHINESE_MAIN_DOMAINS = [
        '360.com', '360.cn', 'baidu.com', 'baidu.cn',
        'aliyun.com', 'alipay.com', 'taobao.com', 'tmall.com',
        'qq.com', 'weixin.qq.com', 'jd.com', '163.com',
        'sina.com.cn', 'sohu.com', 'ifeng.com', 'xinhuanet.com',
        'people.com.cn', 'gov.cn', 'edu.cn', 'mi.com',
        'xiaomi.com', 'huawei.com', 'oppo.com', 'vivo.com'
    ]
    
    # 中文区广告子域名模式（可以拦截）
    CHINESE_AD_PATTERNS = [
        r'.*\.ad\..*', r'.*\.ads\..*', r'.*\.adx\..*', r'.*\.adv\..*',
        r'.*\.publicidad\..*', r'.*\.adserver\..*', r'.*\.adbanner\..*',
        r'.*\.advert\..*', r'.*\.promo\..*', r'.*\.tracking\..*',
        r'.*\.analytics\..*', r'.*\.stat\..*', r'.*\.count\..*',
        r'ad.*\..*', r'ads.*\..*', r'adx.*\..*', r'adv.*\..*',
        r'.*\.doubleclick\.net', r'.*\.googleadservices\.com',
        r'.*\.googlesyndication\.com', r'.*\.moatads\.com',
        r'.*\.scorecardresearch\.com', r'.*\.exosrv\.com'
    ]
    
    # 日志配置
    LOG_LEVEL = logging.INFO
    
    # 测试配置
    TEST_DOMAINS = [
        'www.example.com', 'example.com', 'test.com',
        'ad.example.com', 'tracking.example.com'
    ]

# 尝试导入adblockparser
if Config.USE_ADBLOCKPARSER:
    try:
        from adblockparser import AdblockRule
        ADBLOCKPARSER_AVAILABLE = True
    except ImportError:
        ADBLOCKPARSER_AVAILABLE = False
        print("警告: adblockparser不可用，使用简化规则验证")
else:
    ADBLOCKPARSER_AVAILABLE = False
    print("信息: adblockparser验证已禁用")

# ==================== 初始化日志 ====================
def setup_logging():
    """配置日志系统"""
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 分析识别区 ====================
class AdvancedRuleParser:
    """高级规则解析器，支持AdBlock/AdGuard语法和中文区优化"""

    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+([^#\s]+)')
    HOSTS_IPV6_REGEX = re.compile(r'^(?:[0-9a-fA-F:]+)\s+([^#\s]+)')
    COMMENT_REGEX = re.compile(r'^\s*[!#]|\[Adblock')
    DOMAIN_REGEX = re.compile(r'^(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(\||@@\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    MODIFIER_REGEX = re.compile(r'^(.*?)\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')
    ELEMENT_HIDING_REGEX = re.compile(r'^##')
    
    # AdGuard修饰符
    ADGUARD_MODIFIERS = {
        'document', 'script', 'stylesheet', 'subdocument', 'object', 'image',
        'xmlhttprequest', 'websocket', 'webrtc', 'popup', 'elemhide',
        'generichide', 'genericblock', 'content', 'other', 'third-party',
        'match-case', 'donottrack', 'sitekey', 'denyallow', 'redirect',
        'removeparam', 'important', 'badfilter', 'empty', 'mp4', 'app'
    }

    def __init__(self):
        # 使用可扩展的布隆过滤器
        self.bloom_filter = ScalableBloomFilter(
            initial_capacity=Config.BLOOM_INITIAL_CAPACITY,
            error_rate=Config.BLOOM_ERROR_RATE,
            mode=Config.BLOOM_GROWTH_MODE
        )
        self.exact_seen_rules = set()
        self.rule_stats = {
            'total_processed': 0,
            'valid_rules': 0,
            'invalid_rules': 0,
            'duplicate_rules': 0,
            'hosts_rules': 0,
            'domain_rules': 0,
            'element_hiding_rules': 0,
            'adguard_rules': 0,
            'chinese_main_domain_rules_skipped': 0,
            'chinese_ad_rules_kept': 0
        }
        
        # 预编译中文区广告模式正则
        self.chinese_ad_regexes = [re.compile(pattern) for pattern in Config.CHINESE_AD_PATTERNS]
        
        logger.info(f"使用可扩展布隆过滤器 (初始容量: {Config.BLOOM_INITIAL_CAPACITY}, 误判率: {Config.BLOOM_ERROR_RATE})")
        logger.info(f"Adblockparser验证: {'启用' if Config.USE_ADBLOCKPARSER and ADBLOCKPARSER_AVAILABLE else '禁用'}")

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def normalize_rule(self, rule: str) -> str:
        """规范化规则以便比较"""
        # 移除多余空格，转换为小写，但保留原始修饰符
        return rule.strip().lower()

    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复（使用双结构检查）"""
        normalized = self.normalize_rule(rule)

        # 布隆过滤器初步检查
        if normalized not in self.bloom_filter:
            self.bloom_filter.add(normalized)
            self.exact_seen_rules.add(normalized)
            return False

        # 精确集合确认
        if normalized in self.exact_seen_rules:
            self.rule_stats['duplicate_rules'] += 1
            return True

        # 布隆过滤器误判情况处理
        self.exact_seen_rules.add(normalized)
        return False

    def is_broad_rule(self, rule: str) -> bool:
        """检查是否是过于宽泛的规则"""
        if not Config.REMOVE_BROAD_RULES:
            return False
            
        for pattern in Config.BROAD_RULE_PATTERNS:
            if re.match(pattern, rule):
                return True
        return False

    def is_chinese_main_domain(self, rule: str) -> bool:
        """检查是否匹配中文区主域名（需要保护）"""
        # 提取规则中的域名部分
        domain = self.extract_domain_from_rule(rule)
        if not domain:
            return False
            
        # 检查是否匹配中文区主域名
        for main_domain in Config.CHINESE_MAIN_DOMAINS:
            if domain == main_domain or domain.endswith('.' + main_domain):
                return True
        return False

    def is_chinese_ad_domain(self, rule: str) -> bool:
        """检查是否匹配中文区广告域名（可以拦截）"""
        # 提取规则中的域名部分
        domain = self.extract_domain_from_rule(rule)
        if not domain:
            return False
            
        # 检查是否匹配广告模式
        for regex in self.chinese_ad_regexes:
            if regex.match(domain):
                return True
        return False

    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从规则中提取域名"""
        # 处理 ||domain^ 格式
        if rule.startswith('||') and rule.endswith('^'):
            return rule[2:-1]
            
        # 处理 domain##selector 格式
        if '##' in rule:
            parts = rule.split('##')
            if parts[0]:  # 有域名部分
                return parts[0]
                
        # 处理普通域名规则
        match = self.DOMAIN_REGEX.match(rule)
        if match:
            return match.group(1)
            
        return None

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        self.rule_stats['total_processed'] += 1
        
        # 检查中文区主域名（需要保护）
        if self.is_chinese_main_domain(rule):
            logger.debug(f"跳过中文区主域名规则: {rule}")
            self.rule_stats['chinese_main_domain_rules_skipped'] += 1
            self.rule_stats['invalid_rules'] += 1
            return False
            
        # 检查中文区广告域名（可以拦截）
        if self.is_chinese_ad_domain(rule):
            logger.debug(f"保留中文区广告域名规则: {rule}")
            self.rule_stats['chinese_ad_rules_kept'] += 1
            # 继续后续验证
            
        # 检查过于宽泛的规则
        if self.is_broad_rule(rule):
            logger.debug(f"跳过过于宽泛的规则: {rule}")
            self.rule_stats['invalid_rules'] += 1
            return False
            
        try:
            if Config.USE_ADBLOCKPARSER and ADBLOCKPARSER_AVAILABLE:
                # 使用adblockparser验证规则
                adblock_rule = AdblockRule(rule)
                if adblock_rule.is_filtering_rule:
                    self.rule_stats['valid_rules'] += 1
                    return True
            else:
                # 使用简化验证
                if (rule.strip() and not rule.strip().startswith(('!', '[', '#')) and 
                    any(char in rule for char in ['^', '*', '|', '/', '$', '#'])):
                    self.rule_stats['valid_rules'] += 1
                    return True
                    
            self.rule_stats['invalid_rules'] += 1
            return False
        except:
            # 特殊规则处理（如hosts规则、IP规则等）
            if self.parse_hosts_rule(rule) or self.parse_ip_rule(rule):
                self.rule_stats['valid_rules'] += 1
                return True
                
            self.rule_stats['invalid_rules'] += 1
            return False

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        """解析hosts规则（支持IPv4和IPv6）"""
        # 尝试IPv4格式
        match = self.HOSTS_REGEX.search(line)
        if match:
            domain = match.group(1)
            self.rule_stats['hosts_rules'] += 1
            return f"||{domain}^"

        # 尝试IPv6格式
        match = self.HOSTS_IPV6_REGEX.search(line)
        if match:
            domain = match.group(1)
            self.rule_stats['hosts_rules'] += 1
            return f"||{domain}^"

        return None

    def parse_domain_rule(self, line: str) -> Optional[str]:
        """解析域名规则"""
        match = self.DOMAIN_REGEX.search(line)
        if match:
            domain = match.group(1)
            # 检查是否是有效域名
            if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
                self.rule_stats['domain_rules'] += 1
                return line
        return None

    def parse_ip_rule(self, line: str) -> Optional[str]:
        """解析IP/CIDR规则"""
        match = self.IP_CIDR_REGEX.search(line)
        if match:
            prefix, ip_cidr = match.groups()
            try:
                # 验证IP/CIDR格式
                ipaddress.ip_network(ip_cidr, strict=False)
                return line
            except:
                pass
        return None

    def is_adguard_rule(self, rule: str) -> bool:
        """检查是否是AdGuard规则"""
        if '$' in rule:
            # 提取修饰符部分
            parts = rule.split('$')
            if len(parts) > 1:
                modifiers = parts[-1].split(',')
                for mod in modifiers:
                    if mod.strip() in self.ADGUARD_MODIFIERS:
                        self.rule_stats['adguard_rules'] += 1
                        return True
        return False

    def is_element_hiding_rule(self, rule: str) -> bool:
        """检查是否是元素隐藏规则"""
        if self.ELEMENT_HIDING_REGEX.match(rule):
            self.rule_stats['element_hiding_rules'] += 1
            return True
        return False

    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        """分类规则并返回处理后的规则和是否是允许规则"""
        original_line = line.strip()
        is_allow = original_line.startswith('@@')

        # 跳过注释和空行
        if self.is_comment_or_empty(original_line):
            return None, False

        # 特殊处理AdGuard规则
        if self.is_adguard_rule(original_line):
            return original_line, is_allow

        # 特殊处理元素隐藏规则
        if self.is_element_hiding_rule(original_line):
            return original_line, is_allow

        # 尝试解析为各种规则类型
        rule = None

        # 1. 检查是否是hosts规则
        rule = self.parse_hosts_rule(original_line)
        if rule:
            return rule, is_allow

        # 2. 检查是否是域名规则
        rule = self.parse_domain_rule(original_line)
        if rule:
            return rule, is_allow

        # 3. 检查是否是IP/CIDR规则
        rule = self.parse_ip_rule(original_line)
        if rule:
            return rule, is_allow

        # 4. 使用adblockparser验证规则
        try:
            if Config.USE_ADBLOCKPARSER and ADBLOCKPARSER_AVAILABLE:
                adblock_rule = AdblockRule(original_line)
                if adblock_rule.is_filtering_rule:
                    return original_line, is_allow
            else:
                # 简化验证
                if any(char in original_line for char in ['^', '*', '|', '/', '$']):
                    return original_line, is_allow
        except Exception as e:
            logger.debug(f"规则解析错误: {original_line}, 错误: {e}")

        # 5. 如果所有解析都失败，保留原始规则
        if any(char in original_line for char in ['^', '*', '|', '/', '$']):
            return original_line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class AdvancedRuleMerger:
    """高级规则合并器，支持多种优化策略"""

    def __init__(self):
        self.parser = AdvancedRuleParser()
        self.block_rules = set()
        self.allow_rules = set()
        self.processed_files = set()  # 记录已处理的文件

    def process_file(self, file_path: Path, is_allow: bool = False):
        """处理单个文件"""
        if file_path in self.processed_files:
            logger.debug(f"跳过已处理文件: {file_path}")
            return
            
        logger.info(f"处理文件: {file_path}")
        self.processed_files.add(file_path)
        count = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        # 如果明确指定了规则类型，使用指定的类型
                        if is_allow:
                            self.allow_rules.add(rule)
                        else:
                            # 否则使用规则自身的类型
                            if rule_is_allow:
                                self.allow_rules.add(rule)
                            else:
                                self.block_rules.add(rule)
                        count += 1

                    # 每处理10000行输出一次进度
                    if line_num % 10000 == 0:
                        logger.info(f"已处理 {line_num} 行，添加 {count} 条规则")

        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")

        logger.info(f"从 {file_path} 添加了 {count} 条规则")

    def process_files(self, patterns: List[str], is_allow: bool = False):
        """处理一组文件"""
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                self.process_file(Path(file_path), is_allow)

    def remove_conflicts(self):
        """移除冲突规则（允许规则优先）"""
        before = len(self.block_rules)
        
        # 创建允许规则的域名集合用于快速查找
        allow_domains = set()
        for rule in self.allow_rules:
            if rule.startswith('@@||') and rule.endswith('^'):
                domain = rule[4:-1]  # 提取域名部分
                allow_domains.add(domain)
        
        # 移除被允许规则覆盖的拦截规则
        rules_to_remove = set()
        for rule in self.block_rules:
            if rule.startswith('||') and rule.endswith('^'):
                domain = rule[2:-1]  # 提取域名部分
                if domain in allow_domains:
                    rules_to_remove.add(rule)
        
        self.block_rules -= rules_to_remove
        after = len(self.block_rules)
        removed = before - after
        
        if removed > 0:
            logger.info(f"移除 {removed} 条冲突规则")

    def optimize_rules(self):
        """优化规则集，移除冗余规则"""
        # 实现基于anti-AD项目的优化策略
        logger.info("开始规则优化...")
        
        # 统计优化前的规则数量
        before_block = len(self.block_rules)
        before_allow = len(self.allow_rules)
        
        # 移除被更通用规则覆盖的特定规则
        self._remove_redundant_rules()
        
        # 统计优化后的规则数量
        after_block = len(self.block_rules)
        after_allow = len(self.allow_rules)
        
        logger.info(f"规则优化完成: 拦截规则 {before_block} -> {after_block}, " +
                   f"允许规则 {before_allow} -> {after_allow}")

    def _remove_redundant_rules(self):
        """移除冗余规则"""
        # 实现基于anti-AD项目的冗余规则移除逻辑
        redundant_rules = set()
        
        # 将规则按类型分组
        domain_rules = [r for r in self.block_rules if r.startswith('||') and r.endswith('^')]
        other_rules = self.block_rules - set(domain_rules)
        
        # 创建域名到规则的映射
        domain_map = {}
        for rule in domain_rules:
            domain = rule[2:-1]  # 移除||和^
            domain_map[domain] = rule
        
        # 检查其他规则是否被域名规则覆盖
        for rule in other_rules:
            # 提取规则中的域名部分
            domain_match = re.search(r'\|\|([a-zA-Z0-9.-]+)\^', rule)
            if domain_match:
                domain = domain_match.group(1)
                if domain in domain_map:
                    redundant_rules.add(rule)
        
        # 移除冗余规则
        self.block_rules -= redundant_rules
        
        if redundant_rules:
            logger.info(f"移除 {len(redundant_rules)} 条冗余规则")

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """获取排序后的规则列表"""
        # 按规则类型和字母顺序排序
        def rule_key(rule):
            if rule.startswith('||'):
                return (0, rule)
            elif rule.startswith('@@'):
                return (1, rule)
            elif rule.startswith('/') and rule.endswith('/'):
                return (2, rule)
            else:
                return (3, rule)

        block_list = sorted(self.block_rules, key=rule_key)
        allow_list = sorted(self.allow_rules, key=rule_key)
        
        return block_list, allow_list

    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        return {
            'total_processed': self.parser.rule_stats['total_processed'],
            'valid_rules': self.parser.rule_stats['valid_rules'],
            'invalid_rules': self.parser.rule_stats['invalid_rules'],
            'duplicate_rules': self.parser.rule_stats['duplicate_rules'],
            'block_rules': len(self.block_rules),
            'allow_rules': len(self.allow_rules),
            'hosts_rules': self.parser.rule_stats['hosts_rules'],
            'domain_rules': self.parser.rule_stats['domain_rules'],
            'adguard_rules': self.parser.rule_stats['adguard_rules'],
            'element_hiding_rules_count': self.parser.rule_stats['element_hiding_rules'],
            'chinese_main_domain_rules_skipped': self.parser.rule_stats['chinese_main_domain_rules_skipped'],
            'chinese_ad_rules_kept': self.parser.rule_stats['chinese_ad_rules_kept']
        }

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)

def write_rules(block_rules: List[str], allow_rules: List[str]):
    """将规则写入文件（纯净语法，无元信息）"""
    # 写入拦截规则
    try:
        with open(Config.OUTPUT_DIR / Config.OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f:
            for rule in block_rules:
                f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入拦截规则文件时出错: {e}")
        return

    # 写入允许规则
    try:
        with open(Config.OUTPUT_DIR / Config.OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f:
            for rule in allow_rules:
                f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入允许规则文件时出错: {e}")
        return

    logger.info(f"写入 {len(block_rules)} 条拦截规则到 {Config.OUTPUT_BLOCK}")
    logger.info(f"写入 {len(allow_rules)} 条允许规则到 {Config.OUTPUT_ALLOW}")

def write_stats(stats: Dict[str, Any]):
    """写入统计信息"""
    try:
        with open(Config.OUTPUT_DIR / Config.OUTPUT_STATS, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        logger.info(f"统计信息已写入 {Config.OUTPUT_STATS}")
    except Exception as e:
        logger.error(f"写入统计信息时出错: {e}")

# ==================== 测试验证区 ====================
def test_rules(block_rules: List[str], allow_rules: List[str]):
    """测试规则有效性"""
    logger.info("开始规则测试...")
    
    # 创建测试规则集
    test_rules = block_rules + allow_rules
    
    # 简单的语法检查
    valid_count = 0
    invalid_count = 0
    
    for rule in test_rules:
        if not rule.strip() or rule.strip().startswith('!'):
            continue
            
        # 基本语法检查
        if any(char in rule for char in ['^', '*', '|', '/', '$', '#']):
            valid_count += 1
        else:
            invalid_count += 1
            logger.warning(f"可疑规则: {rule}")
    
    logger.info(f"规则测试完成: 有效 {valid_count}, 可疑 {invalid_count}")
    
    return valid_count, invalid_count

# ==================== 主程序 ====================
def main():
    """主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    # 确保目录存在
    ensure_directories()

    # 初始化合并器
    merger = AdvancedRuleMerger()

    # 处理广告拦截规则文件
    logger.info("开始处理广告拦截规则")
    merger.process_files(Config.ADBLOCK_PATTERNS, is_allow=False)

    # 处理允许规则文件
    logger.info("开始处理允许规则")
    merger.process_files(Config.ALLOW_PATTERNS, is_allow=True)

    # 移除冲突规则
    merger.remove_conflicts()

    # 优化规则集
    merger.optimize_rules()

    # 获取排序后的规则
    block_rules, allow_rules = merger.get_sorted_rules()

    # 测试规则
    test_rules(block_rules, allow_rules)

    # 写入文件
    write_rules(block_rules, allow_rules)

    # 写入统计信息
    stats = merger.get_stats()
    write_stats(stats)

    # 统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")
    logger.info(f"中文区处理: 跳过 {stats['chinese_main_domain_rules_skipped']} 条主域名规则, 保留 {stats['chinese_ad_rules_kept']} 条广告域名规则")

if __name__ == '__main__':
    main()