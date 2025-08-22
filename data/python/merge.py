#!/usr/bin/env python3
"""
广告规则合并去重脚本
支持AdBlock语法、AdGuard语法和hosts语法
简洁高效版本
"""

import os
import re
import glob
import logging
import ipaddress
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

# ==================== 配置区 ====================
class Config:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    
    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt', '*.adb']
    ALLOW_PATTERNS = ['allow*.txt', 'white*.txt']
    
    # 输出文件名
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow.txt'
    
    # 日志配置
    LOG_LEVEL = logging.INFO

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
class RuleParser:
    """规则解析器，支持AdBlock/AdGuard语法"""

    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+([^#\s]+)')
    COMMENT_REGEX = re.compile(r'^\s*[!#]|\[Adblock')
    DOMAIN_REGEX = re.compile(r'^(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(\||@@\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    ELEMENT_HIDING_REGEX = re.compile(r'^##')

    def __init__(self):
        self.seen_rules = set()
        self.rule_stats = {
            'total_processed': 0,
            'valid_rules': 0,
            'invalid_rules': 0,
            'duplicate_rules': 0
        }

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复"""
        normalized = rule.strip().lower()
        if normalized in self.seen_rules:
            self.rule_stats['duplicate_rules'] += 1
            return True
        self.seen_rules.add(normalized)
        return False

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        self.rule_stats['total_processed'] += 1
        
        # 基本验证
        if (rule.strip() and not rule.strip().startswith(('!', '[', '#')) and 
            any(char in rule for char in ['^', '*', '|', '/', '$', '#'])):
            self.rule_stats['valid_rules'] += 1
            return True
            
        self.rule_stats['invalid_rules'] += 1
        return False

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        """解析hosts规则"""
        match = self.HOSTS_REGEX.search(line)
        if match:
            domain = match.group(1)
            return f"||{domain}^"
        return None

    def parse_domain_rule(self, line: str) -> Optional[str]:
        """解析域名规则"""
        match = self.DOMAIN_REGEX.search(line)
        if match:
            domain = match.group(1)
            # 检查是否是有效域名
            if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
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

    def is_element_hiding_rule(self, rule: str) -> bool:
        """检查是否是元素隐藏规则"""
        if self.ELEMENT_HIDING_REGEX.match(rule):
            return True
        return False

    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        """分类规则并返回处理后的规则和是否是允许规则"""
        original_line = line.strip()
        is_allow = original_line.startswith('@@')

        # 跳过注释和空行
        if self.is_comment_or_empty(original_line):
            return None, False

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

        # 4. 如果所有解析都失败，保留原始规则
        if any(char in original_line for char in ['^', '*', '|', '/', '$']):
            return original_line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class RuleMerger:
    """规则合并器"""

    def __init__(self):
        self.parser = RuleParser()
        self.block_rules = set()
        self.allow_rules = set()
        self.processed_files = set()

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
                for line in f:
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        if is_allow or rule_is_allow:
                            self.allow_rules.add(rule)
                        else:
                            self.block_rules.add(rule)
                        count += 1

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
        return self.parser.rule_stats

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def write_rules(block_rules: List[str], allow_rules: List[str]):
    """将规则写入文件"""
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

# ==================== 主程序 ====================
def main():
    """主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    # 确保目录存在
    ensure_directories()

    # 初始化合并器
    merger = RuleMerger()

    # 处理广告拦截规则文件
    logger.info("开始处理广告拦截规则")
    merger.process_files(Config.ADBLOCK_PATTERNS, is_allow=False)

    # 处理允许规则文件
    logger.info("开始处理允许规则")
    merger.process_files(Config.ALLOW_PATTERNS, is_allow=True)

    # 移除冲突规则
    merger.remove_conflicts()

    # 获取排序后的规则
    block_rules, allow_rules = merger.get_sorted_rules()

    # 写入文件
    write_rules(block_rules, allow_rules)

    # 统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    stats = merger.get_stats()
    
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")

if __name__ == '__main__':
    main()