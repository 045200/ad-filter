#!/usr/bin/env python3
"""
优化版广告规则合并去重脚本
支持AdBlock语法、AdGuard语法和hosts语法
针对GitHub Action环境优化
"""

import os
import re
import glob
import logging
import hashlib
from typing import Set, List, Tuple, Optional, Dict
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# ==================== 配置区 ====================
class Config:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))

    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']

    # 输出文件名
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow.txt'

    # 布隆过滤器配置
    BLOOM_INITIAL_CAPACITY = 100000
    BLOOM_ERROR_RATE = 0.001
    BLOOM_GROWTH_MODE = ScalableBloomFilter.LARGE_SET_GROWTH

    # 处理模式
    MAX_WORKERS = os.cpu_count() or 4

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
class EnhancedRuleParser:
    """增强型规则解析器，支持更多语法"""

    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s+([^#\s]+)')
    HOSTS_IPV6_REGEX = re.compile(r'^(?:[0-9a-fA-F:]+)\s+([^#\s]+)')
    COMMENT_REGEX = re.compile(r'^\s*[!#]|\[Adblock')
    DOMAIN_REGEX = re.compile(r'^(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(\||@@\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    MODIFIER_REGEX = re.compile(r'^(.*?)\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')

    def __init__(self):
        # 使用可扩展的布隆过滤器
        self.bloom_filter = ScalableBloomFilter(
            initial_capacity=Config.BLOOM_INITIAL_CAPACITY,
            error_rate=Config.BLOOM_ERROR_RATE,
            mode=Config.BLOOM_GROWTH_MODE
        )
        self.exact_seen_rules = set()
        logger.info(f"使用可扩展布隆过滤器 (初始容量: {Config.BLOOM_INITIAL_CAPACITY}, 误判率: {Config.BLOOM_ERROR_RATE})")

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def normalize_rule(self, rule: str) -> str:
        """规范化规则以便比较"""
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
            return True
            
        # 布隆过滤器误判情况处理
        self.exact_seen_rules.add(normalized)
        return False

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        try:
            # 使用adblockparser验证规则
            adblock_rule = AdblockRule(rule)
            return adblock_rule.is_filtering_rule
        except:
            # 特殊规则处理（如hosts规则、IP规则等）
            if self.parse_hosts_rule(rule) or self.parse_ip_rule(rule):
                return True
            return False

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        """解析hosts规则（支持IPv4和IPv6）"""
        # 尝试IPv4格式
        match = self.HOSTS_REGEX.search(line)
        if match:
            domain = match.group(1)
            return f"||{domain}^"

        # 尝试IPv6格式
        match = self.HOSTS_IPV6_REGEX.search(line)
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
                IP(ip_cidr)
                return line
            except:
                pass
        return None

    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        """分类规则并返回处理后的规则和是否是允许规则"""
        original_line = line.strip()
        is_allow = original_line.startswith('@@')

        # 跳过注释和空行
        if self.is_comment_or_empty(original_line):
            return None, False

        # 特殊处理AdGuard文档级拦截规则[citation:7]
        if '$document' in original_line:
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
            adblock_rule = AdblockRule(original_line)
            if adblock_rule.is_filtering_rule:
                return original_line, is_allow
        except:
            pass

        # 5. 如果所有解析都失败，保留原始规则
        if any(char in original_line for char in ['^', '*', '|', '/', '$']):
            return original_line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class EnhancedRuleMerger:
    """增强型规则合并器"""

    def __init__(self):
        self.parser = EnhancedRuleParser()
        self.block_rules = set()
        self.allow_rules = set()

    def process_file(self, file_path: Path):
        """处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    rule, is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        if is_allow:
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

    def process_files(self, patterns: List[str]):
        """处理一组文件"""
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                self.process_file(Path(file_path))

    def parallel_process_files(self, patterns: List[str]):
        """并行处理文件组"""
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # 提交所有文件处理任务
            future_to_file = {}
            for pattern in patterns:
                for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                    future = executor.submit(self.process_file, Path(file_path))
                    future_to_file[future] = file_path
            
            # 等待所有任务完成
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f"处理文件 {file_path} 时生成异常: {exc}")

    def remove_conflicts(self):
        """移除冲突规则（允许规则优先）"""
        before = len(self.block_rules)
        self.block_rules -= self.allow_rules
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

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

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

# ==================== 主程序 ====================
def main():
    """主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    # 确保目录存在
    ensure_directories()

    # 初始化合并器
    merger = EnhancedRuleMerger()

    # 处理广告拦截规则文件（并行处理）
    logger.info("开始并行处理广告拦截规则")
    merger.parallel_process_files(Config.ADBLOCK_PATTERNS)

    # 处理允许规则文件（并行处理）
    logger.info("开始并行处理允许规则")
    merger.parallel_process_files(Config.ALLOW_PATTERNS)

    # 移除冲突规则
    merger.remove_conflicts()

    # 获取排序后的规则
    block_rules, allow_rules = merger.get_sorted_rules()

    # 写入文件
    write_rules(block_rules, allow_rules)

    # 统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")

if __name__ == '__main__':
    main()