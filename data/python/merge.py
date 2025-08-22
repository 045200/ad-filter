#!/usr/bin/env python3
"""
优化版广告规则合并去重脚本
支持AdBlock语法、AdGuard语法和hosts语法
"""

import os
import re
import glob
import logging
import hashlib
from typing import Set, List, Tuple, Dict, Optional
from pathlib import Path
from datetime import datetime
from collections import OrderedDict

# 第三方库导入
try:
    from adblockparser import AdblockRule
    from IPy import IP
    import ipfilter
    from pybloom_live import BloomFilter
    from counting_bloom_filter import CountingBloomFilter  # 支持删除的布隆过滤器
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请使用 pip install adblockparser IPy ipfilter pybloom-live counting_bloom_filter 安装")
    exit(1)

# ==================== 配置区 ====================
class Config:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    
    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    
    # 输出文件名
    OUTPUT_BLOCK = 'adblock.txt'
    OUTPUT_ALLOW = 'allow.txt'
    
    # 布隆过滤器配置
    BLOOM_CAPACITY = 300000
    BLOOM_ERROR_RATE = 0.005
    
    # 缓存大小
    LRU_CACHE_SIZE = 10000
    
    # 日志配置
    LOG_LEVEL = logging.INFO

# ==================== 初始化日志 ====================
def setup_logging():
    """配置日志系统"""
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
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
        # 双结构去重：布隆过滤器(快速初步检查)+哈希集合(精确判断)
        self.bloom_filter = BloomFilter(
            capacity=Config.BLOOM_CAPACITY,
            error_rate=Config.BLOOM_ERROR_RATE
        )
        self.exact_seen_rules = set()
        self.lru_cache = OrderedDict()
        
    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)
    
    def normalize_rule(self, rule: str) -> str:
        """规范化规则以便比较"""
        return rule.strip().lower()
    
    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复（双结构检查）"""
        normalized = self.normalize_rule(rule)
        
        # LRU缓存检查
        if normalized in self.lru_cache:
            return True
            
        # 布隆过滤器初步检查
        if normalized not in self.bloom_filter:
            self.bloom_filter.add(normalized)
            self.exact_seen_rules.add(normalized)
            # 更新LRU缓存
            self._update_lru_cache(normalized)
            return False
        
        # 精确集合确认
        if normalized in self.exact_seen_rules:
            return True
            
        # 布隆过滤器误判情况处理
        self.exact_seen_rules.add(normalized)
        self._update_lru_cache(normalized)
        return False
        
    def _update_lru_cache(self, rule: str):
        """更新LRU缓存"""
        if len(self.lru_cache) >= Config.LRU_CACHE_SIZE:
            self.lru_cache.popitem(last=False)
        self.lru_cache[rule] = True
    
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
    
    def parse_modifier_rule(self, line: str) -> Optional[Tuple[str, bool]]:
        """解析带修饰符的规则"""
        match = self.MODIFIER_REGEX.search(line)
        if match:
            pattern, modifiers = match.groups()
            # 检查常见修饰符
            if 'client=' in modifiers or 'dnstype=' in modifiers:
                return line, line.startswith('@@')
        return None
        
    def parse_regex_rule(self, line: str) -> Optional[str]:
        """解析正则表达式规则"""
        if line.startswith('/') and line.endswith('/'):
            return line
        return None
    
    def classify_rule(self, line: str) -> Tuple[Optional[str], bool]:
        """分类规则并返回处理后的规则和是否是允许规则"""
        original_line = line.strip()
        is_allow = original_line.startswith('@@')
        
        # 跳过注释和空行
        if self.is_comment_or_empty(original_line):
            return None, False
        
        # 尝试解析为各种规则类型（按复杂度从高到低尝试）
        rule = None
        
        # 1. 正则表达式规则
        rule = self.parse_regex_rule(original_line)
        if rule:
            return rule, is_allow
        
        # 2. 带修饰符的规则
        result = self.parse_modifier_rule(original_line)
        if result:
            return result
            
        # 3. 检查是否是hosts规则
        rule = self.parse_hosts_rule(original_line)
        if rule:
            return rule, is_allow
        
        # 4. 检查是否是域名规则
        rule = self.parse_domain_rule(original_line)
        if rule:
            return rule, is_allow
        
        # 5. 检查是否是IP/CIDR规则
        rule = self.parse_ip_rule(original_line)
        if rule:
            return rule, is_allow
        
        # 6. 使用adblockparser验证规则
        try:
            adblock_rule = AdblockRule(original_line)
            if adblock_rule.is_filtering_rule:
                return original_line, is_allow
        except:
            pass
        
        # 7. 如果所有解析都失败，尝试基本清理
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
        self.rule_sources = {}  # 跟踪规则来源
        
    def process_file(self, file_path: Path):
        """处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    rule, is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule):
                        if is_allow:
                            self.allow_rules.add(rule)
                        else:
                            self.block_rules.add(rule)
                        # 记录规则来源
                        self.rule_sources[rule] = f"{file_path.name}:{line_num}"
                        count += 1
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")
        
        logger.info(f"从 {file_path} 添加了 {count} 条规则")
    
    def process_files(self, patterns: List[str], is_allow: bool = False):
        """处理一组文件"""
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                self.process_file(Path(file_path))
    
    def remove_conflicts(self):
        """移除冲突规则（允许规则优先）"""
        # 从拦截规则中移除允许列表中存在的规则
        before = len(self.block_rules)
        self.block_rules -= self.allow_rules
        after = len(self.block_rules)
        logger.info(f"移除 {before - after} 条冲突规则")
    
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

def read_existing_rules() -> Tuple[Set[str], Set[str]]:
    """读取已存在的规则文件以实现增量更新"""
    block_rules = set()
    allow_rules = set()
    parser = EnhancedRuleParser()
    
    output_block = Config.OUTPUT_DIR / Config.OUTPUT_BLOCK
    output_allow = Config.OUTPUT_DIR / Config.OUTPUT_ALLOW
    
    for file_path in [output_block, output_allow]:
        if file_path.exists():
            is_allow = file_path == output_allow
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    rule, _ = parser.classify_rule(line)
                    if rule:
                        if is_allow:
                            allow_rules.add(rule)
                        else:
                            block_rules.add(rule)
                        # 标记为已存在以避免重复
                        parser.is_duplicate(rule)
    
    return block_rules, allow_rules

def write_rules(block_rules: List[str], allow_rules: List[str]):
    """将规则写入文件"""
    # 写入拦截规则
    with open(Config.OUTPUT_DIR / Config.OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f:
        for rule in block_rules:
            f.write(f"{rule}\n")
    
    # 写入允许规则
    with open(Config.OUTPUT_DIR / Config.OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f:
        for rule in allow_rules:
            f.write(f"{rule}\n")
    
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
    
    # 读取已存在的规则以实现增量更新
    existing_block, existing_allow = read_existing_rules()
    merger.block_rules.update(existing_block)
    merger.allow_rules.update(existing_allow)
    
    logger.info(f"已加载 {len(existing_block)} 条现有拦截规则和 {len(existing_allow)} 条允许规则")
    
    # 处理广告拦截规则文件
    merger.process_files(Config.ADBLOCK_PATTERNS)
    
    # 处理允许规则文件
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
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    
    # 输出语法覆盖统计
    logger.info("规则类型统计:")
    logger.info(f"  - 基本域名规则: {sum(1 for r in block_rules if r.startswith('||'))}")
    logger.info(f"  - 例外规则: {len(allow_rules)}")
    logger.info(f"  - 正则表达式规则: {sum(1 for r in block_rules if r.startswith('/') and r.endswith('/'))}")
    logger.info(f"  - 带修饰符规则: {sum(1 for r in block_rules if '$' in r)}")

if __name__ == '__main__':
    main()