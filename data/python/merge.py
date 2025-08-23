#!/usr/bin/env python3
"""
广告规则合并去重脚本 - 无增量更新版本
支持AdBlock语法、AdGuard语法和hosts语法
每次运行都从头开始处理，不保留任何历史状态
"""

import os
import re
import sys
import glob
import logging
import asyncio
import aiofiles
import ipaddress
import psutil
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

# 尝试导入必要的第三方库
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_FILTER_AVAILABLE = True
except ImportError:
    BLOOM_FILTER_AVAILABLE = False
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
    
    # 输入文件模式
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    
    # 输出文件名
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow_filter.txt'
    
    # 布隆过滤器配置
    USE_BLOOM_FILTER = True  # 布隆过滤器开关
    BLOOM_INITIAL_CAPACITY = 200000
    BLOOM_ERROR_RATE = 0.0005
    
    # Adblockparser开关
    USE_ADBLOCKPARSER = False
    
    # 规则优化配置
    REMOVE_BROAD_RULES = True
    BROAD_RULE_PATTERNS = [
        r'^[^/*|]+\.[^/*|]+$',
        r'^[^/*|]+\.[^/*|]+\.[^/*|]+$',
        r'^\|\|[a-zA-Z0-9.-]+\^$',
    ]
    
    # 异步I/O配置
    ASYNC_ENABLED = True
    ASYNC_BUFFER_SIZE = 8192
    MAX_CONCURRENT_FILES = 5
    
    # 内存监控配置
    MEMORY_MONITOR_ENABLED = True
    MEMORY_WARNING_THRESHOLD = 512 * 1024 * 1024  # 512MB
    MEMORY_CRITICAL_THRESHOLD = 1024 * 1024 * 1024  # 1GB
    
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

# ==================== 内存监控 ====================
class MemoryMonitor:
    """内存使用监控器"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.peak_memory = 0
        
    def check_memory(self):
        """检查当前内存使用情况"""
        if not Config.MEMORY_MONITOR_ENABLED:
            return True
            
        current_memory = self.process.memory_info().rss
        self.peak_memory = max(self.peak_memory, current_memory)
        
        if current_memory > Config.MEMORY_CRITICAL_THRESHOLD:
            logger.error(f"内存使用超过临界值: {current_memory / 1024 / 1024:.2f}MB")
            return False
        elif current_memory > Config.MEMORY_WARNING_THRESHOLD:
            logger.warning(f"内存使用超过警告值: {current_memory / 1024 / 1024:.2f}MB")
            
        return True
    
    def get_stats(self):
        """获取内存统计信息"""
        return {
            'current_memory': self.process.memory_info().rss,
            'peak_memory': self.peak_memory
        }

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
        # 每次运行都创建新的布隆过滤器实例
        if Config.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            self.filter = ScalableBloomFilter(
                initial_capacity=Config.BLOOM_INITIAL_CAPACITY,
                error_rate=Config.BLOOM_ERROR_RATE
            )
            logger.info(f"使用布隆过滤器 (初始容量: {Config.BLOOM_INITIAL_CAPACITY}, 误判率: {Config.BLOOM_ERROR_RATE})")
        else:
            self.filter = set()
            logger.info("使用简单集合进行去重")
            
        self.rule_stats = {
            'total_processed': 0,
            'valid_rules': 0,
            'invalid_rules': 0,
            'duplicate_rules': 0,
            'hosts_rules': 0,
            'domain_rules': 0,
            'ip_rules': 0,
            'element_hiding_rules': 0,
            'adguard_rules': 0
        }

    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def is_duplicate(self, rule: str) -> bool:
        """检查规则是否重复"""
        normalized = rule.strip().lower()
        
        if Config.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            # 使用布隆过滤器进行检查
            if normalized in self.filter:
                self.rule_stats['duplicate_rules'] += 1
                return True
                
            self.filter.add(normalized)
            return False
        else:
            # 使用简单集合检查
            if normalized in self.filter:
                self.rule_stats['duplicate_rules'] += 1
                return True
                
            self.filter.add(normalized)
            return False

    def validate_rule(self, rule: str) -> bool:
        """验证规则有效性"""
        self.rule_stats['total_processed'] += 1
        
        # 检查过于宽泛的规则
        if self.is_broad_rule(rule):
            logger.debug(f"跳过过于宽泛的规则: {rule}")
            self.rule_stats['invalid_rules'] += 1
            return False
            
        # 基本验证
        if (rule.strip() and not rule.strip().startswith(('!', '[', '#')) and 
            any(char in rule for char in ['^', '*', '|', '/', '$', '#'])):
            self.rule_stats['valid_rules'] += 1
            return True
            
        self.rule_stats['invalid_rules'] += 1
        return False

    def is_broad_rule(self, rule: str) -> bool:
        """检查是否是过于宽泛的规则"""
        if not Config.REMOVE_BROAD_RULES:
            return False
            
        for pattern in Config.BROAD_RULE_PATTERNS:
            if re.match(pattern, rule):
                return True
        return False

    def parse_hosts_rule(self, line: str) -> Optional[str]:
        """解析hosts规则"""
        match = self.HOSTS_REGEX.search(line)
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
                self.rule_stats['ip_rules'] += 1
                return line
            except:
                pass
        return None

    def is_element_hiding_rule(self, rule: str) -> bool:
        """检查是否是元素隐藏规则"""
        if self.ELEMENT_HIDING_REGEX.match(rule):
            self.rule_stats['element_hiding_rules'] += 1
            return True
        return False

    def is_adguard_rule(self, rule: str) -> bool:
        """检查是否是AdGuard规则"""
        if '$' in rule:
            self.rule_stats['adguard_rules'] += 1
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

        # 4. 如果所有解析都失败，保留原始规则
        if any(char in original_line for char in ['^', '*', '|', '/', '$']):
            return original_line, is_allow

        return None, False

# ==================== 合并去重区 ====================
class RuleMerger:
    """规则合并器"""

    def __init__(self):
        self.parser = RuleParser()
        self.memory_monitor = MemoryMonitor()
        self.block_rules = set()
        self.allow_rules = set()

    async def process_file_async(self, file_path: Path, is_allow: bool = False):
        """异步处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        try:
            # 使用异步文件读取
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    # 检查内存使用情况
                    if not self.memory_monitor.check_memory():
                        logger.error("内存使用超过临界值，停止处理")
                        return count
                    
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        if is_allow or rule_is_allow:
                            self.allow_rules.add(rule)
                        else:
                            self.block_rules.add(rule)
                        count += 1

        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                async with aiofiles.open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    async for line in f:
                        if not self.memory_monitor.check_memory():
                            logger.error("内存使用超过临界值，停止处理")
                            return count
                        
                        rule, rule_is_allow = self.parser.classify_rule(line)
                        if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                            if is_allow or rule_is_allow:
                                self.allow_rules.add(rule)
                            else:
                                self.block_rules.add(rule)
                            count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except FileNotFoundError:
            logger.error(f"文件不存在: {file_path}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")

        logger.info(f"从 {file_path} 添加了 {count} 条规则")
        return count

    def process_file_sync(self, file_path: Path, is_allow: bool = False):
        """同步处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        try:
            # 使用同步文件读取
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # 检查内存使用情况
                    if not self.memory_monitor.check_memory():
                        logger.error("内存使用超过临界值，停止处理")
                        return count
                    
                    rule, rule_is_allow = self.parser.classify_rule(line)
                    if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                        if is_allow or rule_is_allow:
                            self.allow_rules.add(rule)
                        else:
                            self.block_rules.add(rule)
                        count += 1

        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    for line in f:
                        if not self.memory_monitor.check_memory():
                            logger.error("内存使用超过临界值，停止处理")
                            return count
                        
                        rule, rule_is_allow = self.parser.classify_rule(line)
                        if rule and not self.parser.is_duplicate(rule) and self.parser.validate_rule(rule):
                            if is_allow or rule_is_allow:
                                self.allow_rules.add(rule)
                            else:
                                self.block_rules.add(rule)
                            count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except FileNotFoundError:
            logger.error(f"文件不存在: {file_path}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")

        logger.info(f"从 {file_path} 添加了 {count} 条规则")
        return count

    async def process_files_async(self, patterns: List[str], is_allow: bool = False):
        """异步处理一组文件"""
        tasks = []
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                tasks.append(self.process_file_async(Path(file_path), is_allow))
        
        # 限制并发文件处理数量
        semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_FILES)
        
        async def limited_task(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(*[limited_task(task) for task in tasks], return_exceptions=True)
        
        # 处理结果
        total_count = 0
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"文件处理任务出错: {result}")
            else:
                total_count += result
                
        return total_count

    def process_files_sync(self, patterns: List[str], is_allow: bool = False):
        """同步处理一组文件"""
        total_count = 0
        for pattern in patterns:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                total_count += self.process_file_sync(Path(file_path), is_allow)
        return total_count

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
        stats = self.parser.rule_stats.copy()
        stats.update({
            'block_rules': len(self.block_rules),
            'allow_rules': len(self.allow_rules),
            'memory_stats': self.memory_monitor.get_stats()
        })
        return stats

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def write_rules_async(block_rules: List[str], allow_rules: List[str]):
    """异步将规则写入文件"""
    # 写入拦截规则
    try:
        async with aiofiles.open(Config.OUTPUT_DIR / Config.OUTPUT_BLOCK, 'w', encoding='utf-8', newline='\n') as f:
            for rule in block_rules:
                await f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入拦截规则文件时出错: {e}")
        return

    # 写入允许规则
    try:
        async with aiofiles.open(Config.OUTPUT_DIR / Config.OUTPUT_ALLOW, 'w', encoding='utf-8', newline='\n') as f:
            for rule in allow_rules:
                await f.write(f"{rule}\n")
    except Exception as e:
        logger.error(f"写入允许规则文件时出错: {e}")
        return

    logger.info(f"写入 {len(block_rules)} 条拦截规则到 {Config.OUTPUT_BLOCK}")
    logger.info(f"写入 {len(allow_rules)} 条允许规则到 {Config.OUTPUT_ALLOW}")

def write_rules_sync(block_rules: List[str], allow_rules: List[str]):
    """同步将规则写入文件"""
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
async def main_async():
    """异步主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    # 确保目录存在
    ensure_directories()

    # 初始化合并器
    merger = RuleMerger()

    # 处理广告拦截规则文件
    logger.info("开始处理广告拦截规则")
    if Config.ASYNC_ENABLED:
        await merger.process_files_async(Config.ADBLOCK_PATTERNS, is_allow=False)
    else:
        merger.process_files_sync(Config.ADBLOCK_PATTERNS, is_allow=False)

    # 处理允许规则文件
    logger.info("开始处理允许规则")
    if Config.ASYNC_ENABLED:
        await merger.process_files_async(Config.ALLOW_PATTERNS, is_allow=True)
    else:
        merger.process_files_sync(Config.ALLOW_PATTERNS, is_allow=True)

    # 移除冲突规则
    merger.remove_conflicts()

    # 获取排序后的规则
    block_rules, allow_rules = merger.get_sorted_rules()

    # 写入文件
    if Config.ASYNC_ENABLED:
        await write_rules_async(block_rules, allow_rules)
    else:
        write_rules_sync(block_rules, allow_rules)

    # 统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    stats = merger.get_stats()
    
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")
    
    # 内存统计
    memory_stats = stats['memory_stats']
    logger.info(f"内存使用: 峰值 {memory_stats['peak_memory'] / 1024 / 1024:.2f}MB, 当前 {memory_stats['current_memory'] / 1024 / 1024:.2f}MB")
    
    # 规则类型统计
    logger.info(f"规则类型: {stats['hosts_rules']} 条hosts规则, {stats['domain_rules']} 条域名规则, {stats['ip_rules']} 条IP规则, {stats['element_hiding_rules']} 条元素隐藏规则, {stats['adguard_rules']} 条AdGuard规则")

def main_sync():
    """同步主函数"""
    logger.info("开始处理广告规则")
    start_time = datetime.now()

    # 确保目录存在
    ensure_directories()

    # 初始化合并器
    merger = RuleMerger()

    # 处理广告拦截规则文件
    logger.info("开始处理广告拦截规则")
    merger.process_files_sync(Config.ADBLOCK_PATTERNS, is_allow=False)

    # 处理允许规则文件
    logger.info("开始处理允许规则")
    merger.process_files_sync(Config.ALLOW_PATTERNS, is_allow=True)

    # 移除冲突规则
    merger.remove_conflicts()

    # 获取排序后的规则
    block_rules, allow_rules = merger.get_sorted_rules()

    # 写入文件
    write_rules_sync(block_rules, allow_rules)

    # 统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    stats = merger.get_stats()
    
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(block_rules)} 条拦截规则, {len(allow_rules)} 条允许规则")
    logger.info(f"处理统计: {stats['total_processed']} 条规则已处理, {stats['valid_rules']} 条有效, {stats['invalid_rules']} 条无效, {stats['duplicate_rules']} 条重复")
    
    # 内存统计
    memory_stats = stats['memory_stats']
    logger.info(f"内存使用: 峰值 {memory_stats['peak_memory'] / 1024 / 1024:.2f}MB, 当前 {memory_stats['current_memory'] / 1024 / 1024:.2f}MB")
    
    # 规则类型统计
    logger.info(f"规则类型: {stats['hosts_rules']} 条hosts规则, {stats['domain_rules']} 条域名规则, {stats['ip_rules']} 条IP规则, {stats['element_hiding_rules']} 条元素隐藏规则, {stats['adguard_rules']} 条AdGuard规则")

if __name__ == '__main__':
    if Config.ASYNC_ENABLED:
        asyncio.run(main_async())
    else:
        main_sync()