#!/usr/bin/env python3
"""
AdBlock规则合并与优化脚本 - 纯净规则版（无规则头）
适配20万+规则量，无外部依赖，兼容AdGuard/AdGuard Home/Hosts语法
【核心改进】布隆过滤器 + 分桶内存哈希表 双重去重，彻底解决假阳性问题
"""

import os
import re
import sys
import glob
import logging
import asyncio
import aiofiles
import hashlib
from typing import List, Tuple, Optional, Dict, Any, Set
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 尝试导入第三方布隆过滤器（优先使用，无则用内存优化版Set）
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_FILTER_AVAILABLE = True
except ImportError:
    BLOOM_FILTER_AVAILABLE = False
    class ScalableBloomFilter:
        """内存优化版布隆过滤器替代类（基于Set，减少冗余存储）"""
        def __init__(self, initial_capacity=10000, error_rate=0.001, mode=None):
            self.set = set()
            # 按规则类型分桶存储，减少查询耗时
            self.domain_set = set()  # 域名规则专用桶
            self.ip_set = set()      # IP规则专用桶
            self.adguard_set = set() # AdGuard规则专用桶

        def add(self, item: str, rule_type: str = "normal"):
            """按规则类型分桶添加"""
            item_hash = hashlib.md5(item.encode()).hexdigest()  # 哈希压缩内存占用
            if rule_type == "domain":
                self.domain_set.add(item_hash)
            elif rule_type == "ip":
                self.ip_set.add(item_hash)
            elif rule_type == "adguard":
                self.adguard_set.add(item_hash)
            else:
                self.set.add(item_hash)

        def __contains__(self, item: str, rule_type: str = "normal") -> bool:
            """按规则类型分桶查询"""
            item_hash = hashlib.md5(item.encode()).hexdigest()
            if rule_type == "domain":
                return item_hash in self.domain_set
            elif rule_type == "ip":
                return item_hash in self.ip_set
            elif rule_type == "adguard":
                return item_hash in self.adguard_set
            else:
                return item_hash in self.set

# ==================== 核心配置（适配20万+规则） ====================
class AdBlockConfig:
    """AdBlock规则处理配置（纯净规则版）"""
    # 输入输出路径（兼容Github Action工作目录）
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './data/filter'))

    # 输入文件模式（覆盖AdGuard/AGH/Hosts语法）
    ADBLOCK_PATTERNS = ['adblock*.txt']
    ALLOW_PATTERNS = ['allow*.txt']
    HOSTS_PATTERNS = ['hosts*.txt']

    # 输出文件名（纯净规则，无后缀注释）
    OUTPUT_BLOCK = 'adblock_filter.txt'
    OUTPUT_ALLOW = 'allow_filter.txt'

    # 双重去重配置（布隆+哈希表，适配20万+规则）
    USE_DOUBLE_DEDUPLICATION = True  # 启用双重去重
    USE_BLOOM_FILTER = True
    BLOOM_INITIAL_CAPACITY = 300000  # 初始容量高于预期规则量（预留冗余）
    BLOOM_ERROR_RATE = 0.0005        # 低误判率，平衡内存与准确性

    # 规则过滤优化（减少有效规则误删）
    REMOVE_BROAD_RULES = False       # 关闭宽泛规则过滤
    RULE_LENGTH_LIMIT = 10000        # 放宽规则长度限制

    # 异步I/O配置（Github Action资源适配）
    ASYNC_ENABLED = True
    MAX_CONCURRENT_FILES = 8         # 控制并发，避免资源超限

    # 语法支持配置
    ALLOW_LOCAL_DOMAINS = True
    ALLOW_IP_RULES = True
    SUPPORT_HOSTS_CONVERT = True     # 开启Hosts转AdBlock规则

    # 日志配置（精简输出，不干扰规则文件）
    LOG_LEVEL = logging.INFO

# ==================== 日志初始化 ====================
def setup_logging():
    logging.basicConfig(
        level=AdBlockConfig.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== 规则解析器（兼容多语法 + 双重去重） ====================
class AdBlockRuleParser:
    """支持AdGuard/AdGuard Home/Hosts语法的规则解析器（新增双重去重）"""
    # 完整AdGuard/AGH修饰符支持
    SUPPORTED_MODIFIERS = {
        'document', 'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
        'subdocument', 'ping', 'webrtc', 'websocket', 'other', 'popup', 'third-party',
        'first-party', 'match-case', 'collapse', 'donottrack', 'generichide',
        'genericblock', 'elemhide', 'content', 'jsinject', 'urlblock', 'important',
        'badfilter', 'empty', 'mp4', 'redirect', 'redirect-rule', 'cname', 'dnsrewrite',
        'client', 'dnstype', 'app', 'domain', 'method', 'all', 'from', 'https', 'http',
        'queryprune', 'replace', 'header', 'cookie', 'referrer'
    }

    # 语法正则（适配多格式）
    COMMENT_REGEX = re.compile(r'^\s*[!#;]|\[Adblock|\[AdGuard')  # 过滤所有注释行
    HOSTS_RULE_REGEX = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)\s+([a-zA-Z0-9.-]+)\s*$')
    DOMAIN_REGEX = re.compile(r'^(?:@@)?(?:\|\|)?([a-zA-Z0-9.-]+)[\^\\/*]?')
    IP_CIDR_REGEX = re.compile(r'^(?:@@)?(?:\||)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|))')
    ELEMENT_HIDING_REGEX = re.compile(r'^##|\#@#')
    ADGUARD_MODIFIER_REGEX = re.compile(r'\$(.+)$')
    REGEX_RULE_REGEX = re.compile(r'^/(.*)/$')

    def __init__(self):
        # 1. 初始化分桶布隆过滤器（高效前置过滤）
        if AdBlockConfig.USE_BLOOM_FILTER and BLOOM_FILTER_AVAILABLE:
            self.bloom = ScalableBloomFilter(
                initial_capacity=AdBlockConfig.BLOOM_INITIAL_CAPACITY,
                error_rate=AdBlockConfig.BLOOM_ERROR_RATE
            )
        else:
            self.bloom = ScalableBloomFilter()

        # 2. 初始化分桶内存哈希表（精确兜底，解决布隆假阳性）
        self.hash_table = {
            "domain": set(),  # 域名规则：存储标准化后原文（非哈希，确保精确）
            "ip": set(),      # IP规则
            "adguard": set(), # AdGuard规则
            "normal": set()   # 其他规则
        }

        # 规则统计（新增假阳性统计）
        self.rule_stats = {
            'total_processed': 0, 'valid_rules': 0, 'invalid_rules': 0, 
            'duplicate_rules': 0, 'bloom_false_positive': 0,  # 新增：布隆假阳性数
            'domain_rules': 0, 'ip_rules': 0, 'element_hiding_rules': 0, 
            'adguard_rules': 0, 'dnsrewrite_rules': 0, 'regex_rules': 0, 
            'hosts_converted': 0, 'allow_rules': 0
        }

    def is_comment_or_empty(self, line: str) -> bool:
        """检查注释/空行（过滤所有注释）"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)

    def get_rule_type(self, rule: str) -> str:
        """判断规则类型（用于分桶去重，与哈希表分桶对应）"""
        if self.IP_CIDR_REGEX.match(rule):
            return "ip"
        elif '$' in rule or 'dnsrewrite' in rule:
            return "adguard"
        elif self.DOMAIN_REGEX.match(rule):
            return "domain"
        else:
            return "normal"

    def is_duplicate(self, rule: str) -> bool:
        """双重去重核心逻辑：布隆前置过滤 + 哈希表精确兜底"""
        rule_type = self.get_rule_type(rule)
        normalized_rule = self.normalize_rule(rule)  # 规则标准化（统一去重基准）

        # 步骤1：布隆过滤器快速排除“绝对不存在”的规则（99.95%+效率）
        if normalized_rule not in self.bloom:
            # 新增规则：同时加入布隆和哈希表
            self.bloom.add(normalized_rule, rule_type)
            self.hash_table[rule_type].add(normalized_rule)
            return False
        
        # 步骤2：布隆显示“可能存在”，哈希表精确判断（解决假阳性）
        if normalized_rule in self.hash_table[rule_type]:
            # 真重复：计数并返回
            self.rule_stats['duplicate_rules'] += 1
            return True
        else:
            # 假阳性：更新统计，将规则加入哈希表（避免后续误判）
            self.rule_stats['bloom_false_positive'] += 1
            self.hash_table[rule_type].add(normalized_rule)
            return False

    def normalize_rule(self, rule: str) -> str:
        """规则标准化（保留核心信息，统一去重基准）"""
        normalized = rule.strip().lower()
        if '$' in normalized:
            # 分离规则主体与修饰符，避免修饰符顺序导致的误判（如$third-party,script与$script,third-party）
            main_part, modifier_part = normalized.split('$', 1)
            # 主体简化：移除冗余前缀后缀（如||、^）
            main_part = re.sub(r'^\|\|(.*)\^$', r'\1', main_part)
            main_part = re.sub(r'^\@\@\|\|(.*)\^$', r'@@\1', main_part)
            # 修饰符排序：统一修饰符顺序，避免顺序差异导致的重复
            sorted_modifiers = sorted([m.strip() for m in modifier_part.split(',')])
            normalized = f"{main_part}${','.join(sorted_modifiers)}"
        else:
            # 非修饰符规则：简化主体
            normalized = re.sub(r'^\|\|(.*)\^$', r'\1', normalized)
            normalized = re.sub(r'^\@\@\|\|(.*)\^$', r'@@\1', normalized)
        return normalized

    def validate_rule(self, rule: str) -> bool:
        """规则验证（原逻辑保留，确保规则有效性）"""
        self.rule_stats['total_processed'] += 1
        rule = rule.strip()

        # 长度过滤
        if len(rule) > AdBlockConfig.RULE_LENGTH_LIMIT:
            self.rule_stats['invalid_rules'] += 1
            return False

        # AdGuard修饰符验证
        if '$' in rule and not self.validate_adguard_modifiers(rule):
            self.rule_stats['invalid_rules'] += 1
            return False

        # 规则类型验证（仅保留有效规则类型）
        if any([
            self.DOMAIN_REGEX.match(rule),
            self.IP_CIDR_REGEX.match(rule),
            self.ELEMENT_HIDING_REGEX.match(rule),
            self.REGEX_RULE_REGEX.match(rule),
            '$dnsrewrite' in rule
        ]):
            self.rule_stats['valid_rules'] += 1
            # 允许规则统计
            if rule.startswith('@@') or '#@#' in rule:
                self.rule_stats['allow_rules'] += 1
            return True

        self.rule_stats['invalid_rules'] += 1
        return False

    def validate_adguard_modifiers(self, rule: str) -> bool:
        """验证AdGuard修饰符（原逻辑保留）"""
        modifier_match = self.ADGUARD_MODIFIER_REGEX.search(rule)
        if not modifier_match:
            return False

        modifiers = [m.strip() for m in modifier_match.group(1).split(',')]
        for mod in modifiers:
            mod_name = mod.split('=')[0] if '=' in mod else mod
            if mod_name not in self.SUPPORTED_MODIFIERS:
                logger.debug(f"忽略未知修饰符规则: {rule}（修饰符: {mod_name}）")
                return False
        return True

    def convert_hosts_to_adblock(self, line: str) -> Optional[str]:
        """Hosts规则转AdBlock规则（纯净格式，原逻辑保留）"""
        match = self.HOSTS_RULE_REGEX.match(line)
        if not match:
            return None

        ip, domain = match.groups()
        # 过滤本地无效规则
        if ip in ['127.0.0.1', '::1'] and domain in ['localhost', 'localhost.localdomain']:
            return None

        adblock_rule = f"||{domain}^"
        self.rule_stats['hosts_converted'] += 1
        return adblock_rule

    def classify_rule(self, line: str, is_hosts: bool = False) -> List[Tuple[str, bool]]:
        """规则分类（仅输出纯净规则，集成双重去重）"""
        line = line.strip()
        results = []

        # 过滤注释/空行
        if self.is_comment_or_empty(line):
            return results

        # 处理Hosts文件（转纯净AdBlock规则）
        if is_hosts and AdBlockConfig.SUPPORT_HOSTS_CONVERT:
            hosts_rule = self.convert_hosts_to_adblock(line)
            if hosts_rule:
                # 先去重，再验证（避免无效规则占用内存）
                if not self.is_duplicate(hosts_rule) and self.validate_rule(hosts_rule):
                    results.append((hosts_rule, False))
            return results

        # 过滤非Hosts文件中的Hosts格式规则（避免重复处理）
        if self.HOSTS_RULE_REGEX.match(line):
            return results

        # 元素隐藏规则分类
        if self.ELEMENT_HIDING_REGEX.match(line):
            is_allow = '#@#' in line
            if not self.is_duplicate(line) and self.validate_rule(line):
                self.rule_stats['element_hiding_rules'] += 1
                results.append((line, is_allow))
            return results

        # DNS重写规则分类
        if '$dnsrewrite' in line:
            if not self.is_duplicate(line) and self.validate_rule(line):
                self.rule_stats['dnsrewrite_rules'] += 1
                self.rule_stats['adguard_rules'] += 1
                results.append((line, False))
            return results

        # IP/CIDR规则分类
        ip_match = self.IP_CIDR_REGEX.match(line)
        if ip_match and AdBlockConfig.ALLOW_IP_RULES:
            rule = ip_match.group(0)
            is_allow = rule.startswith('@@')
            if not self.is_duplicate(rule) and self.validate_rule(rule):
                self.rule_stats['ip_rules'] += 1
                results.append((rule, is_allow))
            return results

        # 正则规则分类
        if self.REGEX_RULE_REGEX.match(line):
            if not self.is_duplicate(line) and self.validate_rule(line):
                self.rule_stats['regex_rules'] += 1
                results.append((line, line.startswith('@@')))
            return results

        # 域名/AdGuard规则分类
        domain_match = self.DOMAIN_REGEX.match(line)
        if domain_match or '$' in line:
            rule = line
            is_allow = rule.startswith('@@')
            if not self.is_duplicate(rule) and self.validate_rule(rule):
                if domain_match and '$' not in rule:
                    self.rule_stats['domain_rules'] += 1
                else:
                    self.rule_stats['adguard_rules'] += 1
                results.append((rule, is_allow))
            return results

        return results

# ==================== 规则合并器（内存优化 + 双重去重兼容） ====================
class AdBlockRuleMerger:
    """规则合并器（仅输出纯净规则，兼容双重去重）"""
    def __init__(self):
        self.parser = AdBlockRuleParser()
        self.block_rules = set()  # 纯净拦截规则集（存储原始规则，确保语法正确）
        self.allow_rules = set()  # 纯净允许规则集
        self.BATCH_WRITE_THRESHOLD = 10000  # 分批次写入阈值（控制内存占用）

    def add_rule(self, rule: str, is_allow: bool):
        """添加纯净规则（去重后存入，原逻辑保留）"""
        if is_allow:
            self.allow_rules.add(rule)
        else:
            self.block_rules.add(rule)
        # 分批次清理内存（移除被允许规则覆盖的拦截规则）
        if len(self.block_rules) > self.BATCH_WRITE_THRESHOLD * 2:
            self._batch_optimize()

    def _batch_optimize(self):
        """分批次优化规则（原逻辑保留，确保规则有效性）"""
        # 提取允许规则中的域名（用于过滤拦截规则）
        allow_domains = set()
        for allow_rule in self.allow_rules:
            domain_match = self.parser.DOMAIN_REGEX.match(allow_rule)
            if domain_match:
                allow_domains.add(domain_match.group(1))

        # 过滤被允许规则覆盖的拦截规则
        new_block_rules = set()
        for rule in self.block_rules:
            domain_match = self.parser.DOMAIN_REGEX.match(rule)
            # 仅保留“无域名匹配”或“域名不在允许列表”的拦截规则
            if not domain_match or domain_match.group(1) not in allow_domains:
                new_block_rules.add(rule)
        self.block_rules = new_block_rules

    async def process_file(self, file_path: Path, is_hosts: bool = False):
        """异步处理单个文件（逐行读取，仅保留纯净规则，原逻辑保留）"""
        file_name = file_path.name
        rule_count = 0

        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    # 调用改进后的classify_rule（已集成双重去重）
                    classified = self.parser.classify_rule(line, is_hosts=is_hosts)
                    for rule, is_allow in classified:
                        self.add_rule(rule, is_allow)
                        rule_count += 1
            logger.info(f"处理完成：{file_name} → 有效纯净规则 {rule_count} 条")
        except Exception as e:
            logger.error(f"处理文件 {file_name} 失败：{str(e)}")

        return rule_count

    async def process_files(self):
        """批量处理所有文件（原逻辑保留，控制并发）"""
        tasks = []

        # 1. 处理Hosts文件
        for pattern in AdBlockConfig.HOSTS_PATTERNS:
            for file_path in glob.glob(str(AdBlockConfig.INPUT_DIR / pattern)):
                tasks.append(self.process_file(Path(file_path), is_hosts=True))

        # 2. 处理AdBlock拦截规则
        for pattern in AdBlockConfig.ADBLOCK_PATTERNS:
            for file_path in glob.glob(str(AdBlockConfig.INPUT_DIR / pattern)):
                tasks.append(self.process_file(Path(file_path), is_hosts=False))

        # 3. 处理允许/白名单规则
        for pattern in AdBlockConfig.ALLOW_PATTERNS:
            for file_path in glob.glob(str(AdBlockConfig.INPUT_DIR / pattern)):
                tasks.append(self.process_file(Path(file_path), is_hosts=False))

        # 控制并发（避免Github Action资源超限）
        semaphore = asyncio.Semaphore(AdBlockConfig.MAX_CONCURRENT_FILES)
        async def limited_task(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(t) for t in tasks], return_exceptions=True)
        total_rules = 0
        for res in results:
            if isinstance(res, int):
                total_rules += res
            else:
                logger.error(f"任务失败：{str(res)}")

        return total_rules

    def get_sorted_rules(self) -> Tuple[List[str], List[str]]:
        """规则排序（按类型分组，提升可用性，原逻辑保留）"""
        def rule_sort_key(rule):
            # 排序优先级：IP规则 → 域名规则 → AdGuard规则 → 元素隐藏规则 → 其他规则
            if self.parser.IP_CIDR_REGEX.match(rule):
                return (0, rule)
            elif self.parser.DOMAIN_REGEX.match(rule) and '$' not in rule:
                return (1, rule)
            elif '$' in rule:
                return (2, rule)
            elif self.parser.ELEMENT_HIDING_REGEX.match(rule):
                return (3, rule)
            else:
                return (4, rule)

        sorted_block = sorted(self.block_rules, key=rule_sort_key)
        sorted_allow = sorted(self.allow_rules, key=rule_sort_key)
        return sorted_block, sorted_allow

    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计（新增假阳性统计）"""
        stats = self.parser.rule_stats.copy()
        stats.update({
            'final_block_rules': len(self.block_rules),
            'final_allow_rules': len(self.allow_rules),
            'final_total_rules': len(self.block_rules) + len(self.allow_rules),
            'bloom_false_positive_rate': (stats['bloom_false_positive'] / stats['total_processed'] * 100) 
                                         if stats['total_processed'] > 0 else 0.0  # 假阳性率
        })
        return stats

# ==================== 输入输出工具（仅输出纯净规则） ====================
def ensure_dirs():
    """确保输入输出目录存在（原逻辑保留）"""
    AdBlockConfig.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    AdBlockConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"输入目录：{AdBlockConfig.INPUT_DIR.absolute()}")
    logger.info(f"输出目录：{AdBlockConfig.OUTPUT_DIR.absolute()}")

async def write_rules(block_rules: List[str], allow_rules: List[str]):
    """异步写入纯净规则（无规则头，仅一行一条规则，原逻辑保留）"""
    # 写入拦截规则（纯净格式）
    output_block = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_BLOCK
    async with aiofiles.open(output_block, 'w', encoding='utf-8', newline='\n') as f:
        batch_size = 10000  # 分批次写入，避免内存峰值
        for i in range(0, len(block_rules), batch_size):
            batch = block_rules[i:i+batch_size]
            await f.write('\n'.join(batch) + '\n')
    logger.info(f"已写入纯净拦截规则：{output_block.absolute()}（{len(block_rules)} 条）")

    # 写入允许规则（纯净格式）
    output_allow = AdBlockConfig.OUTPUT_DIR / AdBlockConfig.OUTPUT_ALLOW
    async with aiofiles.open(output_allow, 'w', encoding='utf-8', newline='\n') as f:
        for i in range(0, len(allow_rules), batch_size):
            batch = allow_rules[i:i+batch_size]
            await f.write('\n'.join(batch) + '\n')
    logger.info(f"已写入纯净允许规则：{output_allow.absolute()}（{len(allow_rules)} 条）")

# ==================== 主程序（纯净规则入口 + 双重去重统计） ====================
async def main():
    start_time = datetime.now()
    logger.info("=== 开始AdBlock纯净规则合并与优化（双重去重模式） ===")

    # 初始化目录
    ensure_dirs()

    # 初始化合并器（已集成双重去重解析器）
    merger = AdBlockRuleMerger()

    # 处理所有文件
    logger.info("开始处理输入文件...")
    total_processed = await merger.process_files()
    logger.info(f"文件处理完成：共处理 {total_processed} 条有效纯净规则（去重前）")

    # 排序并写入纯净规则
    logger.info("开始排序并写入纯净规则文件...")
    block_rules, allow_rules = merger.get_sorted_rules()
    await write_rules(block_rules, allow_rules)

    # 输出统计信息（新增双重去重相关统计）
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    stats = merger.get_stats()

    logger.info("\n=== 处理统计报告（含双重去重信息） ===")
    logger.info(f"总耗时：{duration:.2f} 秒")
    logger.info(f"原始规则：{stats['total_processed']} 条（已处理）")
    logger.info(f"有效规则：{stats['valid_rules']} 条 | 无效规则：{stats['invalid_rules']} 条")
    logger.info(f"去重情况：重复规则 {stats['duplicate_rules']} 条 | 布隆假阳性 {stats['bloom_false_positive']} 条（假阳性率 {stats['bloom_false_positive_rate']:.4f}%）")
    logger.info(f"最终纯净规则：")
    logger.info(f"  - 拦截规则：{stats['final_block_rules']} 条")
    logger.info(f"  - 允许规则：{stats['final_allow_rules']} 条")
    logger.info(f"  - 总规则：{stats['final_total_rules']} 条")
    logger.info(f"规则类型分布：域名 {stats['domain_rules']} 条 | IP {stats['ip_rules']} 条 | AdGuard {stats['adguard_rules']} 条 | 元素隐藏 {stats['element_hiding_rules']} 条")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.error("处理被用户中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"程序运行出错：{str(e)}", exc_info=True)
        sys.exit(1)
