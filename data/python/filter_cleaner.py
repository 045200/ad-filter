#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adblock规则处理与优化脚本 (GitHub Actions 优化版)
支持 AdBlock / AdGuard 语法，包含DNS验证、规则合并与去重
模块化设计，支持国内外域名智能分流解析
"""

import argparse
import asyncio
import aiohttp
import aiodns
import logging
import re
import time
import json
import gzip
import shutil
import ipaddress
import maxminddb
import psutil
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from datetime import datetime
from collections import OrderedDict
from urllib.parse import urlparse
import ssl
import certifi

# 配置单例类
class Config:
    GITHUB_WORKSPACE = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    
    # 输入输出路径
    INPUT_DIR = GITHUB_WORKSPACE / "data" / "filter"
    OUTPUT_DIR = GITHUB_WORKSPACE / "data" / "filter"
    CLEANED_FILE = OUTPUT_DIR / "adblock.txt"
    
    # 依赖文件路径 (由外部脚本下载)
    GEOIP_DB_FILE = GITHUB_WORKSPACE / "data" / "GeoLite2-Country.mmdb"
    CHINA_IP_RANGES_FILE = GITHUB_WORKSPACE / "data" / "china_ip_list.txt"
    
    # 备份与白名单
    BACKUP_DIR = GITHUB_WORKSPACE / "data" / "mod" / "backups"
    INVALID_DOMAINS_FILE = GITHUB_WORKSPACE / "data" / "mod" / "invalid_domains.json"
    WHITELIST_FILE = GITHUB_WORKSPACE / "data" / "mod" / "domians.txt"
    
    # 性能与资源配置
    MAX_WORKERS = 4
    DNS_WORKERS = 30
    BATCH_SIZE = 500
    MAX_MEMORY_PERCENT = 80
    DNS_TIMEOUT = 5
    DNS_RETRIES = 2
    
    # DNS服务器配置 (国内外分流)
    DNS_SERVERS = {
        'global': ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
        'china': ['223.5.5.5', '119.29.29.29', '180.76.76.76']
    }
    
    # 缓存配置
    CACHE_TTL = 3600
    MAX_CACHE_SIZE = 10000
    INVALID_DOMAIN_EXPIRY_DAYS = 30

# 正则模式类
class RegexPatterns:
    DOMAIN_EXTRACT = re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]')
    HOSTS_RULE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    # AdGuard 特定模式
    ADGUARD_SCRIPT = re.compile(r'.*\$.*script.*')
    ADGUARD_CSS = re.compile(r'.*#\$#.*')
    ADGUARD_JS = re.compile(r'.*#@#.*')
    ADGUARD_CSP = re.compile(r'.*\$csp=')
    ADGUARD_DOMAIN = re.compile(r'^@@?\|?https?://[^/]+')

# 日志配置
def setup_logger(name: str = 'AdblockProcessor') -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger

logger = setup_logger()

# GeoIP 服务（直接从指定路径读取）
class GeoIPService:
    def __init__(self, db_path: Path):
        self.reader = None
        self.china_ip_ranges = set()
        self.db_path = db_path
        self._init_geoip()
        self._load_china_ip_ranges()
    
    def _init_geoip(self) -> None:
        """初始化GeoIP数据库（直接从指定路径读取）"""
        if self.db_path.exists():
            try:
                self.reader = maxminddb.open_database(str(self.db_path))
                logger.info(f"GeoIP数据库加载成功: {self.db_path}")
            except Exception as e:
                logger.error(f"加载GeoIP数据库失败: {e}")
        else:
            logger.warning(f"GeoIP数据库文件不存在: {self.db_path}")
    
    def _load_china_ip_ranges(self) -> None:
        """加载中国IP范围列表"""
        if Config.CHINA_IP_RANGES_FILE.exists():
            try:
                with open(Config.CHINA_IP_RANGES_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.china_ip_ranges.add(line)
                logger.info(f"已加载 {len(self.china_ip_ranges)} 个中国IP范围")
            except Exception as e:
                logger.error(f"加载中国IP范围失败: {e}")
        else:
            # 常见中国IP段后备方案
            self.china_ip_ranges.update([
                '1.0.1.0/24', '1.0.2.0/23', '1.0.8.0/21', '1.0.32.0/19',
                '223.0.0.0/8', '220.160.0.0/11', '219.128.0.0/11'
            ])
            logger.info("使用内置中国IP范围数据")
    
    def is_china_ip(self, ip_str: str) -> bool:
        """判断IP是否属于中国"""
        try:
            # 首先尝试GeoIP数据库
            if self.reader:
                try:
                    result = self.reader.get(ip_str)
                    if result and 'country' in result:
                        return result['country']['iso_code'] == 'CN'
                except Exception:
                    pass
            
            # 然后检查IP范围列表
            ip_obj = ipaddress.ip_address(ip_str)
            for ip_range in self.china_ip_ranges:
                if ip_obj in ipaddress.ip_network(ip_range):
                    return True
                    
            return False
        except Exception:
            return False
    
    def close(self) -> None:
        """关闭GeoIP读取器"""
        if self.reader:
            self.reader.close()

# 资源监控器
class ResourceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.peak_memory = 0
        self.process = psutil.Process(os.getpid())
    
    def check_memory_usage(self) -> bool:
        """检查内存使用情况，返回是否超过限制"""
        memory_mb = self.process.memory_info().rss / 1024 / 1024
        self.peak_memory = max(self.peak_memory, memory_mb)
        
        total_memory = psutil.virtual_memory().total / 1024 / 1024
        memory_percent = (memory_mb / total_memory) * 100
        
        if memory_percent > Config.MAX_MEMORY_PERCENT:
            logger.warning(f"内存使用率过高: {memory_percent:.1f}% ({memory_mb:.1f}MB)")
            return False
        return True
    
    def get_stats(self) -> Dict:
        """获取资源使用统计"""
        memory_mb = self.process.memory_info().rss / 1024 / 1024
        cpu_percent = self.process.cpu_percent()
        elapsed = time.time() - self.start_time
        
        return {
            'memory_mb': memory_mb,
            'cpu_percent': cpu_percent,
            'elapsed_seconds': elapsed,
            'peak_memory_mb': self.peak_memory
        }

# DNS缓存实现
class DNSCache:
    """LRU DNS缓存实现"""
    def __init__(self, maxsize: int = 10000):
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0
    
    def get(self, domain: str) -> Optional[bool]:
        """获取缓存结果"""
        if domain in self.cache:
            self.hits += 1
            self.cache.move_to_end(domain)
            return self.cache[domain]
        self.misses += 1
        return None
    
    def set(self, domain: str, result: bool) -> None:
        """设置缓存结果"""
        if domain in self.cache:
            self.cache.move_to_end(domain)
        else:
            if len(self.cache) >= self.maxsize:
                self.cache.popitem(last=False)
        self.cache[domain] = result
    
    def get_stats(self) -> Dict:
        """获取缓存统计"""
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0,
            'size': len(self.cache)
        }

# 智能DNS验证器
class DNSValidator:
    def __init__(self, geoip_service: GeoIPService):
        self.geoip = geoip_service
        self.cache = DNSCache(maxsize=Config.MAX_CACHE_SIZE)
        self.resolver = aiodns.DNSResolver()
        self.resolver.timeout = Config.DNS_TIMEOUT
        
        # 会话和连接器
        self.session = None
        self.connector = None
        
        # 域名策略缓存
        self.domain_strategies = {}
        
        # 统计信息
        self.stats = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'china_domains': 0,
            'global_domains': 0,
            'cache_hits': 0
        }
    
    async def init_session(self) -> None:
        """初始化aiohttp会话"""
        if self.session is None:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            self.connector = aiohttp.TCPConnector(
                limit=min(Config.DNS_WORKERS, 50),
                ssl=ssl_context
            )
            self.session = aiohttp.ClientSession(connector=self.connector)
    
    async def close_session(self) -> None:
        """关闭aiohttp会话"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    async def determine_domain_strategy(self, domain: str) -> str:
        """确定域名解析策略（国内/国际）"""
        if domain in self.domain_strategies:
            return self.domain_strategies[domain]
        
        # 基于域名特征判断
        china_tlds = {'.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.edu.cn'}
        china_keywords = {'baidu', 'tencent', 'qq', 'alibaba', 'taobao', 'jd', 'weibo',
                         'xiaomi', 'huawei', 'sina', 'sohu', '163', '126'}
        
        # 检查域名后缀
        if any(domain.endswith(tld) for tld in china_tlds):
            self.domain_strategies[domain] = 'china'
            return 'china'
        
        # 检查域名关键字
        if any(keyword in domain for keyword in china_keywords):
            self.domain_strategies[domain] = 'china'
            return 'china'
        
        # 默认使用国际策略
        self.domain_strategies[domain] = 'global'
        return 'global'
    
    async def resolve_domain(self, domain: str, strategy: str) -> bool:
        """解析域名"""
        self.stats['total_queries'] += 1
        
        try:
            # 选择DNS服务器
            dns_servers = Config.DNS_SERVERS[strategy]
            self.resolver.nameservers = dns_servers
            
            # 执行DNS查询
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            
            self.stats['successful_queries'] += 1
            if strategy == 'china':
                self.stats['china_domains'] += 1
            else:
                self.stats['global_domains'] += 1
                
            return len(result) > 0
        except (asyncio.TimeoutError, aiodns.error.DNSError):
            self.stats['failed_queries'] += 1
            return False
        except Exception as e:
            logger.debug(f"DNS查询异常 {domain}: {e}")
            self.stats['failed_queries'] += 1
            return False
    
    async def is_domain_valid(self, domain: str) -> bool:
        """检查域名是否有效"""
        # 检查缓存
        cached_result = self.cache.get(domain)
        if cached_result is not None:
            self.stats['cache_hits'] += 1
            return cached_result
        
        # 确定解析策略
        strategy = await self.determine_domain_strategy(domain)
        
        # 解析域名
        result = await self.resolve_domain(domain, strategy)
        
        # 缓存结果
        self.cache.set(domain, result)
        
        return result

# 规则处理器
class RuleProcessor:
    def __init__(self):
        self.regex = RegexPatterns()
        self.known_invalid_domains = set()
        self.whitelist_domains = set()
        self._load_invalid_domains()
        self._load_whitelist()
    
    def _load_invalid_domains(self) -> None:
        """加载已知无效域名"""
        if Config.INVALID_DOMAINS_FILE.exists():
            try:
                with open(Config.INVALID_DOMAINS_FILE, 'r') as f:
                    data = json.load(f)
                    self.known_invalid_domains = set(data.get('domains', []))
                logger.info(f"已加载 {len(self.known_invalid_domains)} 个已知无效域名")
            except Exception as e:
                logger.error(f"加载无效域名列表失败: {e}")
    
    def _load_whitelist(self) -> None:
        """加载白名单域名"""
        if Config.WHITELIST_FILE.exists():
            try:
                with open(Config.WHITELIST_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('*.'):
                                line = line[2:]
                            self.whitelist_domains.add(line)
                logger.info(f"已加载 {len(self.whitelist_domains)} 个白名单域名")
            except Exception as e:
                logger.error(f"加载白名单失败: {e}")
    
    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从规则中提取域名"""
        rule = rule.strip()
        
        # 跳过注释和空行
        if self.regex.COMMENT.match(rule) or self.regex.EMPTY_LINE.match(rule):
            return None
        
        # 尝试匹配各种规则格式
        domain_match = self.regex.DOMAIN_EXTRACT.match(rule)
        if domain_match:
            domain = domain_match.group(1)
            if '$' in domain:
                domain = domain.split('$')[0]
            return domain
        
        hosts_match = self.regex.HOSTS_RULE.match(rule)
        if hosts_match:
            return hosts_match.group(1)
        
        adguard_match = self.regex.ADGUARD_DOMAIN.match(rule)
        if adguard_match:
            domain = adguard_match.group(0).lstrip('@|').lstrip('https://').lstrip('http://')
            return domain.split('/')[0]
        
        return None
    
    def is_rule_valid(self, rule: str, domain: Optional[str] = None) -> bool:
        """检查规则是否有效"""
        if domain is None:
            domain = self.extract_domain_from_rule(rule)
        
        if not domain:
            return True  # 无法提取域名的规则默认有效
        
        # 检查白名单
        if domain in self.whitelist_domains:
            return True
        
        # 检查已知无效域名
        if domain in self.known_invalid_domains:
            return False
        
        return True  # 默认有效

# 规则优化器
class RuleOptimizer:
    def __init__(self):
        self.regex = RegexPatterns()
        self.processed_rules = set()
    
    def optimize_rules(self, rules: List[str]) -> List[str]:
        """优化规则列表"""
        optimized = []
        
        for rule in rules:
            if self._should_keep_rule(rule):
                optimized.append(rule)
        
        # 去重
        unique_rules = list(OrderedDict.fromkeys(optimized))
        
        logger.info(f"规则优化完成: 原始 {len(rules)} 条, 优化后 {len(unique_rules)} 条")
        return unique_rules
    
    def _should_keep_rule(self, rule: str) -> bool:
        """判断是否应该保留规则"""
        rule = rule.strip()
        
        # 跳过空行
        if not rule:
            return False
        
        # 保留注释
        if rule.startswith(('!', '#')):
            return True
        
        # 检查重复规则
        if rule in self.processed_rules:
            return False
        self.processed_rules.add(rule)
        
        return True

# 主处理器
class AdblockProcessor:
    def __init__(self):
        self.geoip = GeoIPService(Config.GEOIP_DB_FILE)
        self.validator = DNSValidator(self.geoip)
        self.rule_processor = RuleProcessor()
        self.rule_optimizer = RuleOptimizer()
        self.resource_monitor = ResourceMonitor()
        
        # 确保目录存在
        Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    async def process_files(self) -> None:
        """处理所有规则文件"""
        logger.info("开始处理规则文件")
        start_time = time.time()
        
        # 初始化DNS验证器
        await self.validator.init_session()
        
        try:
            # 查找所有输入文件
            input_files = list(Config.INPUT_DIR.glob("*.txt"))
            if not input_files:
                logger.warning(f"未找到输入文件于 {Config.INPUT_DIR}")
                return
            
            logger.info(f"找到 {len(input_files)} 个输入文件")
            
            # 处理每个文件
            all_rules = []
            for file_path in input_files:
                rules = await self._process_single_file(file_path)
                all_rules.extend(rules)
            
            # 优化和保存规则
            if all_rules:
                optimized_rules = self.rule_optimizer.optimize_rules(all_rules)
                self._save_rules(optimized_rules)
            
            # 保存统计信息
            elapsed = time.time() - start_time
            self._save_stats(elapsed)
            
        finally:
            # 清理资源
            await self.validator.close_session()
            self.geoip.close()
    
    async def _process_single_file(self, file_path: Path) -> List[str]:
        """处理单个文件"""
        logger.info(f"处理文件: {file_path.name}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []
        
        # 提取域名并验证
        domains_to_validate = set()
        domain_to_rules = {}
        
        for line in lines:
            domain = self.rule_processor.extract_domain_from_rule(line)
            if domain:
                domains_to_validate.add(domain)
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = []
                domain_to_rules[domain].append(line.strip())
        
        logger.info(f"从 {file_path.name} 提取到 {len(domains_to_validate)} 个域名")
        
        # 批量验证域名
        valid_domains = await self._validate_domains_batch(list(domains_to_validate))
        
        # 构建有效规则列表
        valid_rules = []
        for domain, rules in domain_to_rules.items():
            if domain in valid_domains:
                valid_rules.extend(rules)
        
        logger.info(f"文件 {file_path.name} 保留 {len(valid_rules)} 条有效规则")
        return valid_rules
    
    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名"""
        valid_domains = set()
        total_domains = len(domains)
        
        logger.info(f"开始验证 {total_domains} 个域名")
        
        # 分批处理
        for i in range(0, total_domains, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            batch_num = i // Config.BATCH_SIZE + 1
            total_batches = (total_domains + Config.BATCH_SIZE - 1) // Config.BATCH_SIZE
            
            logger.info(f"处理域名批次 {batch_num}/{total_batches} ({len(batch)} 个域名)")
            
            # 验证批次中的域名
            tasks = [self.validator.is_domain_valid(domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(results):
                if isinstance(result, Exception) or not result:
                    continue
                valid_domains.add(batch[j])
            
            # 检查资源使用
            if not self.resource_monitor.check_memory_usage():
                logger.warning("内存使用接近限制，暂停处理")
                await asyncio.sleep(1)
            
            # 记录进度
            resource_stats = self.resource_monitor.get_stats()
            logger.info(
                f"进度: {min(i + Config.BATCH_SIZE, total_domains)}/{total_domains} "
                f"域名 | 内存: {resource_stats['memory_mb']:.1f}MB"
            )
        
        logger.info(f"域名验证完成: 有效 {len(valid_domains)}/{total_domains}")
        return valid_domains
    
    def _save_rules(self, rules: List[str]) -> None:
        """保存规则到文件"""
        try:
            with open(Config.CLEANED_FILE, 'w', encoding='utf-8') as f:
                for rule in rules:
                    f.write(f"{rule}\n")
            logger.info(f"已保存 {len(rules)} 条规则到 {Config.CLEANED_FILE}")
        except Exception as e:
            logger.error(f"保存规则失败: {e}")
    
    def _save_stats(self, elapsed: float) -> None:
        """保存统计信息"""
        stats = {
            'timestamp': datetime.now().isoformat(),
            'processing_time_seconds': elapsed,
            'resource_usage': self.resource_monitor.get_stats(),
            'dns_stats': self.validator.stats,
            'cache_stats': self.validator.cache.get_stats(),
            'rules_processed': len(self.rule_optimizer.processed_rules)
        }
        
        # 保存JSON统计
        stats_file = Config.OUTPUT_DIR / "processing_stats.json"
        try:
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            logger.info(f"统计信息已保存到 {stats_file}")
        except Exception as e:
            logger.error(f"保存统计信息失败: {e}")
        
        # 输出摘要
        logger.info("\n===== 处理完成 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"峰值内存: {self.resource_monitor.peak_memory:.1f} MB")
        logger.info(f"处理规则: {len(self.rule_optimizer.processed_rules)} 条")
        logger.info(f"DNS查询: {self.validator.stats['total_queries']} 次")
        logger.info(f"缓存命中率: {self.validator.cache.get_stats()['hit_rate']:.1%}")

# 命令行接口
def main():
    parser = argparse.ArgumentParser(description='Adblock规则处理与优化工具')
    parser.add_argument('--input', type=Path, default=Config.INPUT_DIR, 
                       help='输入目录路径')
    parser.add_argument('--output', type=Path, default=Config.OUTPUT_DIR,
                       help='输出目录路径')
    parser.add_argument('--geoip', type=Path, default=Config.GEOIP_DB_FILE,
                       help='GeoIP数据库路径')
    parser.add_argument('--workers', type=int, default=Config.MAX_WORKERS,
                       help='工作线程数')
    
    args = parser.parse_args()
    
    # 更新配置
    if args.input != Config.INPUT_DIR:
        Config.INPUT_DIR = args.input
    if args.output != Config.OUTPUT_DIR:
        Config.OUTPUT_DIR = args.output
    if args.geoip != Config.GEOIP_DB_FILE:
        Config.GEOIP_DB_FILE = args.geoip
    if args.workers != Config.MAX_WORKERS:
        Config.MAX_WORKERS = args.workers
    
    # 创建处理器并运行
    processor = AdblockProcessor()
    asyncio.run(processor.process_files())

if __name__ == '__main__':
    main()