#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adblock规则清理与优化脚本 (修复版)
修复DNS验证问题，添加备用验证方法
"""

import os
import re
import sys
import glob
import json
import time
import logging
import asyncio
import aiohttp
import aiodns
import ipaddress
import maxminddb
import psutil
import xxhash
import random
import subprocess
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from datetime import datetime
from collections import OrderedDict
from urllib.parse import urlparse
import ssl
import certifi

# 配置类
class Config:
    # 基础路径
    GITHUB_WORKSPACE = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    BASE_DIR = GITHUB_WORKSPACE

    # 输入输出路径
    INPUT_DIR = BASE_DIR / "data" / "filter"
    OUTPUT_DIR = BASE_DIR / "data" / "filter"
    CLEANED_FILE = OUTPUT_DIR / "adblock.txt"

    # 依赖文件路径
    GEOIP_DB_FILE = BASE_DIR / "data" / "GeoLite2-Country.mmdb"
    CHINA_IP_RANGES_FILE = BASE_DIR / "data" / "china_ip_list.txt"

    # 备份与白名单
    BACKUP_DIR = BASE_DIR / "data" / "mod" / "backups"
    INVALID_DOMAINS_FILE = BASE_DIR / "data" / "mod" / "invalid_domains.json"
    WHITELIST_FILE = BASE_DIR / "data" / "mod" / "domians.txt"

    # 缓存配置
    CACHE_DIR = BASE_DIR / "data" / "cache"
    CACHE_TTL = 86400  # 24小时缓存有效期
    MAX_CACHE_SIZE = 10000  # 添加缺失的配置项

    # 性能与资源配置
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 4))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 20))  # 减少并发量
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 200))   # 减小批次大小
    MAX_MEMORY_PERCENT = int(os.getenv('MAX_MEMORY_PERCENT', 80))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 10))  # 增加超时时间
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 3))   # 增加重试次数

    # DNS服务器配置 (国内外分流)
    DNS_SERVERS = {
        'global': ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
        'china': ['223.5.5.5', '119.29.29.29', '180.76.76.76']
    }

    # DoH (DNS over HTTPS) 备用方案
    DOH_SERVERS = {
        'global': [
            'https://cloudflare-dns.com/dns-query',
            'https://dns.google/resolve'
        ],
        'china': [
            'https://doh.pub/dns-query',
            'https://dns.alidns.com/dns-query'
        ]
    }

    # 启用备用验证方法
    USE_DOH = True
    USE_PING = True  # 使用ping作为备用验证

# 正则模式类
class RegexPatterns:
    DOMAIN_EXTRACT = re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]')
    HOSTS_RULE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

    # AdGuard 特定模式
    ADGUARD_SCRIPT = re.compile(r'.*\$.*script.*')
    ADGUARD_CSS = re.compile(r'.*#\$#.*')
    ADGUARD_JS = re.compile(r'.*#@#.*')
    ADGUARD_CSP = re.compile(r'.*\$csp=')
    ADGUARD_DOMAIN = re.compile(r'^@@?\|?https?://[^/]+')

# 日志配置
def setup_logger(name: str = 'AdblockCleaner') -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # 检查是否为GitHub Actions环境
    if os.getenv('GITHUB_ACTIONS') == 'true':
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(message)s')
    else:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

logger = setup_logger()

# GeoIP 服务
class GeoIPService:
    def __init__(self, db_path: Path):
        self.reader = None
        self.china_ip_ranges = set()
        self.db_path = db_path
        self._init_geoip()
        self._load_china_ip_ranges()

    def _init_geoip(self) -> None:
        """初始化GeoIP数据库"""
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
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'size': len(self.cache)
        }

# GitHub环境专用的缓存管理器
class GitHubCacheManager:
    """GitHub环境专用的缓存管理器"""

    def __init__(self, cache_dir: Path = Config.CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, domain: str) -> str:
        """生成缓存键名"""
        return xxhash.xxh64(domain.encode()).hexdigest()

    def _get_cache_path(self, domain: str) -> Path:
        """获取缓存文件路径"""
        cache_key = self._get_cache_key(domain)
        return self.cache_dir / f"{cache_key}.json"

    def get_cache(self, domain: str) -> Optional[Dict]:
        """获取缓存数据"""
        cache_path = self._get_cache_path(domain)
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    cache_data = json.load(f)

                # 检查缓存是否过期
                if time.time() - cache_data.get('timestamp', 0) < Config.CACHE_TTL:
                    return cache_data
            except Exception as e:
                logger.debug(f"读取缓存失败 {domain}: {e}")
        return None

    def set_cache(self, domain: str, result: bool, strategy: str) -> None:
        """设置缓存数据"""
        cache_path = self._get_cache_path(domain)
        try:
            cache_data = {
                'result': result,
                'timestamp': time.time(),
                'strategy': strategy,
                'domain': domain
            }

            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            logger.debug(f"缓存已保存: {domain} -> {result}")

        except Exception as e:
            logger.error(f"保存缓存失败 {domain}: {e}")

    def cleanup_old_cache(self, max_age_days: int = 7) -> None:
        """清理过期缓存"""
        current_time = time.time()
        cache_files = list(self.cache_dir.glob("*.json"))

        cleaned_count = 0
        for cache_file in cache_files:
            file_age = current_time - cache_file.stat().st_mtime
            if file_age > max_age_days * 86400:
                cache_file.unlink()
                cleaned_count += 1

        logger.info(f"已清理 {cleaned_count} 个过期缓存文件")

# 智能DNS验证器
class DNSValidator:
    def __init__(self, geoip_service: GeoIPService):
        self.geoip = geoip_service
        self.cache = DNSCache(maxsize=Config.MAX_CACHE_SIZE)
        self.cache_manager = GitHubCacheManager()
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
            'cache_hits': 0,
            'persistent_cache_hits': 0,
            'doh_queries': 0,
            'ping_checks': 0,
            'cache_misses': 0
        }

    async def init_session(self) -> None:
        """初始化aiohttp会话"""
        if self.session is None:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            self.connector = aiohttp.TCPConnector(
                limit=min(Config.DNS_WORKERS, 20),
                ssl=ssl_context
            )
            self.session = aiohttp.ClientSession(connector=self.connector)

    async def close_session(self) -> None:
        """关闭aiohttp会话"""
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()

    def is_valid_domain_format(self, domain: str) -> bool:
        """检查域名格式是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 检查是否包含非法字符
        if not RegexPatterns.DOMAIN_PATTERN.match(domain):
            return False
            
        # 检查是否为IP地址
        if RegexPatterns.IP_ADDRESS.match(domain):
            return False
            
        return True

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

    async def resolve_domain_doh(self, domain: str, strategy: str) -> bool:
        """使用DNS over HTTPS解析域名"""
        self.stats['doh_queries'] += 1
        
        doh_servers = Config.DOH_SERVERS[strategy]
        doh_url = random.choice(doh_servers)
        
        params = {
            'name': domain,
            'type': 'A'
        }
        headers = {
            'accept': 'application/dns-json'
        }

        try:
            async with self.session.get(doh_url, params=params, headers=headers, 
                                      timeout=Config.DNS_TIMEOUT) as response:
                if response.status == 200:
                    data = await response.json()
                    # 检查是否有Answer记录
                    if data.get('Answer') or data.get('Authority') or data.get('Additional'):
                        return True
                    # 检查是否有CNAME记录
                    if data.get('Question'):
                        return True
                return False
        except Exception as e:
            logger.debug(f"DoH查询失败 {domain}: {e}")
            return False

    async def ping_domain(self, domain: str) -> bool:
        """使用ping命令检查域名"""
        self.stats['ping_checks'] += 1
        
        try:
            # 使用ping命令检查域名
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    async def resolve_domain(self, domain: str, strategy: str) -> bool:
        """解析域名"""
        self.stats['total_queries'] += 1

        # 首先尝试标准DNS解析
        try:
            # 选择DNS服务器
            dns_servers = Config.DNS_SERVERS[strategy]
            self.resolver.nameservers = dns_servers

            # 执行DNS查询
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )

            if result:
                self.stats['successful_queries'] += 1
                if strategy == 'china':
                    self.stats['china_domains'] += 1
                else:
                    self.stats['global_domains'] += 1
                return True
        except Exception as e:
            logger.debug(f"DNS查询失败 {domain}: {e}")

        # 如果标准DNS失败，尝试DoH
        if Config.USE_DOH:
            doh_result = await self.resolve_domain_doh(domain, strategy)
            if doh_result:
                self.stats['successful_queries'] += 1
                return True

        # 如果DoH也失败，尝试ping
        if Config.USE_PING:
            ping_result = await self.ping_domain(domain)
            if ping_result:
                self.stats['successful_queries'] += 1
                return True

        self.stats['failed_queries'] += 1
        return False

    async def is_domain_valid(self, domain: str) -> bool:
        """检查域名是否有效"""
        # 首先检查域名格式
        if not self.is_valid_domain_format(domain):
            return False

        # 首先检查持久化缓存
        cache_data = self.cache_manager.get_cache(domain)
        if cache_data is not None:
            self.stats['persistent_cache_hits'] += 1
            return cache_data['result']

        # 然后检查内存缓存
        cached_result = self.cache.get(domain)
        if cached_result is not None:
            self.stats['cache_hits'] += 1
            return cached_result

        # 确定解析策略
        strategy = await self.determine_domain_strategy(domain)

        # 解析域名
        result = await self.resolve_domain(domain, strategy)

        # 保存到内存缓存
        self.cache.set(domain, result)

        # 保存到持久化缓存
        self.cache_manager.set_cache(domain, result, strategy)

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
class AdblockCleaner:
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
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def process_files(self) -> None:
        """处理所有规则文件"""
        logger.info("开始处理规则文件")
        start_time = time.time()

        # 清理过期缓存
        self.validator.cache_manager.cleanup_old_cache(7)

        # 初始化DNS验证器
        await self.validator.init_session()

        try:
            # 查找所有输入文件
            input_files = list(Config.INPUT_DIR.glob("adblock_filter.txt"))
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
            else:
                logger.warning("没有找到任何有效规则，创建空文件")
                self._save_rules(["! 由Adblock清理工具生成", "! 没有找到有效规则"])

            # 保存统计信息
            elapsed = time.time() - start_time
            self._save_stats(elapsed)

        except Exception as e:
            logger.error(f"处理文件时发生错误: {e}")
            import traceback
            logger.error(traceback.format_exc())
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
            if domain and self.validator.is_valid_domain_format(domain):
                domains_to_validate.add(domain)
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = []
                domain_to_rules[domain].append(line.strip())
            else:
                # 保留无法提取域名的规则（注释、特殊规则等）
                if line.strip() and not line.strip().startswith(('!', '#')):
                    logger.debug(f"无法提取有效域名的规则: {line.strip()}")

        logger.info(f"从 {file_path.name} 提取到 {len(domains_to_validate)} 个待验证域名")

        # 批量验证域名
        valid_domains = await self._validate_domains_batch(list(domains_to_validate))

        # 构建有效规则列表
        valid_rules = []
        for domain, rules in domain_to_rules.items():
            if domain in valid_domains:
                valid_rules.extend(rules)

        # 添加无法提取域名的规则（注释、特殊规则等）
        for line in lines:
            line = line.strip()
            if line and not self.rule_processor.extract_domain_from_rule(line):
                valid_rules.append(line)

        logger.info(f"文件 {file_path.name} 保留 {len(valid_rules)} 条有效规则")
        return valid_rules

    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名"""
        valid_domains = set()
        total_domains = len(domains)

        if total_domains == 0:
            return valid_domains

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
                if isinstance(result, Exception):
                    logger.debug(f"域名验证异常 {batch[j]}: {result}")
                    continue
                if result:
                    valid_domains.add(batch[j])

            # 检查资源使用
            if not self.resource_monitor.check_memory_usage():
                logger.warning("内存使用接近限制，暂停处理")
                await asyncio.sleep(1)

            # 记录进度
            valid_count = len(valid_domains)
            processed_count = min(i + Config.BATCH_SIZE, total_domains)
            resource_stats = self.resource_monitor.get_stats()
            logger.info(
                f"进度: {processed_count}/{total_domains} 域名 | "
                f"有效: {valid_count} | "
                f"内存: {resource_stats['memory_mb']:.1f}MB"
            )

        logger.info(f"域名验证完成: 有效 {len(valid_domains)}/{total_domains}")
        return valid_domains

    def _save_rules(self, rules: List[str]) -> None:
        """保存规则到文件"""
        try:
            # 创建备份
            if Config.CLEANED_FILE.exists():
                backup_file = Config.BACKUP_DIR / f"adblock_backup_{int(time.time())}.txt"
                Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                with open(backup_file, 'w', encoding='utf-8') as f:
                    with open(Config.CLEANED_FILE, 'r', encoding='utf-8') as original:
                        f.write(original.read())

            # 保存新规则
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
            'persistent_cache_stats': {
                'hits': self.validator.stats['persistent_cache_hits'],
                'total_queries': self.validator.stats['total_queries'],
                'hit_rate': self.validator.stats['persistent_cache_hits'] / self.validator.stats['total_queries'] 
                if self.validator.stats['total_queries'] > 0 else 0
            },
            'rules_processed': len(self.rule_optimizer.processed_rules)
        }

        # 保存JSON统计
        stats_file = Config.OUTPUT_DIR / "cleaning_stats.json"
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
        logger.info(f"成功查询: {self.validator.stats['successful_queries']} 次")
        logger.info(f"失败查询: {self.validator.stats['failed_queries']} 次")
        logger.info(f"DoH查询: {self.validator.stats['doh_queries']} 次")
        logger.info(f"Ping检查: {self.validator.stats['ping_checks']} 次")
        logger.info(f"内存缓存命中率: {self.validator.cache.get_stats()['hit_rate']:.1%}")

# 主函数
async def main():
    """主函数"""
    try:
        cleaner = AdblockCleaner()
        await cleaner.process_files()
    except Exception as e:
        logger.error(f"规则清理失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())