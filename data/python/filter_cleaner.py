#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adblock规则清理工具 - 支持Adguard语法及规则合并去重"""

import os
import sys
import glob
import re
import logging
import time
import asyncio
import aiohttp
import aiodns
import ssl
import certifi
from pathlib import Path
from typing import Tuple, List, Set, Dict, Optional
from urllib.parse import urlparse
import json
from datetime import datetime, timedelta
import psutil
import gzip
import shutil
import ipaddress
import maxminddb


class Config:
    """配置：GitHub CI 环境优化配置"""
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)

    # 输入输出目录
    TEMP_DIR = BASE_DIR / "data" / "filter"
    OUTPUT_DIR = TEMP_DIR
    CLEANED_FILE = TEMP_DIR / "adblock_merged.txt"

    # 备份文件
    INVALID_DOMAINS_BACKUP = BASE_DIR / "data" / "filter" / "adblock_update.txt"
    BACKUP_HISTORY_DIR = BASE_DIR / "data" / "filter" / "backups"
    WHITELIST_FILE = BASE_DIR / "data" / "domains.txt"

    # GitHub Actions 环境配置
    MAX_WORKERS = 4
    DNS_WORKERS = 100
    BATCH_SIZE = 500
    MAX_MEMORY_PERCENT = 70

    # DNS解析设置
    DNS_TIMEOUT = 3
    DNS_RETRIES = 2
    DNS_RETRY_DELAY = 1

    # 多协议DNS服务器配置（含SmartDNS）
    DNS_SERVERS = {
        'global': {
            'doh': [
                "https://1.1.1.1/dns-query",
                "https://dns.google/dns-query",
                "https://doh.opendns.com/dns-query",
            ],
            'dot': [
                "1.1.1.1",
                "8.8.8.8",
                "9.9.9.9",
            ],
            'smartdns': [
                "127.0.0.1:5353",
                "208.67.222.222:5353"
            ]
        },
        'china': {
            'doh': [
                "https://doh.360.cn/dns-query",
                "https://dns.alidns.com/dns-query",
                "https://doh.pub/dns-query",
            ],
            'dot': [
                "223.5.5.5",
                "119.29.29.29",
                "180.76.76.76",
            ],
            'smartdns': [
                "127.0.0.1:5353",
                "119.29.29.29:5353"
            ]
        }
    }

    # 中国IP范围文件
    CHINA_IP_RANGES_FILE = BASE_DIR / "data" / "filter" / "china_ip_ranges.txt"
    GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    GEOIP_DB_FILE = BASE_DIR / "data" / "filter" / "GeoLite2-Country.mmdb"

    # 性能优化设置
    CACHE_TTL = 3600
    MAX_CACHE_SIZE = 20000
    INVALID_DOMAIN_EXPIRY_DAYS = 30  # 无效域名过期时间

    # 特殊规则保留
    PRESERVE_ELEMENT_HIDING = True
    PRESERVE_SCRIPT_RULES = True
    PRESERVE_REGEX_RULES = True
    PRESERVE_ADGUARD_RULES = True  # AdGuard规则保留


class RegexPatterns:
    """Adblock与AdGuard语法模式"""
    # 基础模式
    DOMAIN_EXTRACT = re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]')
    HOSTS_RULE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    ADBLOCK_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_-]+')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    # 标准Adblock模式
    ELEMENT_HIDING = re.compile(r'.*##.*')
    SCRIPTLET = re.compile(r'.*#\?#.*')
    GENERIC = re.compile(r'^/.*/$')
    
    # AdGuard特有语法模式 - 新增
    ADGUARD_SCRIPT = re.compile(r'.*\$.*script.*')
    ADGUARD_HEADER = re.compile(r'^\s*!\s*AdGuard\s+Filter\s*$', re.IGNORECASE)
    ADGUARD_EXTENDED_OPTIONS = re.compile(r'\$~?[\w-]+(?:=[^,]+)?(?:,~?[\w-]+(?:=[^,]+)?)*$')
    ADGUARD_DOMAIN = re.compile(r'^@@?\|?https?://[^/]+')
    ADGUARD_CSP = re.compile(r'.*\$csp=')
    ADGUARD_REDIRECT = re.compile(r'.*\$redirect=')
    ADGUARD_STUB = re.compile(r'.*\$stub=')
    ADGUARD_WEB_REQUEST = re.compile(r'.*\$webrequest=')
    ADGUARD_POPUP = re.compile(r'.*\$popup')
    ADGUARD_POPUNDER = re.compile(r'.*\$popunder')
    ADGUARD_CLOAKING = re.compile(r'.*\$cloaking')
    ADGUARD_CSS = re.compile(r'.*#\$#.*')  # AdGuard CSS规则
    ADGUARD_JS = re.compile(r'.*#@#.*')   # AdGuard JS规则
    ADGUARD_MEDIA = re.compile(r'.*\$media=')


def setup_logger():
    logger = logging.getLogger('AdblockCleanerCI')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


class GeoIPClassifier:
    """IP地理信息分类器"""
    def __init__(self):
        self.geoip_reader = None
        self.china_ip_ranges = set()
        self._init_geoip()
        self._load_china_ip_ranges()

    def _init_geoip(self):
        """初始化GeoIP数据库"""
        try:
            if Config.GEOIP_DB_FILE.exists():
                self.geoip_reader = maxminddb.open_database(str(Config.GEOIP_DB_FILE))
                logger.info("GeoIP数据库加载成功")
            else:
                logger.warning("GeoIP数据库未找到，将使用IP范围文件")
        except Exception as e:
            logger.error(f"加载GeoIP数据库失败: {str(e)}")

    def _load_china_ip_ranges(self):
        """加载中国IP范围"""
        try:
            if Config.CHINA_IP_RANGES_FILE.exists():
                with open(Config.CHINA_IP_RANGES_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.china_ip_ranges.add(line)
                logger.info(f"已加载 {len(self.china_ip_ranges)} 个中国IP范围")
            else:
                # 默认添加一些常见中国IP段
                self.china_ip_ranges.update([
                    '1.0.1.0/24', '1.0.2.0/23', '1.0.8.0/21', '1.0.32.0/19', '1.1.0.0/24',
                    '223.0.0.0/8', '220.160.0.0/11', '219.128.0.0/11', '218.0.0.0/11'
                ])
                logger.info("使用默认中国IP范围")
        except Exception as e:
            logger.error(f"加载中国IP范围失败: {str(e)}")

    def is_china_ip(self, ip_address: str) -> bool:
        """判断IP是否属于中国"""
        try:
            # 首先检查GeoIP数据库
            if self.geoip_reader:
                try:
                    result = self.geoip_reader.get(ip_address)
                    if result and 'country' in result:
                        return result['country']['iso_code'] == 'CN'
                except:
                    pass

            # 然后检查IP范围
            ip_obj = ipaddress.ip_address(ip_address)
            for ip_range in self.china_ip_ranges:
                if ip_obj in ipaddress.ip_network(ip_range):
                    return True

            return False
        except Exception:
            return False

    def close(self):
        """关闭GeoIP读取器"""
        if self.geoip_reader:
            self.geoip_reader.close()


class ResourceMonitor:
    """资源监控器"""
    def __init__(self):
        self.start_time = time.time()
        self.peak_memory = 0

    def check_memory_usage(self):
        """检查内存使用情况"""
        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024
        self.peak_memory = max(self.peak_memory, memory_mb)

        total_memory = psutil.virtual_memory().total / 1024 / 1024
        memory_percent = (memory_mb / total_memory) * 100

        if memory_percent > Config.MAX_MEMORY_PERCENT:
            logger.warning(f"内存使用率过高: {memory_percent:.1f}% ({memory_mb:.1f}MB)")
            return False
        return True

    def log_resource_usage(self):
        """记录资源使用情况"""
        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024
        cpu_percent = process.cpu_percent()
        elapsed = time.time() - self.start_time
        logger.info(f"资源使用 - 内存: {memory_mb:.1f}MB, CPU: {cpu_percent}%, 时间: {elapsed:.1f}s")


class AdaptiveDNSValidator:
    """自适应DNS验证器（支持国内外域名分流）"""
    def __init__(self):
        self.domain_blacklist = {
            'localhost', 'localdomain', 'example.com', 'example.org', 
            'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
            '::1', '255.255.255.255', 'localhost.localdomain',
            'example', 'test', 'invalid', 'local'
        }

        self.valid_domains = set()
        self.invalid_domains = {}  # 改为字典存储过期时间: {domain: timestamp}
        self.cache_timestamps = {}
        self.domain_strategies = {}  # 域名->策略映射缓存
        self.geoip_classifier = GeoIPClassifier()

        self.known_invalid_domains = self._load_known_invalid_domains()
        self.whitelist_domains = self._load_whitelist_domains()
        self._preload_whitelist_to_cache()

        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.resolver = aiodns.DNSResolver()
        self.resolver.timeout = Config.DNS_TIMEOUT

        self.session = None
        self.connector = None

        # 性能统计
        self.stats = {
            'doh_queries': 0,
            'dot_queries': 0,
            'smartdns_queries': 0,
            'dns_queries': 0,
            'cache_hits': 0,
            'known_invalid_hits': 0,
            'whitelist_hits': 0,
            'china_domains': 0,
            'global_domains': 0,
            'expired_invalid_domains': 0  # 新增过期无效域名统计
        }

    def _load_known_invalid_domains(self) -> Dict[str, float]:
        """从备份文件加载已知无效域名（带时间戳）"""
        known_invalid = {}
        backup_file = Config.INVALID_DOMAINS_BACKUP
        if backup_file.exists():
            try:
                with open(backup_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # 格式: domain[ timestamp]
                            parts = line.split()
                            domain = parts[0]
                            timestamp = float(parts[1]) if len(parts) > 1 else time.time()
                            known_invalid[domain] = timestamp
                logger.info(f"已加载 {len(known_invalid)} 个已知无效域名")
            except Exception as e:
                logger.error(f"加载已知无效域名失败: {str(e)}")
        return known_invalid

    def _load_whitelist_domains(self) -> Set[str]:
        """从白名单文件加载白名单域名"""
        whitelist = set()
        whitelist_file = Config.WHITELIST_FILE
        if whitelist_file.exists():
            try:
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('*.'):
                                line = line[2:]
                            whitelist.add(line)
                logger.info(f"已加载 {len(whitelist)} 个白名单域名")
            except Exception as e:
                logger.error(f"加载白名单域名失败: {str(e)}")
        else:
            logger.info(f"白名单文件不存在: {whitelist_file}")
        return whitelist

    def _preload_whitelist_to_cache(self):
        """预加载白名单域名到有效域名缓存"""
        current_time = time.time()
        for domain in self.whitelist_domains:
            self.valid_domains.add(domain)
            self.cache_timestamps[domain] = current_time
        logger.info(f"已将 {len(self.whitelist_domains)} 个白名单域名预加载到缓存")

    def _clean_expired_invalid_domains(self):
        """清理过期的无效域名记录"""
        current_time = time.time()
        expiry_seconds = Config.INVALID_DOMAIN_EXPIRY_DAYS * 86400
        expired = []
        
        for domain, timestamp in self.known_invalid_domains.items():
            if current_time - timestamp > expiry_seconds:
                expired.append(domain)
                
        for domain in expired:
            del self.known_invalid_domains[domain]
            self.stats['expired_invalid_domains'] += 1
            
        if expired:
            logger.info(f"已清理 {len(expired)} 个过期的无效域名记录")

    async def determine_domain_strategy(self, domain: str) -> str:
        """确定域名的解析策略（国内/国际）"""
        # 首先检查缓存
        if domain in self.domain_strategies:
            return self.domain_strategies[domain]

        # 常见中国域名后缀
        china_tlds = {'.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.edu.cn'}
        # 常见中国域名关键字
        china_keywords = {'baidu', 'tencent', 'qq', 'alibaba', 'taobao', 'jd', 'weibo',
                         'xiaomi', 'huawei', 'oppo', 'vivo', 'sina', 'sohu', '163', '126'}

        # 检查域名后缀
        if any(domain.endswith(tld) for tld in china_tlds):
            self.domain_strategies[domain] = 'china'
            return 'china'

        # 检查域名关键字
        if any(keyword in domain for keyword in china_keywords):
            self.domain_strategies[domain] = 'china'
            return 'china'

        # 通过DNS解析获取IP并检查地理位置
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=2.0
            )
            if result:
                ip_address = result[0].host
                if self.geoip_classifier.is_china_ip(ip_address):
                    self.domain_strategies[domain] = 'china'
                    return 'china'
        except:
            pass

        # 默认使用国际策略
        self.domain_strategies[domain] = 'global'
        return 'global'

    async def init_session(self):
        """初始化aiohttp会话"""
        if self.session is None:
            self.connector = aiohttp.TCPConnector(
                limit=min(Config.DNS_WORKERS, 50),
                limit_per_host=8,
                ttl_dns_cache=300,
                ssl=self.ssl_context
            )
            self.session = aiohttp.ClientSession(connector=self.connector)
            
        # 初始化时清理过期无效域名
        self._clean_expired_invalid_domains()

    async def close_session(self):
        """关闭aiohttp会话"""
        if self.session:
            await self.session.close()
            self.session = None
        if self.connector:
            await self.connector.close()
            self.connector = None
        self.geoip_classifier.close()

    def is_valid_domain_format(self, domain: str) -> bool:
        """检查域名格式是否有效"""
        if not domain or domain in self.domain_blacklist:
            return False
        if len(domain) < 4 or len(domain) > 253:
            return False
        if '.' not in domain:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            return False
        if RegexPatterns.IP_ADDRESS.match(domain):
            return False
        parts = domain.split('.')
        for part in parts:
            if len(part) > 63:
                return False
        return True

    async def resolve_with_retry(self, func, *args, max_retries=Config.DNS_RETRIES, **kwargs):
        """带重试的DNS解析"""
        for attempt in range(max_retries):
            try:
                return await func(*args, **kwargs)
            except (asyncio.TimeoutError, aiodns.error.DNSError, aiohttp.ClientError) as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(Config.DNS_RETRY_DELAY * (attempt + 1))
                else:
                    return False
            except Exception:
                return False
        return False

    async def resolve_via_doh(self, domain: str, server: str) -> bool:
        """通过DoH协议解析域名"""
        self.stats['doh_queries'] += 1
        try:
            headers = {'accept': 'application/dns-json'}
            params = {'name': domain, 'type': 'A'}
            timeout = aiohttp.ClientTimeout(total=Config.DNS_TIMEOUT)
            async with self.session.get(server, headers=headers, params=params, 
                                      ssl=self.ssl_context, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    return 'Answer' in data and len(data['Answer']) > 0
        except:
            return False

    async def resolve_via_dot(self, domain: str, server: str) -> bool:
        """通过DoT协议解析域名"""
        self.stats['dot_queries'] += 1
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return len(result) > 0
        except:
            return False

    async def resolve_via_smartdns(self, domain: str, server: str) -> bool:
        """通过SmartDNS解析域名"""
        self.stats['smartdns_queries'] += 1
        try:
            # 解析SmartDNS服务器地址和端口
            if ':' in server:
                host, port = server.split(':', 1)
                port = int(port)
            else:
                host = server
                port = 5353  # 默认SmartDNS端口

            # 创建专用的SmartDNS解析器
            smart_resolver = aiodns.DNSResolver()
            smart_resolver.nameservers = [host]
            smart_resolver.port = port
            smart_resolver.timeout = Config.DNS_TIMEOUT

            result = await asyncio.wait_for(
                smart_resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return len(result) > 0
        except:
            return False

    async def resolve_via_standard_dns(self, domain: str) -> bool:
        """通过标准DNS协议解析域名"""
        self.stats['dns_queries'] += 1
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return len(result) > 0
        except:
            return False

    async def resolve_domain(self, domain: str, strategy: str) -> bool:
        """根据策略解析域名"""
        # 1. 首先尝试标准DNS
        result = await self.resolve_with_retry(self.resolve_via_standard_dns, domain)
        if result:
            return True

        # 2. 尝试SmartDNS
        smartdns_servers = Config.DNS_SERVERS[strategy]['smartdns']
        for smartdns_server in smartdns_servers:
            result = await self.resolve_with_retry(self.resolve_via_smartdns, domain, smartdns_server)
            if result:
                return True
            await asyncio.sleep(0.01)

        # 3. 尝试DoH协议
        doh_servers = Config.DNS_SERVERS[strategy]['doh']
        for doh_server in doh_servers:
            result = await self.resolve_with_retry(self.resolve_via_doh, domain, doh_server)
            if result:
                return True
            await asyncio.sleep(0.01)

        # 4. 最后尝试DoT协议
        dot_servers = Config.DNS_SERVERS[strategy]['dot']
        for dot_server in dot_servers:
            result = await self.resolve_with_retry(self.resolve_via_dot, domain, dot_server)
            if result:
                return True
            await asyncio.sleep(0.01)

        return False

    async def is_domain_resolvable(self, domain: str) -> bool:
        """检查域名是否可解析"""
        current_time = time.time()

        # 检查白名单
        if domain in self.whitelist_domains:
            self.stats['whitelist_hits'] += 1
            return True

        # 检查已知无效域名
        if domain in self.known_invalid_domains:
            self.stats['known_invalid_hits'] += 1
            return False

        # 检查缓存
        if domain in self.cache_timestamps:
            if current_time - self.cache_timestamps[domain] < Config.CACHE_TTL:
                if domain in self.valid_domains:
                    self.stats['cache_hits'] += 1
                    return True
                elif domain in self.invalid_domains:
                    self.stats['cache_hits'] += 1
                    return False

        if domain in self.invalid_domains:
            return False

        if domain in self.valid_domains:
            return True

        # 确定解析策略
        strategy = await self.determine_domain_strategy(domain)
        if strategy == 'china':
            self.stats['china_domains'] += 1
        else:
            self.stats['global_domains'] += 1

        # 解析域名
        result = await self.resolve_domain(domain, strategy)

        if result:
            self.valid_domains.add(domain)
            self.cache_timestamps[domain] = current_time
            if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
                self._cleanup_cache()
            return True
        else:
            self.invalid_domains[domain] = current_time  # 存储时间戳
            self.cache_timestamps[domain] = current_time
            return False

    def _cleanup_cache(self):
        """清理过期的缓存条目"""
        current_time = time.time()
        expired_domains = [
            domain for domain, timestamp in self.cache_timestamps.items()
            if current_time - timestamp > Config.CACHE_TTL
        ]

        for domain in expired_domains:
            if domain in self.valid_domains:
                self.valid_domains.remove(domain)
            if domain in self.invalid_domains:
                del self.invalid_domains[domain]
            if domain in self.cache_timestamps:
                del self.cache_timestamps[domain]

        if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
            sorted_domains = sorted(self.cache_timestamps.items(), key=lambda x: x[1])
            for domain, _ in sorted_domains[:Config.MAX_CACHE_SIZE // 2]:
                if domain in self.valid_domains:
                    self.valid_domains.remove(domain)
                if domain in self.invalid_domains:
                    del self.invalid_domains[domain]
                if domain in self.cache_timestamps:
                    del self.cache_timestamps[domain]

    async def validate_domain(self, domain: str) -> bool:
        """验证域名"""
        if not self.is_valid_domain_format(domain):
            return False
        return await self.is_domain_resolvable(domain)


class AdblockCleanerCI:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

        self.regex = RegexPatterns()
        self.validator = AdaptiveDNSValidator()
        self.resource_monitor = ResourceMonitor()
        
        # 用于规则去重的存储
        self.unique_rules = set()
        self.domain_to_rules = {}  # 域名到规则的映射，用于合并

    async def run(self):
        start_time = time.time()
        logger.info("===== Adblock规则清理工具（支持AdGuard语法） =====")
        logger.info("GitHub CI环境: 2核7GB标准配置 / 4核16GB大型配置")
        logger.info(f"并发设置: DNS Workers={Config.DNS_WORKERS}, CPU Workers={Config.MAX_WORKERS}")
        logger.info(f"内存限制: {Config.MAX_MEMORY_PERCENT}%")
        logger.info(f"自适应DNS: 支持国内外域名分流解析（含SmartDNS）")

        await self.validator.init_session()

        input_files = []
        for pattern in ["adblock_filter.txt"]:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])

        if not input_files:
            logger.error("未找到输入文件，退出")
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        for file_path in input_files:
            await self._process_file(file_path)

        # 合并去重后保存最终结果
        self._save_merged_unique_rules()
        
        await self.validator.close_session()
        self._backup_invalid_domains()

        elapsed = time.time() - start_time
        logger.info(f"\n===== 清理完成 =====")
        logger.info(f"总耗时: {elapsed:.2f}秒")
        logger.info(f"峰值内存: {self.resource_monitor.peak_memory:.1f}MB")
        logger.info(f"有效域名: {len(self.validator.valid_domains)}")
        logger.info(f"无效域名: {len(self.validator.invalid_domains)}")
        logger.info(f"过期无效域名: {self.validator.stats['expired_invalid_domains']}")
        logger.info(f"国内域名: {self.validator.stats['china_domains']}")
        logger.info(f"国际域名: {self.validator.stats['global_domains']}")
        logger.info(f"白名单命中: {self.validator.stats['whitelist_hits']}")
        logger.info(f"缓存命中: {self.validator.stats['cache_hits']}")
        logger.info(f"DNS查询统计: 标准{self.validator.stats['dns_queries']} | "
                   f"SmartDNS{self.validator.stats['smartdns_queries']} | "
                   f"DoH{self.validator.stats['doh_queries']} | "
                   f"DoT{self.validator.stats['dot_queries']}")
        logger.info(f"规则处理: 原始{len(self.unique_rules)}条，去重后{len(self.unique_rules)}条")

        self._save_stats(start_time, elapsed)

    async def _process_file(self, file_path: Path):
        """处理单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"读取文件{file_path.name}出错: {str(e)}")
            return

        all_domains = self._extract_domains_from_lines(lines)
        logger.info(f"从文件中提取到 {len(all_domains)} 个域名")

        # 先收集所有规则，建立域名与规则的映射关系
        self._build_domain_to_rules_mapping(lines)

        valid_domains = set()
        domain_list = list(all_domains)

        for i in range(0, len(domain_list), Config.BATCH_SIZE):
            batch = domain_list[i:i+Config.BATCH_SIZE]
            batch_num = i//Config.BATCH_SIZE + 1
            total_batches = (len(domain_list)-1)//Config.BATCH_SIZE + 1
            
            logger.info(f"处理域名批次 {batch_num}/{total_batches} ({len(batch)} 个域名)")
            batch_valid_domains = await self._validate_domains_batch(batch)
            valid_domains.update(batch_valid_domains)

            if not self.resource_monitor.check_memory_usage():
                logger.warning("内存使用超过限制，暂停处理")
                await asyncio.sleep(1)

            self.resource_monitor.log_resource_usage()

        logger.info(f"有效域名: {len(valid_domains)} 个，无效域名: {len(all_domains) - len(valid_domains)} 个")

        # 过滤并合并规则
        self._filter_and_merge_rules(valid_domains)

    def _build_domain_to_rules_mapping(self, lines: List[str]):
        """建立域名到规则的映射，用于后续合并去重"""
        for line in lines:
            original_line = line.rstrip('\n')
            line = line.strip()
            
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
                self.unique_rules.add(original_line)
                continue
                
            domain = self._extract_domain_from_rule(line)
            if domain:
                if domain not in self.domain_to_rules:
                    self.domain_to_rules[domain] = set()
                self.domain_to_rules[domain].add(original_line)
            else:
                # 没有明确域名的规则（如通配符规则）直接添加
                self.unique_rules.add(original_line)

    def _extract_domains_from_lines(self, lines: List[str]) -> Set[str]:
        """从所有行中提取域名"""
        domains = set()
        for line in lines:
            line = line.strip()
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
                continue
            domain = self._extract_domain_from_rule(line)
            if domain:
                domains.add(domain)
        return domains

    def _extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从单条规则中提取域名（支持AdGuard规则）"""
        # 优先检查AdGuard特定规则中的域名
        adguard_match = self.regex.ADGUARD_DOMAIN.match(rule)
        if adguard_match:
            domain = adguard_match.group(0).lstrip('@|').lstrip('https://').lstrip('http://')
            return domain.split('/')[0]

        domain_match = self.regex.DOMAIN_EXTRACT.match(rule)
        if domain_match:
            domain = domain_match.group(1)
            if '$' in domain:
                domain = domain.split('$')[0]
            return domain

        hosts_match = self.regex.HOSTS_RULE.match(rule)
        if hosts_match:
            return hosts_match.group(1)

        if rule.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(rule)
                if parsed.netloc:
                    return parsed.netloc.split(':')[0]
            except:
                pass

        return None

    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名有效性"""
        valid_domains = set()
        tasks = [self.validator.validate_domain(domain) for domain in domains]

        batch_size = Config.DNS_WORKERS
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)

            for j, result in enumerate(results):
                domain = domains[i+j]
                if isinstance(result, Exception):
                    continue
                elif result:
                    valid_domains.add(domain)

        return valid_domains

    def _filter_and_merge_rules(self, valid_domains: Set[str]):
        """过滤并合并规则（合并去重）"""
        # 处理有效域名的规则
        for domain in valid_domains:
            if domain in self.domain_to_rules:
                # 对同一域名的规则进行合并优化
                optimized_rules = self._optimize_rules_for_domain(domain, self.domain_to_rules[domain])
                self.unique_rules.update(optimized_rules)
        
        # 处理无效域名的规则 - 仅保留最新的一条规则
        invalid_domains = set(self.domain_to_rules.keys()) - valid_domains
        for domain in invalid_domains:
            if domain in self.domain_to_rules and len(self.domain_to_rules[domain]) > 0:
                # 取最后一条规则作为保留项（可根据需要修改策略）
                rules = sorted(self.domain_to_rules[domain], key=lambda x: len(x), reverse=True)
                self.unique_rules.add(rules[0])  # 取最长的规则作为最精确的规则

    def _optimize_rules_for_domain(self, domain: str, rules: Set[str]) -> Set[str]:
        """优化特定域名的规则集合，合并重复或可替代的规则"""
        if not rules:
            return set()
            
        # 对于AdGuard规则的特殊优化
        adguard_rules = [r for r in rules if self._is_adguard_rule(r)]
        standard_rules = [r for r in rules if not self._is_adguard_rule(r)]
        
        optimized = set()
        
        # 处理AdGuard规则
        if adguard_rules:
            # 按规则类型分组
            element_hiding = [r for r in adguard_rules if self.regex.ELEMENT_HIDING.match(r)]
            scriptlets = [r for r in adguard_rules if self.regex.SCRIPTLET.match(r)]
            css_rules = [r for r in adguard_rules if self.regex.ADGUARD_CSS.match(r)]
            js_rules = [r for r in adguard_rules if self.regex.ADGUARD_JS.match(r)]
            other_adguard = [r for r in adguard_rules if not any([
                self.regex.ELEMENT_HIDING.match(r),
                self.regex.SCRIPTLET.match(r),
                self.regex.ADGUARD_CSS.match(r),
                self.regex.ADGUARD_JS.match(r)
            ])]
            
            # 每组保留最具体的规则
            if element_hiding:
                optimized.add(self._get_most_specific_rule(element_hiding))
            if scriptlets:
                optimized.add(self._get_most_specific_rule(scriptlets))
            if css_rules:
                optimized.add(self._get_most_specific_rule(css_rules))
            if js_rules:
                optimized.add(self._get_most_specific_rule(js_rules))
            optimized.update(other_adguard)
        
        # 处理标准规则
        if standard_rules:
            optimized.add(self._get_most_specific_rule(standard_rules))
            
        return optimized

    def _is_adguard_rule(self, rule: str) -> bool:
        """判断是否为AdGuard特有规则"""
        return any([
            self.regex.ADGUARD_HEADER.match(rule),
            self.regex.ADGUARD_EXTENDED_OPTIONS.match(rule),
            self.regex.ADGUARD_CSP.match(rule),
            self.regex.ADGUARD_REDIRECT.match(rule),
            self.regex.ADGUARD_STUB.match(rule),
            self.regex.ADGUARD_WEB_REQUEST.match(rule),
            self.regex.ADGUARD_POPUP.match(rule),
            self.regex.ADGUARD_POPUNDER.match(rule),
            self.regex.ADGUARD_CLOAKING.match(rule),
            self.regex.ADGUARD_CSS.match(rule),
            self.regex.ADGUARD_JS.match(rule),
            self.regex.ADGUARD_MEDIA.match(rule)
        ])

    def _get_most_specific_rule(self, rules: List[str]) -> str:
        """从规则列表中选择最具体的规则（通常是最长的）"""
        # 按长度排序，最长的通常最具体
        return max(rules, key=lambda x: len(x))

    def _save_merged_unique_rules(self):
        """保存合并去重后的规则"""
        output_path = Config.CLEANED_FILE
        
        # 按规则类型排序输出
        comments = []
        adguard_rules = []
        element_hiding = []
        script_rules = []
        other_rules = []
        
        for rule in self.unique_rules:
            if self.regex.COMMENT.match(rule):
                comments.append(rule)
            elif self._is_adguard_rule(rule):
                adguard_rules.append(rule)
            elif self.regex.ELEMENT_HIDING.match(rule):
                element_hiding.append(rule)
            elif self.regex.SCRIPTLET.match(rule) or self.regex.ADGUARD_SCRIPT.match(rule):
                script_rules.append(rule)
            else:
                other_rules.append(rule)
        
        # 组合所有规则
        all_rules = []
        all_rules.extend(comments)
        all_rules.extend(adguard_rules)
        all_rules.extend(element_hiding)
        all_rules.extend(script_rules)
        all_rules.extend(other_rules)
        
        # 添加换行符
        all_rules = [f"{rule}\n" for rule in all_rules]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(all_rules)

        logger.info(f"已写入合并去重后的规则到 {output_path}，保留 {len(all_rules)} 条规则")

    def _backup_invalid_domains(self):
        """备份无效域名到文件（带时间戳）"""
        # 合并已知无效域名和新发现的无效域名
        all_invalid_domains = {**self.validator.known_invalid_domains,** self.validator.invalid_domains}
        
        if not all_invalid_domains:
            logger.info("没有无效域名需要备份")
            return

        Config.INVALID_DOMAINS_BACKUP.parent.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = Config.BACKUP_HISTORY_DIR / f"adblock_update_{timestamp}.txt"
        compressed_backup = Config.BACKUP_HISTORY_DIR / f"adblock_update_{timestamp}.txt.gz"

        try:
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write("# Adblock无效域名备份文件（带时间戳）\n")
                f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
                f.write(f"# 总数: {len(all_invalid_domains)}\n")
                f.write(f"# 格式: 域名 时间戳（秒）\n\n")
                for domain, ts in sorted(all_invalid_domains.items()):
                    f.write(f"{domain} {ts:.0f}\n")

            with open(backup_file, 'rb') as f_in:
                with gzip.open(compressed_backup, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            shutil.copy2(backup_file, Config.INVALID_DOMAINS_BACKUP)
            self._cleanup_old_backups()

            logger.info(f"已备份 {len(all_invalid_domains)} 个无效域名")
        except Exception as e:
            logger.error(f"备份无效域名失败: {str(e)}")

    def _cleanup_old_backups(self):
        """清理旧的备份文件"""
        try:
            backup_files = sorted(
                Config.BACKUP_HISTORY_DIR.glob("adblock_update_*.txt"),
                key=os.path.getmtime,
                reverse=True
            )
            if len(backup_files) > 10:
                for old_file in backup_files[10:]:
                    old_file.unlink()
                    compressed_file = Config.BACKUP_HISTORY_DIR / f"{old_file.stem}.gz"
                    if compressed_file.exists():
                        compressed_file.unlink()
        except Exception as e:
            logger.error(f"清理旧备份失败: {str(e)}")

    def _save_stats(self, start_time: float, elapsed: float):
        """保存统计信息"""
        stats = {
            "timestamp": datetime.now().isoformat(),
            "processing_time_seconds": elapsed,
            "peak_memory_mb": self.resource_monitor.peak_memory,
            "valid_domains": len(self.validator.valid_domains),
            "invalid_domains": len(self.validator.invalid_domains),
            "expired_invalid_domains": self.validator.stats['expired_invalid_domains'],
            "china_domains": self.validator.stats['china_domains'],
            "global_domains": self.validator.stats['global_domains'],
            "dns_query_stats": self.validator.stats,
            "rule_stats": {
                "original_rules": len(self.unique_rules),
                "final_rules": len(self.unique_rules),
                "adguard_rules": sum(1 for r in self.unique_rules if self._is_adguard_rule(r))
            },
            "ci_environment": "GitHub Actions",
            "concurrency_settings": {
                "dns_workers": Config.DNS_WORKERS,
                "cpu_workers": Config.MAX_WORKERS,
                "batch_size": Config.BATCH_SIZE
            }
        }

        stats_file = Config.TEMP_DIR / "cleaning_stats.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        logger.info(f"统计信息已保存到 {stats_file}")


async def main():
    try:
        cleaner = AdblockCleanerCI()
        await cleaner.run()
    except Exception as e:
        logger.critical(f"工具运行失败: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
