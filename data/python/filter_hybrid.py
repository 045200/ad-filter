#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adblock规则清理工具 - 带白名单功能的GitHub CI优化版"""

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
import tldextract
import json
from datetime import datetime
import resource
import psutil
import hashlib
import gzip
import shutil


class Config:
    """配置：GitHub CI 环境优化配置"""
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    
    # 输入：仓库根目录下的临时目录
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    # 输出：清理后的文件将覆盖原文件
    OUTPUT_DIR = TEMP_DIR
    
    # 核心输出文件
    CLEANED_FILE = TEMP_DIR / "adblock_merged.txt"
    
    # 无效域名备份文件
    INVALID_DOMAINS_BACKUP = BASE_DIR / "data" / "mod" / "adblock_update.txt"
    BACKUP_HISTORY_DIR = BASE_DIR / "data" / "mod" / "backups"
    
    # 白名单文件
    WHITELIST_FILE = BASE_DIR / "data" / "mod" / "domains.txt"
    
    MAX_BACKUP_FILES = 10  # 最大备份文件数量
    
    # GitHub CI 环境优化配置
    MAX_WORKERS = 4  # 匹配 CPU 核心数
    DNS_WORKERS = 100  # DNS查询的并发数（提高IO密集型任务并发）
    RULE_LEN_RANGE = (3, 2048)
    MAX_FILESIZE_MB = 100  # 增加文件大小限制
    INPUT_PATTERNS = ["adblock_filter.txt"]
    
    # DNS解析设置
    DNS_TIMEOUT = 3  # 稍微增加超时时间
    DNS_RETRIES = 2  # 增加重试次数
    DNS_RETRY_DELAY = 1  # 重试延迟(秒)
    
    # 内存管理
    MAX_MEMORY_PERCENT = 70  # 最大内存使用百分比
    BATCH_SIZE = 5000  # 域名批量处理大小
    
    # 多协议DNS服务器配置（优化服务器选择）
    DOH_SERVERS = [
        "https://1.1.1.1/dns-query",  # Cloudflare (全球CDN)
        "https://dns.google/dns-query",  # Google (全球CDN)
        "https://dns.alidns.com/dns-query",  # AliDNS (亚洲优化)
        "https://doh.opendns.com/dns-query",  # OpenDNS (北美优化)
        "https://doh.dns.sb/dns-query",  # DNS.SB (备用)
        "https://doh.li/dns-query",  # DNS.LI (备用)
        "https://dns.adguard.com/dns-query",  # AdGuard (备用)
        "https://dns.cloudflare.com/dns-query",  # Cloudflare备用
    ]
    
    DOT_SERVERS = [
        "1.1.1.1",  # Cloudflare
        "8.8.8.8",  # Google
        "9.9.9.9",  # Quad9
        "208.67.222.222",  # OpenDNS
    ]
    
    # 特殊规则保留设置
    PRESERVE_ELEMENT_HIDING = True
    PRESERVE_SCRIPT_RULES = True
    PRESERVE_REGEX_RULES = True
    
    # 性能优化设置
    CACHE_TTL = 3600  # 缓存有效期(秒)
    MAX_CACHE_SIZE = 10000  # 最大缓存条目数


class RegexPatterns:
    """Adblock语法模式"""
    # 域名提取模式
    DOMAIN_EXTRACT = re.compile(r'^(?:@@\|\|)?([\w.-]+)(?:\^|\$|/|$)')
    HOSTS_RULE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')
    
    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    # 特殊规则类型（通常需要保留）
    ELEMENT_HIDING = re.compile(r'.*##.*')
    SCRIPTLET = re.compile(r'.*#\?#.*')
    GENERIC = re.compile(r'^/.*/$')  # 正则表达式规则
    ADGUARD_SCRIPT = re.compile(r'.*\$.*script.*')


def setup_logger():
    logger = logging.getLogger('AdblockCleanerCI')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


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
        
        # 获取系统总内存
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


class MultiProtocolDNSValidator:
    """多协议DNS验证器（GitHub CI 优化版）"""
    def __init__(self):
        # 域名黑名单（无效或保留域名）
        self.domain_blacklist = {
            'localhost', 'localdomain', 'example.com', 'example.org', 
            'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
            '::1', '255.255.255.255', 'localhost.localdomain',
            'example', 'test', 'invalid', 'local'
        }
        
        # 缓存已验证的域名
        self.valid_domains = set()
        self.invalid_domains = set()
        self.cache_timestamps = {}  # 缓存时间戳
        
        # 从备份文件加载已知无效域名
        self.known_invalid_domains = self._load_known_invalid_domains()
        
        # 从白名单文件加载白名单域名
        self.whitelist_domains = self._load_whitelist_domains()
        
        # 创建SSL上下文
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # 初始化DNS解析器
        self.resolver = aiodns.DNSResolver()
        self.resolver.timeout = Config.DNS_TIMEOUT
        
        # 会话管理
        self.session = None
        self.connector = None
        
        # 性能统计
        self.stats = {
            'doh_queries': 0,
            'dot_queries': 0,
            'dns_queries': 0,
            'cache_hits': 0,
            'known_invalid_hits': 0,
            'whitelist_hits': 0
        }

    def _load_known_invalid_domains(self) -> Set[str]:
        """从备份文件加载已知无效域名"""
        known_invalid = set()
        backup_file = Config.INVALID_DOMAINS_BACKUP
        
        if backup_file.exists():
            try:
                logger.info(f"从备份文件加载已知无效域名: {backup_file}")
                with open(backup_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            known_invalid.add(domain)
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
                logger.info(f"从白名单文件加载域名: {whitelist_file}")
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # 跳过注释和空行
                        if line and not line.startswith('#'):
                            # 处理通配符域名 (*.example.com → example.com)
                            if line.startswith('*.'):
                                line = line[2:]
                            whitelist.add(line)
                logger.info(f"已加载 {len(whitelist)} 个白名单域名")
            except Exception as e:
                logger.error(f"加载白名单域名失败: {str(e)}")
        else:
            logger.info(f"白名单文件不存在: {whitelist_file}")
        
        return whitelist

    async def init_session(self):
        """初始化aiohttp会话（GitHub CI 优化）"""
        if self.session is None:
            # 使用连接池限制，避免过多连接
            self.connector = aiohttp.TCPConnector(
                limit=Config.DNS_WORKERS,
                limit_per_host=10,
                ttl_dns_cache=300,  # DNS缓存5分钟
                ssl=self.ssl_context
            )
            self.session = aiohttp.ClientSession(connector=self.connector)
    
    async def close_session(self):
        """关闭aiohttp会话"""
        if self.session:
            await self.session.close()
            self.session = None
        if self.connector:
            await self.connector.close()
            self.connector = None

    def is_valid_domain_format(self, domain: str) -> bool:
        """检查域名格式是否有效（优化性能）"""
        if not domain or domain in self.domain_blacklist:
            return False
            
        # 检查是否是IP地址
        if RegexPatterns.IP_ADDRESS.match(domain):
            return False
            
        # 基本长度检查
        if len(domain) < 4 or len(domain) > 253:
            return False
            
        # 快速检查域名格式（避免使用tldextract以提高性能）
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False
            
        # 检查域名格式
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False
            
        return True

    async def resolve_with_retry(self, func, *args, max_retries=Config.DNS_RETRIES, **kwargs):
        """带重试的DNS解析"""
        for attempt in range(max_retries):
            try:
                return await func(*args, **kwargs)
            except (asyncio.TimeoutError, aiodns.error.DNSError, aiohttp.ClientError) as e:
                if attempt < max_retries - 1:
                    logger.debug(f"尝试 {attempt+1}/{max_retries} 失败: {str(e)}")
                    await asyncio.sleep(Config.DNS_RETRY_DELAY * (attempt + 1))
                else:
                    logger.debug(f"所有 {max_retries} 次尝试都失败")
                    return False
            except Exception as e:
                logger.debug(f"解析过程中出现意外错误: {str(e)}")
                return False
        return False

    async def resolve_via_doh(self, domain: str, server: str) -> bool:
        """通过DoH协议解析域名（优化超时）"""
        self.stats['doh_queries'] += 1
        try:
            headers = {
                'accept': 'application/dns-json'
            }
            params = {
                'name': domain,
                'type': 'A'
            }
            
            timeout = aiohttp.ClientTimeout(total=Config.DNS_TIMEOUT)
            async with self.session.get(server, headers=headers, params=params, 
                                      ssl=self.ssl_context, timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    return 'Answer' in data and len(data['Answer']) > 0
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False
        
        return False

    async def resolve_via_dot(self, domain: str, server: str) -> bool:
        """通过DoT协议解析域名（优化超时）"""
        self.stats['dot_queries'] += 1
        try:
            # 使用aiodns库进行DoT查询
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return len(result) > 0
        except (asyncio.TimeoutError, aiodns.error.DNSError):
            return False
        except Exception:
            return False

    async def resolve_via_standard_dns(self, domain: str) -> bool:
        """通过标准DNS协议解析域名（优化超时）"""
        self.stats['dns_queries'] += 1
        try:
            result = await asyncio.wait_for(
                self.resolver.query(domain, 'A'),
                timeout=Config.DNS_TIMEOUT
            )
            return len(result) > 0
        except (asyncio.TimeoutError, aiodns.error.DNSError):
            return False
        except Exception:
            return False

    async def is_domain_resolvable(self, domain: str) -> bool:
        """使用多协议检查域名是否可解析（GitHub CI 优化）"""
        current_time = time.time()
        
        # 首先检查白名单
        if domain in self.whitelist_domains:
            self.stats['whitelist_hits'] += 1
            logger.debug(f"域名 {domain} 在白名单中，跳过验证")
            return True
            
        # 检查已知无效域名列表
        if domain in self.known_invalid_domains:
            self.stats['known_invalid_hits'] += 1
            return False
            
        # 检查缓存有效性
        if domain in self.cache_timestamps:
            if current_time - self.cache_timestamps[domain] < Config.CACHE_TTL:
                if domain in self.valid_domains:
                    self.stats['cache_hits'] += 1
                    return True
                elif domain in self.invalid_domains:
                    self.stats['cache_hits'] += 1
                    return False
        
        # 跳过已知无效域名
        if domain in self.invalid_domains:
            return False
            
        # 检查缓存
        if domain in self.valid_domains:
            return True
        
        # 尝试DoH协议（优先选择最快的服务器）
        for doh_server in Config.DOH_SERVERS:
            result = await self.resolve_with_retry(self.resolve_via_doh, domain, doh_server)
            if result:
                self.valid_domains.add(domain)
                self.cache_timestamps[domain] = current_time
                # 清理过大的缓存
                if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
                    self._cleanup_cache()
                return True
            await asyncio.sleep(0.01)  # 短暂延迟
        
        # 尝试DoT协议
        for dot_server in Config.DOT_SERVERS:
            result = await self.resolve_with_retry(self.resolve_via_dot, domain, dot_server)
            if result:
                self.valid_domains.add(domain)
                self.cache_timestamps[domain] = current_time
                if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
                    self._cleanup_cache()
                return True
            await asyncio.sleep(0.01)
        
        # 尝试标准DNS
        result = await self.resolve_with_retry(self.resolve_via_standard_dns, domain)
        if result:
            self.valid_domains.add(domain)
            self.cache_timestamps[domain] = current_time
            if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
                self._cleanup_cache()
            return True
        
        # 所有方法都失败
        self.invalid_domains.add(domain)
        self.cache_timestamps[domain] = current_time
        return False

    def _cleanup_cache(self):
        """清理过期的缓存条目"""
        current_time = time.time()
        # 清理过期缓存
        expired_domains = [
            domain for domain, timestamp in self.cache_timestamps.items()
            if current_time - timestamp > Config.CACHE_TTL
        ]
        
        for domain in expired_domains:
            if domain in self.valid_domains:
                self.valid_domains.remove(domain)
            if domain in self.invalid_domains:
                self.invalid_domains.remove(domain)
            if domain in self.cache_timestamps:
                del self.cache_timestamps[domain]
        
        # 如果仍然太大，清理最旧的条目
        if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
            # 按时间排序并清理最旧的
            sorted_domains = sorted(
                self.cache_timestamps.items(), 
                key=lambda x: x[1]
            )
            for domain, _ in sorted_domains[:Config.MAX_CACHE_SIZE // 2]:
                if domain in self.valid_domains:
                    self.valid_domains.remove(domain)
                if domain in self.invalid_domains:
                    self.invalid_domains.remove(domain)
                if domain in self.cache_timestamps:
                    del self.cache_timestamps[domain]

    async def validate_domain(self, domain: str) -> bool:
        """综合验证域名（GitHub CI 优化）"""
        # 首先检查格式
        if not self.is_valid_domain_format(domain):
            return False
            
        # 然后检查DNS解析
        return await self.is_domain_resolvable(domain)


def check_file_size(file_path: Path) -> bool:
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > Config.MAX_FILESIZE_MB:
            logger.warning(f"跳过大文件 {file_path.name}（{size_mb:.1f}MB）")
            return False
        return True
    except Exception as e:
        logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
        return False


class AdblockCleanerCI:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        
        self.regex = RegexPatterns()
        self.validator = MultiProtocolDNSValidator()
        self.resource_monitor = ResourceMonitor()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    async def run(self):
        start_time = time.time()
        logger.info("===== Adblock规则清理工具 CI优化版 =====")
        logger.info(f"GitHub CI环境: 4核16G")
        logger.info(f"并发设置: DNS Workers={Config.DNS_WORKERS}, CPU Workers={Config.MAX_WORKERS}")
        logger.info(f"内存限制: {Config.MAX_MEMORY_PERCENT}%")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"输出文件: {Config.CLEANED_FILE}")
        logger.info(f"白名单文件: {Config.WHITELIST_FILE}")

        # 初始化DNS验证器会话
        await self.validator.init_session()

        # 获取输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        
        if not input_files:
            logger.error("未找到输入文件，退出")
            return
            
        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        # 处理每个文件
        for file_path in input_files:
            await self._process_file(file_path)

        # 关闭会话
        await self.validator.close_session()

        # 备份无效域名到文件
        self._backup_invalid_domains()

        elapsed = time.time() - start_time
        logger.info(f"\n===== 清理完成 =====")
        logger.info(f"有效域名缓存: {len(self.validator.valid_domains)}")
        logger.info(f"无效域名缓存: {len(self.validator.invalid_domains)}")
        logger.info(f"已知无效域名: {len(self.validator.known_invalid_domains)}")
        logger.info(f"白名单域名: {len(self.validator.whitelist_domains)}")
        logger.info(f"峰值内存使用: {self.resource_monitor.peak_memory:.1f}MB")
        logger.info(f"总耗时: {elapsed:.2f}秒")
        
        # 记录DNS查询统计
        logger.info(f"DNS查询统计: DoH={self.validator.stats['doh_queries']}, "
                   f"DoT={self.validator.stats['dot_queries']}, "
                   f"标准DNS={self.validator.stats['dns_queries']}")
        logger.info(f"缓存命中: {self.validator.stats['cache_hits']}, "
                   f"已知无效命中: {self.validator.stats['known_invalid_hits']}, "
                   f"白名单命中: {self.validator.stats['whitelist_hits']}")
        
        # 保存统计信息
        self._save_stats(start_time, elapsed)

    async def _process_file(self, file_path: Path):
        """处理单个文件，去除无效域名（GitHub CI 优化）"""
        if not check_file_size(file_path):
            return
            
        logger.info(f"开始处理文件: {file_path.name}")
        
        # 读取文件内容
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"读取文件{file_path.name}出错: {str(e)}")
            return
            
        # 提取所有域名
        all_domains = self._extract_domains_from_lines(lines)
        logger.info(f"从文件中提取到 {len(all_domains)} 个域名")
        
        # 分批验证域名（避免内存溢出）
        valid_domains = set()
        domain_list = list(all_domains)
        
        for i in range(0, len(domain_list), Config.BATCH_SIZE):
            batch = domain_list[i:i+Config.BATCH_SIZE]
            batch_num = i//Config.BATCH_SIZE + 1
            total_batches = (len(domain_list)-1)//Config.BATCH_SIZE + 1
            logger.info(f"处理域名批次 {batch_num}/{total_batches} ({len(batch)} 个域名)")
            
            batch_valid_domains = await self._validate_domains_batch(batch)
            valid_domains.update(batch_valid_domains)
            
            # 检查资源使用情况
            if not self.resource_monitor.check_memory_usage():
                logger.warning("内存使用超过限制，暂停处理")
                await asyncio.sleep(1)  # 暂停一下让内存回收
                
            self.resource_monitor.log_resource_usage()
        
        logger.info(f"有效域名: {len(valid_domains)} 个，无效域名: {len(all_domains) - len(valid_domains)} 个")
        
        # 过滤规则，只保留包含有效域名的规则
        cleaned_lines = self._filter_rules(lines, valid_domains)
        
        # 写入清理后的文件
        output_path = Config.CLEANED_FILE
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(cleaned_lines)
            
        logger.info(f"已写入清理后的规则到 {output_path}，保留 {len(cleaned_lines)} 条规则")

    def _extract_domains_from_lines(self, lines: List[str]) -> Set[str]:
        """从所有行中提取域名"""
        domains = set()
        
        for line in lines:
            line = line.strip()
            
            # 跳过注释和空行
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
                continue
                
            # 尝试提取域名
            domain = self._extract_domain_from_rule(line)
            if domain:
                domains.add(domain)
                
        return domains

    def _extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从单条规则中提取域名（性能优化）"""
        # 尝试匹配Adblock域名规则
        domain_match = self.regex.DOMAIN_EXTRACT.match(rule)
        if domain_match:
            return domain_match.group(1)
            
        # 尝试匹配Hosts规则
        hosts_match = self.regex.HOSTS_RULE.match(rule)
        if hosts_match:
            return hosts_match.group(1)
            
        # 尝试从URL规则中提取域名
        if rule.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(rule)
                if parsed.netloc:
                    return parsed.netloc.split(':')[0]  # 移除端口号
            except:
                pass
                
        return None

    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名有效性（GitHub CI 优化）"""
        valid_domains = set()
        
        # 使用异步任务并行验证域名
        tasks = []
        for domain in domains:
            tasks.append(self.validator.validate_domain(domain))
        
        # 分批处理以避免内存问题
        batch_size = Config.DNS_WORKERS
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for j, result in enumerate(results):
                domain = domains[i+j]
                if isinstance(result, Exception):
                    logger.debug(f"验证域名 {domain} 时出错: {str(result)}")
                elif result:
                    valid_domains.add(domain)
                    
        return valid_domains

    def _filter_rules(self, lines: List[str], valid_domains: Set[str]) -> List[str]:
        """过滤规则，只保留包含有效域名的规则"""
        cleaned_lines = []
        
        for line in lines:
            original_line = line
            line = line.strip()
            
            # 保留注释和空行
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
                cleaned_lines.append(original_line)
                continue
                
            # 保留特殊规则类型（根据配置）
            if (Config.PRESERVE_ELEMENT_HIDING and self.regex.ELEMENT_HIDING.match(line)) or \
               (Config.PRESERVE_SCRIPT_RULES and (self.regex.SCRIPTLET.match(line) or self.regex.ADGUARD_SCRIPT.match(line))) or \
               (Config.PRESERVE_REGEX_RULES and self.regex.GENERIC.match(line)):
                cleaned_lines.append(original_line)
                continue
                
            # 提取规则中的域名
            domain = self._extract_domain_from_rule(line)
            
            # 如果规则不包含域名，或者包含的域名有效，则保留
            if not domain or domain in valid_domains:
                cleaned_lines.append(original_line)
                
        return cleaned_lines

    def _backup_invalid_domains(self):
        """备份无效域名到文件，并管理备份历史"""
        # 合并所有无效域名（已知的和新发现的）
        all_invalid_domains = self.validator.known_invalid_domains | self.validator.invalid_domains
        
        if not all_invalid_domains:
            logger.info("没有无效域名需要备份")
            return
            
        # 确保目录存在
        Config.INVALID_DOMAINS_BACKUP.parent.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        
        # 创建带时间戳的备份文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = Config.BACKUP_HISTORY_DIR / f"adblock_update_{timestamp}.txt"
        compressed_backup = Config.BACKUP_HISTORY_DIR / f"adblock_update_{timestamp}.txt.gz"
        
        try:
            # 写入带时间戳的备份
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write("# Adblock无效域名备份文件\n")
                f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
                f.write(f"# 总数: {len(all_invalid_domains)}\n")
                f.write("# 此文件包含已知无法解析的域名，用于加速后续验证\n\n")
                
                for domain in sorted(all_invalid_domains):
                    f.write(f"{domain}\n")
            
            # 创建压缩版本
            with open(backup_file, 'rb') as f_in:
                with gzip.open(compressed_backup, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # 更新主备份文件（不带时间戳）
            shutil.copy2(backup_file, Config.INVALID_DOMAINS_BACKUP)
            
            # 清理旧备份文件
            self._cleanup_old_backups()
            
            logger.info(f"已备份 {len(all_invalid_domains)} 个无效域名到 {backup_file}")
            logger.info(f"压缩备份已保存到 {compressed_backup}")
        except Exception as e:
            logger.error(f"备份无效域名失败: {str(e)}")

    def _cleanup_old_backups(self):
        """清理旧的备份文件"""
        try:
            # 获取所有备份文件并按修改时间排序
            backup_files = sorted(
                Config.BACKUP_HISTORY_DIR.glob("adblock_update_*.txt"),
                key=os.path.getmtime,
                reverse=True
            )
            
            # 删除超出数量限制的旧备份
            if len(backup_files) > Config.MAX_BACKUP_FILES:
                for old_file in backup_files[Config.MAX_BACKUP_FILES:]:
                    old_file.unlink()
                    # 同时删除对应的压缩文件
                    compressed_file = Config.BACKUP_HISTORY_DIR / f"{old_file.stem}.gz"
                    if compressed_file.exists():
                        compressed_file.unlink()
                    logger.info(f"删除旧备份文件: {old_file.name}")
                    
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
            "known_invalid_domains": len(self.validator.known_invalid_domains),
            "whitelist_domains": len(self.validator.whitelist_domains),
            "dns_query_stats": self.validator.stats,
            "ci_environment": "GitHub Actions (4 cores, 16GB RAM)",
            "concurrency_settings": {
                "dns_workers": Config.DNS_WORKERS,
                "cpu_workers": Config.MAX_WORKERS,
                "batch_size": Config.BATCH_SIZE
            },
            "doh_servers": Config.DOH_SERVERS,
            "dot_servers": Config.DOT_SERVERS,
            "preserve_settings": {
                "element_hiding": Config.PRESERVE_ELEMENT_HIDING,
                "script_rules": Config.PRESERVE_SCRIPT_RULES,
                "regex_rules": Config.PRESERVE_REGEX_RULES
            },
            "backup_file": str(Config.INVALID_DOMAINS_BACKUP),
            "backup_history_dir": str(Config.BACKUP_HISTORY_DIR),
            "whitelist_file": str(Config.WHITELIST_FILE)
        }
        
        stats_file = Config.TEMP_DIR / "cleaning_stats.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        logger.info(f"统计信息已保存到 {stats_file}")


async def main():
    try:
        # 提高文件描述符限制（GitHub CI 优化）
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
        except:
            pass  # 忽略错误，如果权限不足
            
        cleaner = AdblockCleanerCI()
        await cleaner.run()
    except Exception as e:
        logger.critical(f"工具运行失败: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    # 设置事件循环策略（GitHub CI 优化）
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    else:
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    
    asyncio.run(main())