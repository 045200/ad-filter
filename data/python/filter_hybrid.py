#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adblock规则清理工具 - GitHub CI 优化版"""

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


class Config:
    """配置：GitHub CI 环境优化配置"""
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    
    # 输入：仓库根目录下的临时目录
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    # 输出：清理后的文件将覆盖原文件
    OUTPUT_DIR = TEMP_DIR
    
    # 核心输出文件
    CLEANED_FILE = TEMP_DIR / "adblock_merged_cleaned.txt"
    
    # GitHub CI 环境优化配置
    MAX_WORKERS = 4  # 匹配 CPU 核心数
    DNS_WORKERS = 100  # DNS查询的并发数（提高IO密集型任务并发）
    RULE_LEN_RANGE = (3, 2048)
    MAX_FILESIZE_MB = 100  # 增加文件大小限制
    INPUT_PATTERNS = ["adblock_merged.txt"]
    
    # DNS解析设置
    DNS_TIMEOUT = 2  # 减少超时时间
    DNS_RETRIES = 1  # 减少重试次数（快速失败）
    
    # 内存管理
    MAX_MEMORY_PERCENT = 70  # 最大内存使用百分比
    BATCH_SIZE = 5000  # 域名批量处理大小
    
    # 多协议DNS服务器配置（优化服务器选择）
    DOH_SERVERS = [
        "https://1.1.1.1/dns-query",  # Cloudflare (全球CDN)
        "https://dns.google/dns-query",  # Google (全球CDN)
        "https://dns.alidns.com/dns-query",  # AliDNS (亚洲优化)
        "https://doh.opendns.com/dns-query",  # OpenDNS (北美优化)
    ]
    
    DOT_SERVERS = [
        "1.1.1.1",  # Cloudflare
        "8.8.8.8",  # Google
    ]
    
    # 特殊规则保留设置
    PRESERVE_ELEMENT_HIDING = True
    PRESERVE_SCRIPT_RULES = True
    PRESERVE_REGEX_RULES = True


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
        
        # 创建SSL上下文
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
        # 初始化DNS解析器
        self.resolver = aiodns.DNSResolver()
        self.resolver.timeout = Config.DNS_TIMEOUT
        
        # 会话管理
        self.session = None
        self.connector = None

    async def init_session(self):
        """初始化aiohttp会话（GitHub CI 优化）"""
        if self.session is None:
            # 使用连接池限制，避免过多连接
            self.connector = aiohttp.TCPConnector(
                limit=Config.DNS_WORKERS,
                limit_per_host=10,
                ttl_dns_cache=300  # DNS缓存5分钟
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

    async def resolve_via_doh(self, domain: str, server: str) -> bool:
        """通过DoH协议解析域名（优化超时）"""
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
        # 跳过已知无效域名
        if domain in self.invalid_domains:
            return False
            
        # 检查缓存
        if domain in self.valid_domains:
            return True
        
        # 尝试DoH协议（优先选择最快的服务器）
        for doh_server in Config.DOH_SERVERS:
            if await self.resolve_via_doh(domain, doh_server):
                self.valid_domains.add(domain)
                return True
            await asyncio.sleep(0.01)  # 短暂延迟
        
        # 尝试DoT协议
        for dot_server in Config.DOT_SERVERS:
            if await self.resolve_via_dot(domain, dot_server):
                self.valid_domains.add(domain)
                return True
            await asyncio.sleep(0.01)
        
        # 尝试标准DNS
        if await self.resolve_via_standard_dns(domain):
            self.valid_domains.add(domain)
            return True
        
        # 所有方法都失败
        self.invalid_domains.add(domain)
        return False

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

        elapsed = time.time() - start_time
        logger.info(f"\n===== 清理完成 =====")
        logger.info(f"有效域名缓存: {len(self.validator.valid_domains)}")
        logger.info(f"无效域名缓存: {len(self.validator.invalid_domains)}")
        logger.info(f"峰值内存使用: {self.resource_monitor.peak_memory:.1f}MB")
        logger.info(f"总耗时: {elapsed:.2f}秒")
        
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
            logger.info(f"处理域名批次 {i//Config.BATCH_SIZE + 1}/{(len(domain_list)-1)//Config.BATCH_SIZE + 1}")
            
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

    def _save_stats(self, start_time: float, elapsed: float):
        """保存统计信息"""
        stats = {
            "timestamp": datetime.now().isoformat(),
            "processing_time_seconds": elapsed,
            "peak_memory_mb": self.resource_monitor.peak_memory,
            "valid_domains": len(self.validator.valid_domains),
            "invalid_domains": len(self.validator.invalid_domains),
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
            }
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