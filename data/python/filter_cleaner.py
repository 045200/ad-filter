#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS的Adblock规则清理器
实现SmartDNS + CDN双重验证方案
专为GitHub Actions环境优化
支持完整的Adblock/AdGuard/AdGuard Home语法
"""

import os
import re
import sys
import json
import time
import logging
import asyncio
import aiohttp
import aiodns
import subprocess
import socket
import ipaddress
import random
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple, Any
from datetime import datetime
from collections import OrderedDict
import maxminddb

# 配置类
class Config:
    # 基础路径
    GITHUB_WORKSPACE = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    BASE_DIR = GITHUB_WORKSPACE

    # 输入输出路径
    FILTER_DIR = BASE_DIR / "data" / "filter"
    INPUT_BLOCKLIST = FILTER_DIR / "adblock_filter.txt"
    INPUT_ALLOWLIST = FILTER_DIR / "allow_filter.txt"
    OUTPUT_BLOCKLIST = FILTER_DIR / "adblock.txt"
    OUTPUT_ALLOWLIST = FILTER_DIR / "allow.txt"

    # SmartDNS配置
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5353))

    # 额外数据文件
    EXTRA_DATA_DIR = BASE_DIR / "data" / "extra"
    CHINA_IP_FILE = EXTRA_DATA_DIR / "china_ip_ranges.txt"
    GEOIP_DB = EXTRA_DATA_DIR / "GeoLite2-Country.mmdb"
    GEOSITE_FILE = EXTRA_DATA_DIR / "geosite.dat"
    CDN_IP_RANGES_FILE = EXTRA_DATA_DIR / "cdn_ip_ranges.json"

    # 规则源路径
    SMARTDNS_SOURCES_DIR = BASE_DIR / "data" / "sources"

    # 备份路径
    BACKUP_DIR = FILTER_DIR / "backups"

    # 缓存配置
    CACHE_DIR = BASE_DIR / "data" / "cache"
    CACHE_TTL = 86400  # 24小时

    # 性能配置
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 8))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 50))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
    MAX_MEMORY_PERCENT = int(os.getenv('MAX_MEMORY_PERCENT', 80))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 10))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 2))
    CDN_VERIFICATION = os.getenv('CDN_VERIFICATION', 'true').lower() == 'true'

    # 功能开关
    USE_SMARTDNS = os.getenv('USE_SMARTDNS', 'true').lower() == 'true'
    PROCESS_SMARTDNS_RULES = os.getenv('PROCESS_SMARTDNS_RULES', 'true').lower() == 'true'
    USE_GEOIP = os.getenv('USE_GEOIP', 'true').lower() == 'true'
    USE_GEOSITE = os.getenv('USE_GEOSITE', 'true').lower() == 'true'

    # DNS服务器配置
    CHINA_DNS_SERVERS = [
        '114.114.114.114',
        '114.114.115.115',
        '223.5.5.5',
        '223.6.6.6'
    ]
    
    GLOBAL_DNS_SERVERS = [
        '1.1.1.1',
        '8.8.8.8',
        '9.9.9.9',
        '208.67.222.222'
    ]

# 额外文件下载配置
EXTRA_DOWNLOADS = {
    "china_ip_ranges.txt": {
        "url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
    },
    "GeoLite2-Country.mmdb": {
        "url": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    },
    "geosite.dat": {
        "url": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
    },
    "cdn_ip_ranges.json": {
        "url": "https://raw.githubusercontent.com/SukkaW/CDN-IP-Blacklist/master/cdn_ip_ranges.json",
    }
}

# 日志配置
def setup_logger():
    logger = logging.getLogger('SmartDNSCleaner')
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

logger = setup_logger()

# 文件下载器
class FileDownloader:
    @staticmethod
    async def download_file(url: str, dest: Path, session: aiohttp.ClientSession = None):
        """下载文件到指定路径"""
        dest.parent.mkdir(parents=True, exist_ok=True)

        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True

        try:
            async with session.get(url) as response:
                if response.status == 200:
                    with open(dest, 'wb') as f:
                        while True:
                            chunk = await response.content.read(1024)
                            if not chunk:
                                break
                            f.write(chunk)
                    logger.info(f"下载成功: {dest.name}")
                else:
                    logger.error(f"下载失败: {url} - 状态码: {response.status}")
        except Exception as e:
            logger.error(f"下载文件时出错 {url}: {e}")
        finally:
            if close_session:
                await session.close()

    @staticmethod
    async def download_extra_files():
        """下载额外数据文件"""
        tasks = []
        async with aiohttp.ClientSession() as session:
            for filename, info in EXTRA_DOWNLOADS.items():
                dest_path = Config.EXTRA_DATA_DIR / filename
                if not dest_path.exists():
                    tasks.append(FileDownloader.download_file(info["url"], dest_path, session))

            if tasks:
                await asyncio.gather(*tasks)
                logger.info("所有额外文件下载完成")
            else:
                logger.info("所有额外文件已存在，跳过下载")

# 增强的规则处理器
class EnhancedRuleProcessor:
    def __init__(self):
        # 正则模式定义
        self.regex_patterns = {
            # 基础Adblock语法
            'domain': re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]'),
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$'),
            'comment': re.compile(r'^[!#]'),
            'empty': re.compile(r'^\s*$'),

            # AdGuard扩展语法
            'adguard_domain': re.compile(r'^@@?\|\|?([\w.-]+)[\^\$\|\/]'),
            'adguard_modifiers': re.compile(r'\$([^,\s]+)'),
        }

        # 支持的AdGuard修饰符
        self.supported_modifiers = {
            'domain', 'third-party', 'script', 'stylesheet', 'image', 'object',
            'xmlhttprequest', 'websocket', 'webrtc', 'popup', 'subdocument',
            'document', 'elemhide', 'content', 'genericblock', 'generichide'
        }

    def parse_rule(self, rule: str) -> Tuple[Optional[str], Optional[dict]]:
        """
        解析单条规则，返回域名和修饰符信息
        返回值: (domain, modifiers)
        """
        rule = rule.strip()

        # 跳过注释和空行
        if not rule or self.regex_patterns['comment'].match(rule) or self.regex_patterns['empty'].match(rule):
            return None, None

        # 提取域名
        domain = None
        for pattern_name in ['domain', 'hosts', 'adguard_domain']:
            match = self.regex_patterns[pattern_name].match(rule)
            if match:
                domain = match.group(1)
                break

        if not domain:
            return None, None

        # 提取修饰符
        modifiers = {}
        modifier_matches = self.regex_patterns['adguard_modifiers'].findall(rule)
        for modifier in modifier_matches:
            if '=' in modifier:
                key, value = modifier.split('=', 1)
                modifiers[key] = value
            else:
                modifiers[modifier] = True

        # 过滤不支持的修饰符
        supported_modifiers = {}
        for mod, value in modifiers.items():
            if mod in self.supported_modifiers:
                supported_modifiers[mod] = value

        return domain, supported_modifiers

    def extract_domains_from_rules(self, rules: List[str]) -> Set[str]:
        """
        从规则列表中提取所有域名
        """
        domains = set()

        for rule in rules:
            domain, modifiers = self.parse_rule(rule)
            if domain:
                domains.add(domain)

        return domains

# 地理位置工具
class GeoIPTools:
    def __init__(self):
        self.china_ips = set()
        self.geoip_reader = None
        self.cdn_ip_ranges = {}
        self.loaded = False

    def load_data(self):
        """加载地理位置数据"""
        try:
            # 加载中国IP范围
            if Config.CHINA_IP_FILE.exists():
                with open(Config.CHINA_IP_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.china_ips.add(line)
                logger.info(f"已加载 {len(self.china_ips)} 个中国IP范围")

            # 加载GeoIP数据库
            if Config.USE_GEOIP and Config.GEOIP_DB.exists():
                self.geoip_reader = maxminddb.open_database(str(Config.GEOIP_DB))
                logger.info("GeoIP数据库加载成功")

            # 加载CDN IP范围
            if Config.CDN_VERIFICATION and Config.CDN_IP_RANGES_FILE.exists():
                with open(Config.CDN_IP_RANGES_FILE, 'r') as f:
                    self.cdn_ip_ranges = json.load(f)
                logger.info(f"已加载 {len(self.cdn_ip_ranges)} 个CDN IP范围")

            self.loaded = True
        except Exception as e:
            logger.error(f"加载地理位置数据失败: {e}")

    def is_china_ip(self, ip: str) -> bool:
        """检查IP是否属于中国"""
        if not self.loaded:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.china_ips:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except:
            pass

        return False

    def get_country_code(self, ip: str) -> Optional[str]:
        """获取IP所属国家代码"""
        if not self.geoip_reader:
            return None

        try:
            data = self.geoip_reader.get(ip)
            if data and 'country' in data and 'iso_code' in data['country']:
                return data['country']['iso_code']
        except:
            pass

        return None

    def is_cdn_ip(self, ip: str) -> bool:
        """检查IP是否属于CDN"""
        if not self.cdn_ip_ranges:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
            for cdn_name, ranges in self.cdn_ip_ranges.items():
                for cidr in ranges:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return True
        except:
            pass

        return False

    def close(self):
        """关闭资源"""
        if self.geoip_reader:
            self.geoip_reader.close()

# 域名分类器
class DomainClassifier:
    def __init__(self, geo_tools: GeoIPTools):
        self.geo_tools = geo_tools
        self.china_domains = set()
        self.global_domains = set()
        self.unknown_domains = set()
        
        # 常见中国域名后缀
        self.china_tlds = {
            'cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
            'ac.cn', 'mil.cn', '公司', '网络', '中国', '台灣', '台湾', '香港', '澳门'
        }
        
        # 常见中国域名关键词
        self.china_keywords = {
            'baidu', 'taobao', 'alibaba', 'tencent', 'qq', 'weixin', 'sina',
            'sohu', '163', '126', 'jd', '360', 'xiaomi', 'huawei', 'oppo',
            'vivo', 'meituan', 'douyin', 'bytedance', 'kuaishou', 'bilibili',
            'weibo', 'zhihu', 'douban', 'ximalaya', 'ctrip', 'qunar', '58',
            'ganji', 'autohome', 'dianping', 'eleme', 'didiglobal', 'ke'
        }

    def classify_domain(self, domain: str) -> str:
        """
        分类域名：china, global 或 unknown
        """
        # 检查域名后缀
        for tld in self.china_tlds:
            if domain.endswith('.' + tld) or domain == tld:
                self.china_domains.add(domain)
                return 'china'
        
        # 检查域名关键词
        for keyword in self.china_keywords:
            if keyword in domain:
                self.china_domains.add(domain)
                return 'china'
                
        # 无法确定的域名标记为unknown，后续通过DNS解析确定
        self.unknown_domains.add(domain)
        return 'unknown'

    def get_stats(self):
        """获取分类统计"""
        return {
            'china': len(self.china_domains),
            'global': len(self.global_domains),
            'unknown': len(self.unknown_domains)
        }

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        self.port = Config.SMARTDNS_PORT
        self.is_running = False

    def generate_config(self):
        """生成SmartDNS配置文件"""
        config_content = f"""bind 127.0.0.1:{self.port}
bind-tcp 127.0.0.1:{self.port}
cache-size 512
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level error
log-size 128K
speed-check-mode ping,tcp:80,tcp:443

# DNS服务器 - 基于测试结果选择响应快且支持加密协议的
# 国内DNS服务器
server 114.114.114.114
server 114.114.115.115
server-tls 223.5.5.5
server-tls 223.6.6.6
server-https https://doh.pub/dns-query
server-https https://dns.alidns.com/dns-query

# 国际DNS服务器
server-tls 1.1.1.1
server-tls 8.8.8.8
server-tls 9.9.9.9
server-https https://cloudflare-dns.com/dns-query
server-https https://dns.google/dns-query
"""

        # 如果启用了GeoSite，添加GeoSite配置
        if Config.USE_GEOSITE and Config.GEOSITE_FILE.exists():
            config_content += f"\n# GeoSite配置\n"
            config_content += f"geosite-file {Config.GEOSITE_FILE}\n"
            config_content += f"nameserver /geosite:cn/114.114.114.114\n"
            config_content += f"nameserver /geosite:geolocation-cn/114.114.114.114\n"
            config_content += f"nameserver /geosite:geolocation-!cn/1.1.1.1\n"

        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(Config.SMARTDNS_CONFIG_FILE, 'w') as f:
            f.write(config_content)

        logger.info("SmartDNS配置文件生成完成")

    def start(self):
        """启动SmartDNS服务"""
        if not Config.USE_SMARTDNS:
            logger.info("SmartDNS功能已禁用")
            return False

        self.generate_config()

        try:
            # 检查是否已有进程在运行
            if self.is_running:
                self.stop()

            cmd = [
                Config.SMARTDNS_BIN,
                "-c", str(Config.SMARTDNS_CONFIG_FILE),
                "-x"
            ]

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # 等待服务启动
            time.sleep(3)

            # 测试服务是否正常
            test_result = self.test_connection()
            if test_result:
                logger.info("SmartDNS服务启动成功")
                self.is_running = True
                return True
            else:
                logger.error("SmartDNS服务启动失败")
                # 输出错误信息
                try:
                    stdout, stderr = self.process.communicate(timeout=2)
                    if stdout:
                        logger.error(f"SmartDNS stdout: {stdout}")
                    if stderr:
                        logger.error(f"SmartDNS stderr: {stderr}")
                except:
                    pass
                return False

        except Exception as e:
            logger.error(f"启动SmartDNS服务时出错: {e}")
            return False

    def stop(self):
        """停止SmartDNS服务"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("SmartDNS服务已停止")
            except:
                try:
                    self.process.kill()
                    self.process.wait()
                    logger.info("SmartDNS服务已被强制停止")
                except:
                    pass
            finally:
                self.process = None
                self.is_running = False

    def test_connection(self):
        """测试SmartDNS连接"""
        test_domains = ['www.baidu.com', 'www.google.com', 'www.cloudflare.com']
        success_count = 0
        
        for domain in test_domains:
            try:
                # 使用dig测试连接
                cmd = [
                    "dig", "@127.0.0.1", "-p", str(self.port),
                    domain, "+short", "+time=5", "+tries=2"
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0 and len(result.stdout.strip()) > 0:
                    success_count += 1
                    logger.debug(f"SmartDNS测试 {domain} 成功")
                else:
                    logger.warning(f"SmartDNS测试 {domain} 失败: {result.stderr}")
            except Exception as e:
                logger.warning(f"SmartDNS测试 {domain} 异常: {e}")

        # 至少成功两个测试才认为服务正常
        return success_count >= 2

# DNS验证器 - 实现SmartDNS + CDN双重验证
class DNSValidator:
    def __init__(self, smartdns_manager: Optional[SmartDNSManager], geo_tools: GeoIPTools):
        self.smartdns = smartdns_manager
        self.geo_tools = geo_tools
        self.classifier = DomainClassifier(geo_tools)
        self.cache = {}
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'cached': 0,
            'smartdns_queries': 0,
            'direct_queries': 0,
            'cdn_verifications': 0,
            'china_domains': 0,
            'global_domains': 0
        }

    async def validate_domain(self, domain: str) -> bool:
        """验证域名有效性 - 实现SmartDNS + CDN双重验证"""
        self.stats['total'] += 1

        # 检查缓存
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]

        # 分类域名
        domain_type = self.classifier.classify_domain(domain)
        
        # 第一步：使用SmartDNS或直接DNS查询域名
        if Config.USE_SMARTDNS and self.smartdns and self.smartdns.is_running:
            self.stats['smartdns_queries'] += 1
            dns_result = await self.query_smartdns(domain)
        else:
            if domain_type == 'china':
                dns_servers = Config.CHINA_DNS_SERVERS
            else:
                dns_servers = Config.GLOBAL_DNS_SERVERS
                
            self.stats['direct_queries'] += 1
            dns_result = await self.query_direct(domain, dns_servers)

        # 如果DNS查询失败，直接返回无效
        if not dns_result:
            self.cache[domain] = False
            self.stats['invalid'] += 1
            return False

        # 第二步：CDN验证（如果启用）
        if Config.CDN_VERIFICATION:
            self.stats['cdn_verifications'] += 1
            cdn_result = await self.verify_cdn(domain, dns_result)
            
            # 如果CDN验证失败，返回无效
            if not cdn_result:
                self.cache[domain] = False
                self.stats['invalid'] += 1
                return False

        # 第三步：根据域名类型更新统计
        if domain_type == 'china':
            self.stats['china_domains'] += 1
        else:
            self.stats['global_domains'] += 1

        # 缓存结果
        self.cache[domain] = True
        self.stats['valid'] += 1
        return True

    async def verify_cdn(self, domain: str, ip_addresses: List[str]) -> bool:
        """CDN验证 - 检查IP是否属于CDN或合法IP范围"""
        for ip in ip_addresses:
            # 检查是否为CDN IP
            if self.geo_tools.is_cdn_ip(ip):
                logger.debug(f"域名 {domain} 使用CDN IP: {ip}")
                return True
            
            # 检查IP地理位置是否与域名类型匹配
            domain_type = self.classifier.classify_domain(domain)
            is_china_ip = self.geo_tools.is_china_ip(ip)
            
            if domain_type == 'china' and is_china_ip:
                return True
            elif domain_type != 'china' and not is_china_ip:
                return True
            
            # 如果无法确定域名类型，检查IP是否属于中国
            if domain_type == 'unknown':
                country_code = self.geo_tools.get_country_code(ip)
                if country_code == 'CN' and is_china_ip:
                    self.classifier.china_domains.add(domain)
                    return True
                elif country_code and country_code != 'CN' and not is_china_ip:
                    self.classifier.global_domains.add(domain)
                    return True
        
        # 所有IP验证都失败
        logger.debug(f"CDN验证失败: {domain} -> {ip_addresses}")
        return False

    async def query_smartdns(self, domain: str) -> List[str]:
        """使用SmartDNS查询域名"""
        for attempt in range(Config.DNS_RETRIES):
            try:
                # 使用aiodns进行异步DNS查询
                resolver = aiodns.DNSResolver()
                resolver.nameservers = ['127.0.0.1']
                resolver.port = Config.SMARTDNS_PORT

                result = await asyncio.wait_for(
                    resolver.query(domain, 'A'),
                    timeout=Config.DNS_TIMEOUT
                )
                
                # 提取IP地址
                ip_addresses = [record.host for record in result]
                return ip_addresses
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                if attempt < Config.DNS_RETRIES - 1:
                    await asyncio.sleep(0.1)  # 短暂等待后重试
                continue
            except Exception as e:
                logger.debug(f"SmartDNS查询异常 {domain}: {e}")
                break
                
        return []

    async def query_direct(self, domain: str, dns_servers: List[str]) -> List[str]:
        """直接使用指定DNS服务器查询域名"""
        for attempt in range(Config.DNS_RETRIES):
            try:
                # 随机选择一个DNS服务器
                dns_server = random.choice(dns_servers)
                
                # 使用aiodns进行异步DNS查询
                resolver = aiodns.DNSResolver()
                resolver.nameservers = [dns_server]
                
                result = await asyncio.wait_for(
                    resolver.query(domain, 'A'),
                    timeout=Config.DNS_TIMEOUT
                )
                
                # 提取IP地址
                ip_addresses = [record.host for record in result]
                return ip_addresses
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                if attempt < Config.DNS_RETRIES - 1:
                    await asyncio.sleep(0.1)  # 短暂等待后重试
                continue
            except Exception as e:
                logger.debug(f"直接DNS查询异常 {domain}@{dns_server}: {e}")
                break
                
        return []

    def get_stats(self):
        """获取统计信息"""
        return {**self.stats, **self.classifier.get_stats()}

# 主处理器
class RuleCleaner:
    def __init__(self):
        # 确保目录存在
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        Config.EXTRA_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # 初始化其他组件
        self.smartdns = SmartDNSManager()
        self.validator = None
        self.processor = EnhancedRuleProcessor()
        self.geo_tools = GeoIPTools()

    async def initialize(self):
        """异步初始化方法"""
        # 下载额外文件
        await FileDownloader.download_extra_files()

        # 加载地理位置工具
        self.geo_tools.load_data()

        # 初始化验证器
        self.validator = DNSValidator(self.smartdns, self.geo_tools)

    async def process(self):
        """处理规则文件"""
        logger.info("开始处理规则文件")
        start_time = time.time()

        # 异步初始化
        await self.initialize()

        # 启动SmartDNS
        smartdns_started = False
        if Config.USE_SMARTDNS:
            smartdns_started = self.smartdns.start()
            if not smartdns_started:
                logger.warning("SmartDNS启动失败，将使用直接DNS验证方法")

        try:
            # 处理黑名单文件
            logger.info("处理黑名单文件...")
            blocklist_rules = self.read_rules(Config.INPUT_BLOCKLIST)
            valid_blocklist_rules = await self.validate_rules(blocklist_rules)
            self.save_rules(valid_blocklist_rules, Config.OUTPUT_BLOCKLIST, Config.INPUT_BLOCKLIST)

            # 处理白名单文件
            logger.info("处理白名单文件...")
            allowlist_rules = self.read_rules(Config.INPUT_ALLOWLIST)
            valid_allowlist_rules = await self.validate_rules(allowlist_rules)
            self.save_rules(valid_allowlist_rules, Config.OUTPUT_ALLOWLIST, Config.INPUT_ALLOWLIST)

            # 输出统计信息
            elapsed = time.time() - start_time
            self.print_stats(elapsed)

        finally:
            # 停止SmartDNS
            if smartdns_started:
                self.smartdns.stop()
            # 关闭地理位置工具
            self.geo_tools.close()

    def read_rules(self, file_path: Path) -> List[str]:
        """读取规则文件"""
        rules = []
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rules = [line.rstrip('\n') + '\n' for line in f]  # 确保每行有换行符
                logger.info(f"从 {file_path.name} 读取 {len(rules)} 条规则")
            except Exception as e:
                logger.error(f"读取文件 {file_path} 失败: {e}")
        else:
            logger.warning(f"文件不存在: {file_path}")

        return rules

    async def validate_rules(self, rules: List[str]) -> List[str]:
        """验证规则有效性"""
        valid_rules = []
        domains_to_validate = set()
        domain_to_rules = {}

        # 提取域名并分组
        for rule in rules:
            domain, modifiers = self.processor.parse_rule(rule)
            if domain:
                domains_to_validate.add(domain)
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = []
                domain_to_rules[domain].append(rule)
            else:
                # 保留无法提取域名的规则（注释、特殊规则等）
                valid_rules.append(rule)

        logger.info(f"需要验证 {len(domains_to_validate)} 个域名")

        # 批量验证域名
        valid_domains = await self.validate_domains_batch(list(domains_to_validate))

        # 构建有效规则列表
        for domain in valid_domains:
            valid_rules.extend(domain_to_rules[domain])

        return valid_rules

    async def validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名"""
        valid_domains = set()
        total = len(domains)

        if total == 0:
            return valid_domains

        # 使用信号量限制并发数
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)

        async def validate_with_semaphore(domain):
            async with semaphore:
                return domain, await self.validator.validate_domain(domain)

        # 分批处理
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [validate_with_semaphore(domain) for domain in batch]
            results = await asyncio.gather(*tasks)

            for domain, result in results:
                if result:
                    valid_domains.add(domain)

            # 输出进度
            processed = min(i + Config.BATCH_SIZE, total)
            logger.info(f"进度: {processed}/{total} 域名, 有效: {len(valid_domains)}")

        logger.info(f"验证完成: 有效 {len(valid_domains)}/{total} 域名")
        return valid_domains

    def save_rules(self, rules: List[str], output_path: Path, input_path: Path):
        """保存规则到文件"""
        try:
            # 创建备份
            if input_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = Config.BACKUP_DIR / f"{input_path.stem}_backup_{timestamp}.txt"
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                backup_file.write_text(input_path.read_text(encoding='utf-8'), encoding='utf-8')

            # 保存新规则
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(rules)

            logger.info(f"已保存 {len(rules)} 条规则到 {output_path}")
        except Exception as e:
            logger.error(f"保存规则失败: {e}")

    def print_stats(self, elapsed: float):
        """输出统计信息"""
        stats = self.validator.get_stats()

        logger.info("\n===== 处理统计 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")
        logger.info(f"SmartDNS查询: {stats['smartdns_queries']} 次")
        logger.info(f"直接DNS查询: {stats['direct_queries']} 次")
        logger.info(f"CDN验证: {stats['cdn_verifications']} 次")
        logger.info(f"中国域名: {stats['china_domains']} 个")
        logger.info(f"国际域名: {stats['global_domains']} 个")
        logger.info(f"未知域名: {stats['unknown']} 个")

# 主函数
async def main():
    cleaner = RuleCleaner()
    await cleaner.process()

if __name__ == '__main__':
    asyncio.run(main())