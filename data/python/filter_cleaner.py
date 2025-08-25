#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS的Adblock规则清理器
专为GitHub Actions环境优化
支持完整的Adblock/AdGuard/AdGuard Home语法
使用SmartDNS过滤过期无效域名
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
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
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

    # 规则源路径
    SMARTDNS_SOURCES_DIR = BASE_DIR / "data" / "sources"

    # 备份路径
    BACKUP_DIR = FILTER_DIR / "backups"

    # 缓存配置
    CACHE_DIR = BASE_DIR / "data" / "cache"
    CACHE_TTL = 86400  # 24小时

    # 性能配置
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 8))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 30))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
    MAX_MEMORY_PERCENT = int(os.getenv('MAX_MEMORY_PERCENT', 80))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 8))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 2))

    # 功能开关
    USE_SMARTDNS = os.getenv('USE_SMARTDNS', 'true').lower() == 'true'
    PROCESS_SMARTDNS_RULES = os.getenv('PROCESS_SMARTDNS_RULES', 'true').lower() == 'true'
    USE_GEOIP = os.getenv('USE_GEOIP', 'true').lower() == 'true'
    USE_GEOSITE = os.getenv('USE_GEOSITE', 'true').lower() == 'true'

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
        if not rule or self.regex_patterns['comment'].match(rule):
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

    def close(self):
        """关闭资源"""
        if self.geoip_reader:
            self.geoip_reader.close()

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        self.port = Config.SMARTDNS_PORT

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
            time.sleep(2)

            # 测试服务是否正常
            test_result = self.test_connection()
            if test_result:
                logger.info("SmartDNS服务启动成功")
                return True
            else:
                logger.error("SmartDNS服务启动失败")
                return False

        except Exception as e:
            logger.error(f"启动SmartDNS服务时出错: {e}")
            return False

    def stop(self):
        """停止SmartDNS服务"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            logger.info("SmartDNS服务已停止")

    def test_connection(self):
        """测试SmartDNS连接"""
        try:
            # 使用dig测试连接
            cmd = [
                "dig", "@127.0.0.1", "-p", str(self.port),
                "google.com", "+short", "+time=3", "+tries=2"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except:
            return False

    def query_domain(self, domain):
        """查询域名解析结果"""
        try:
            cmd = [
                "dig", "@127.0.0.1", "-p", str(self.port),
                domain, "+short", "+time=3", "+tries=1"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.DNS_TIMEOUT
            )

            if result.returncode == 0 and result.stdout.strip():
                return True
            return False
        except:
            return False

# DNS验证器
class DNSValidator:
    def __init__(self, smartdns_manager):
        self.smartdns = smartdns_manager
        self.cache = {}
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'cached': 0,
            'smartdns_queries': 0,
            'fallback_queries': 0
        }

    async def validate_domain(self, domain):
        """验证域名有效性"""
        self.stats['total'] += 1

        # 检查缓存
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]

        # 使用SmartDNS验证
        if Config.USE_SMARTDNS and self.smartdns:
            self.stats['smartdns_queries'] += 1
            result = self.smartdns.query_domain(domain)
        else:
            # 备用验证方法
            self.stats['fallback_queries'] += 1
            result = await self.fallback_validate(domain)

        # 缓存结果
        self.cache[domain] = result

        if result:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1

        return result

    async def fallback_validate(self, domain):
        """备用域名验证方法"""
        try:
            # 使用系统DNS解析
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: socket.getaddrinfo(domain, None, family=socket.AF_INET)
            )
            return bool(result)
        except:
            return False

    def get_stats(self):
        """获取统计信息"""
        return self.stats

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
        self.validator = DNSValidator(self.smartdns)

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
                logger.warning("SmartDNS启动失败，将使用备用验证方法")

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

    def read_rules(self, file_path):
        """读取规则文件"""
        rules = []
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rules = f.readlines()
                logger.info(f"从 {file_path.name} 读取 {len(rules)} 条规则")
            except Exception as e:
                logger.error(f"读取文件 {file_path} 失败: {e}")
        else:
            logger.warning(f"文件不存在: {file_path}")

        return rules

    async def validate_rules(self, rules):
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

    async def validate_domains_batch(self, domains):
        """批量验证域名"""
        valid_domains = set()
        total = len(domains)

        if total == 0:
            return valid_domains

        # 分批处理
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [self.validator.validate_domain(domain) for domain in batch]
            results = await asyncio.gather(*tasks)

            for j, result in enumerate(results):
                if result:
                    valid_domains.add(batch[j])

            # 输出进度
            processed = min(i + Config.BATCH_SIZE, total)
            logger.info(f"进度: {processed}/{total} 域名")

        logger.info(f"验证完成: 有效 {len(valid_domains)}/{total} 域名")
        return valid_domains

    def save_rules(self, rules, output_path, input_path):
        """保存规则到文件"""
        try:
            # 创建备份
            if input_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = Config.BACKUP_DIR / f"{input_path.stem}_backup_{timestamp}.txt"
                backup_file.write_text(input_path.read_text())

            # 保存新规则
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(rules)

            logger.info(f"已保存 {len(rules)} 条规则到 {output_path}")
        except Exception as e:
            logger.error(f"保存规则失败: {e}")

    def print_stats(self, elapsed):
        """输出统计信息"""
        stats = self.validator.get_stats()

        logger.info("\n===== 处理统计 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")
        logger.info(f"SmartDNS查询: {stats['smartdns_queries']} 次")
        logger.info(f"备用查询: {stats['fallback_queries']} 次")

# 主函数
async def main():
    cleaner = RuleCleaner()
    await cleaner.process()

if __name__ == '__main__':
    asyncio.run(main())