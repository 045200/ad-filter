#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS的Adblock规则清理器
专为GitHub Actions环境优化
支持SmartDNS规则源引入
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
from pathlib import Path
from typing import Set, List, Dict, Optional
from datetime import datetime
from collections import OrderedDict
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
    
    # SmartDNS配置
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5353))
    
    # 规则源路径
    SMARTDNS_SOURCES_DIR = BASE_DIR / "data" / "sources"
    
    # 备份与白名单
    BACKUP_DIR = BASE_DIR / "data" / "mod" / "backups"
    WHITELIST_FILE = BASE_DIR / "data" / "filter" / "allow.txt"
    
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

# 国内DNS服务器
server 223.5.5.5
server 119.29.29.29
server-tls 1.12.12.12
server-https https://doh.pub/dns-query

# 国际DNS服务器
server-tls 1.1.1.1 -group overseas -exclude-default-group
server-tls 8.8.8.8 -group overseas -exclude-default-group
server-https https://cloudflare-dns.com/dns-query -group overseas -exclude-default-group

# 域名分流规则
nameserver /cn/223.5.5.5
nameserver /taobao.com/223.5.5.5
nameserver /qq.com/119.29.29.29
nameserver /google.com/overseas
nameserver /facebook.com/overseas
nameserver /twitter.com/overseas
nameserver /youtube.com/overseas
"""
        
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

# 规则处理器
class RuleProcessor:
    def __init__(self):
        self.whitelist = self.load_whitelist()
        self.regex_patterns = {
            'domain': re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]'),
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$'),
            'comment': re.compile(r'^[!#]'),
            'empty': re.compile(r'^\s*$'),
            'adguard_modifiers': re.compile(r'\$[^,\s]+')  # 匹配AdGuard修饰符
        }
    
    def load_whitelist(self):
        """加载白名单"""
        whitelist = set()
        if Config.WHITELIST_FILE.exists():
            try:
                with open(Config.WHITELIST_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            whitelist.add(line)
                logger.info(f"已加载 {len(whitelist)} 个白名单域名")
            except Exception as e:
                logger.error(f"加载白名单失败: {e}")
        return whitelist
    
    def extract_domain(self, rule):
        """从规则中提取域名"""
        rule = rule.strip()
        
        # 跳过注释和空行
        if self.regex_patterns['comment'].match(rule) or self.regex_patterns['empty'].match(rule):
            return None
        
        # 移除AdGuard修饰符
        rule = self.regex_patterns['adguard_modifiers'].sub('', rule)
        
        # 尝试匹配各种规则格式
        for pattern_name, pattern in self.regex_patterns.items():
            if pattern_name in ['domain', 'hosts']:
                match = pattern.match(rule)
                if match:
                    domain = match.group(1)
                    if '$' in domain:
                        domain = domain.split('$')[0]
                    return domain
        return None
    
    def is_whitelisted(self, domain):
        """检查域名是否在白名单中"""
        return domain in self.whitelist
    
    def load_smartdns_rules(self):
        """加载SmartDNS规则源中的域名"""
        domains = set()
        
        if not Config.PROCESS_SMARTDNS_RULES:
            return domains
            
        if Config.SMARTDNS_SOURCES_DIR.exists():
            for file_path in Config.SMARTDNS_SOURCES_DIR.glob("*_processed.txt"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            domain = line.strip()
                            if domain and not domain.startswith('#'):
                                domains.add(domain)
                    logger.info(f"从 {file_path.name} 加载了 {len(domains)} 个域名")
                except Exception as e:
                    logger.error(f"加载SmartDNS规则文件 {file_path} 失败: {e}")
        
        return domains

# 主处理器
class RuleCleaner:
    def __init__(self):
        self.smartdns = SmartDNSManager()
        self.validator = DNSValidator(self.smartdns)
        self.processor = RuleProcessor()
        
        # 确保目录存在
        Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    async def process(self):
        """处理规则文件"""
        logger.info("开始处理规则文件")
        start_time = time.time()
        
        # 启动SmartDNS
        smartdns_started = False
        if Config.USE_SMARTDNS:
            smartdns_started = self.smartdns.start()
            if not smartdns_started:
                logger.warning("SmartDNS启动失败，将使用备用验证方法")
        
        try:
            # 读取并处理规则文件
            rules = self.read_rules()
            logger.info(f"共读取 {len(rules)} 条规则")
            
            # 加载SmartDNS规则源中的域名
            smartdns_domains = self.processor.load_smartdns_rules()
            logger.info(f"从SmartDNS规则源加载了 {len(smartdns_domains)} 个域名")
            
            # 提取并验证域名
            valid_rules = await self.validate_rules(rules, smartdns_domains)
            
            # 保存结果
            self.save_rules(valid_rules)
            
            # 输出统计信息
            elapsed = time.time() - start_time
            self.print_stats(elapsed)
            
        finally:
            # 停止SmartDNS
            if smartdns_started:
                self.smartdns.stop()
    
    def read_rules(self):
        """读取规则文件"""
        rules = []
        for file_path in Config.INPUT_DIR.glob("adblock_filter.txt"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rules.extend(f.readlines())
                logger.info(f"从 {file_path.name} 读取规则")
            except Exception as e:
                logger.error(f"读取文件 {file_path} 失败: {e}")
        return rules
    
    async def validate_rules(self, rules, smartdns_domains):
        """验证规则有效性"""
        valid_rules = []
        domains_to_validate = set()
        domain_to_rules = {}
        
        # 提取域名并分组
        for rule in rules:
            domain = self.processor.extract_domain(rule)
            if domain:
                # 检查白名单
                if self.processor.is_whitelisted(domain):
                    valid_rules.append(rule)
                    continue
                
                domains_to_validate.add(domain)
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = []
                domain_to_rules[domain].append(rule)
            else:
                # 保留无法提取域名的规则
                valid_rules.append(rule)
        
        # 添加SmartDNS规则源中的域名
        for domain in smartdns_domains:
            if domain not in domains_to_validate and not self.processor.is_whitelisted(domain):
                domains_to_validate.add(domain)
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = [f"||{domain}^"]
        
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
    
    def save_rules(self, rules):
        """保存规则到文件"""
        try:
            # 创建备份
            if Config.CLEANED_FILE.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = Config.BACKUP_DIR / f"adblock_backup_{timestamp}.txt"
                backup_file.write_text(Config.CLEANED_FILE.read_text())
            
            # 保存新规则
            with open(Config.CLEANED_FILE, 'w', encoding='utf-8') as f:
                f.writelines(rules)
            
            logger.info(f"已保存 {len(rules)} 条规则到 {Config.CLEANED_FILE}")
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