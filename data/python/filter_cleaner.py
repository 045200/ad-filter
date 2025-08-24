#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard/AdGuard Home规则清理器
专为GitHub Actions环境优化
使用SmartDNS和多DNS服务器验证去除过期无效域名
"""

import os
import re
import sys
import json
import time
import logging
import asyncio
import aiohttp
import subprocess
import socket
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from datetime import datetime

# 配置类
class Config:
    # 基础路径
    GITHUB_WORKSPACE = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    BASE_DIR = GITHUB_WORKSPACE

    # 输入输出路径
    FILTER_DIR = BASE_DIR / "data" / "filter"
    INPUT_BLOCKLIST = FILTER_DIR / "adblock_filter.txt"
    OUTPUT_BLOCKLIST = FILTER_DIR / "adblock.txt"

    # SmartDNS配置
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5353))

    # 性能配置
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 20))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 300))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 6))

    # 缓存配置
    CACHE_FILE = FILTER_DIR / "domain_cache.json"
    CACHE_TTL = 86400  # 缓存有效期24小时

# 检查是否在GitHub Actions环境中
IS_GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# 日志配置
def setup_logger():
    logger = logging.getLogger('AdGuardCleaner')
    
    # 在GitHub Actions中使用更简化的日志级别
    if IS_GITHUB_ACTIONS:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    
    # 简化日志格式
    if IS_GITHUB_ACTIONS:
        formatter = logging.Formatter('%(levelname)s: %(message)s')
    else:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

logger = setup_logger()

def log_group(title):
    """GitHub Actions日志分组"""
    if IS_GITHUB_ACTIONS:
        print(f"::group::{title}")
    else:
        logger.info(f"=== {title} ===")

def end_group():
    """结束GitHub Actions日志分组"""
    if IS_GITHUB_ACTIONS:
        print("::endgroup::")

def log_info(message):
    """信息日志，在GitHub Actions中简化"""
    if IS_GITHUB_ACTIONS:
        print(f"ℹ️  {message}")
    else:
        logger.info(message)

def log_error(message):
    """错误日志，在GitHub Actions中突出显示"""
    if IS_GITHUB_ACTIONS:
        print(f"::error::{message}")
    else:
        logger.error(message)

def log_warning(message):
    """警告日志，在GitHub Actions中突出显示"""
    if IS_GITHUB_ACTIONS:
        print(f"::warning::{message}")
    else:
        logger.warning(message)

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        self.port = Config.SMARTDNS_PORT
        self.started = False

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

        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(Config.SMARTDNS_CONFIG_FILE, 'w') as f:
            f.write(config_content)

    def start(self):
        """启动SmartDNS服务"""
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
                log_info("SmartDNS服务启动成功")
                self.started = True
                return True
            else:
                log_error("SmartDNS服务启动失败")
                return False

        except Exception as e:
            log_error(f"启动SmartDNS服务时出错: {e}")
            return False

    def stop(self):
        """停止SmartDNS服务"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            log_info("SmartDNS服务已停止")
            self.started = False

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

# AdGuard规则处理器
class AdGuardRuleProcessor:
    def __init__(self):
        # 可验证规则的正则模式（包含域名）
        self.validatable_patterns = {
            # 基本域名规则
            'domain_rule': re.compile(r'^\|{1,2}([a-zA-Z0-9.-]+)[\^\|\/]'),
            # 包含修饰符的域名规则
            'domain_with_modifiers': re.compile(r'^\|{1,2}([a-zA-Z0-9.-]+)[\^\|\/].*?\$[a-z,-]+'),
            # 主机文件格式
            'hosts_format': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+)$'),
        }
        
        # 不可验证规则的正则模式（直接保留）
        self.non_validatable_patterns = {
            # 注释
            'comment': re.compile(r'^[!#]'),
            # 空行
            'empty': re.compile(r'^\s*$'),
            # 正则表达式规则
            'regex_rule': re.compile(r'^/.*/$'),
            # 异常规则
            'exception_rule': re.compile(r'^@@'),
            # 脚本规则
            'script_rule': re.compile(r'#%#'),
            # 元素隐藏规则
            'element_hiding': re.compile(r'#@?#'),
            # HTML过滤规则
            'html_filter': re.compile(r'\$\$'),
        }
        
        # 支持的修饰符（可验证）
        self.valid_modifiers = {
            'domain', 'third-party', 'script', 'stylesheet', 'image', 
            'object', 'xmlhttprequest', 'websocket', 'popup', 'document',
            'elemhide', 'generichide', 'important'
        }

    def categorize_rule(self, rule: str) -> Tuple[Optional[str], str]:
        """
        分类规则并提取域名（如果可验证）
        返回值: (domain, category)
        """
        rule = rule.strip()
        
        # 检查不可验证规则
        for category, pattern in self.non_validatable_patterns.items():
            if pattern.match(rule):
                return None, category
        
        # 检查可验证规则
        for category, pattern in self.validatable_patterns.items():
            match = pattern.match(rule)
            if match:
                domain = match.group(1)
                
                # 检查修饰符是否支持验证
                if self._has_unsupported_modifiers(rule):
                    return None, "unsupported_modifiers"
                    
                return domain, category
        
        # 默认分类为未知（保留）
        return None, "unknown"

    def _has_unsupported_modifiers(self, rule: str) -> bool:
        """检查规则是否包含不支持的修饰符"""
        # 提取修饰符部分
        modifier_match = re.search(r'\$([^,\s]+)', rule)
        if not modifier_match:
            return False
            
        modifiers = modifier_match.group(1).split(',')
        
        # 检查是否有不支持的修饰符
        for modifier in modifiers:
            # 处理否定修饰符 (~modifier)
            if modifier.startswith('~'):
                modifier = modifier[1:]
                
            # 处理键值对修饰符 (key=value)
            if '=' in modifier:
                modifier = modifier.split('=')[0]
                
            if modifier not in self.valid_modifiers:
                return True
                
        return False

# DNS验证器
class DNSValidator:
    def __init__(self, smartdns_manager):
        self.smartdns = smartdns_manager
        self.cache = self._load_cache()
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'cached': 0,
            'smartdns_queries': 0,
            'dig_queries': 0,
            'system_queries': 0
        }
        
        # 多DNS服务器配置（不依赖地理信息）
        self.dns_servers = [
            "1.1.1.1",        # Cloudflare (全球)
            "8.8.8.8",        # Google (全球)
            "114.114.114.114", # 114DNS (中国)
            "223.5.5.5",      # AliDNS (中国)
        ]

    def _load_cache(self):
        """加载域名缓存"""
        if Config.CACHE_FILE.exists():
            try:
                with open(Config.CACHE_FILE, 'r') as f:
                    cached_data = json.load(f)
                    # 清理过期缓存
                    current_time = time.time()
                    return {domain: (result, timestamp) for domain, (result, timestamp) in cached_data.items() 
                            if current_time - timestamp < Config.CACHE_TTL}
            except Exception as e:
                log_error(f"加载缓存失败: {e}")
        return {}

    def _save_cache(self):
        """保存域名缓存"""
        try:
            with open(Config.CACHE_FILE, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            log_error(f"保存缓存失败: {e}")

    async def validate_domain(self, domain):
        """验证域名有效性 - 使用多种验证方法"""
        self.stats['total'] += 1
        current_time = time.time()

        # 检查缓存
        if domain in self.cache:
            result, timestamp = self.cache[domain]
            if current_time - timestamp < Config.CACHE_TTL:
                self.stats['cached'] += 1
                if result:
                    self.stats['valid'] += 1
                else:
                    self.stats['invalid'] += 1
                return result

        # 1. 首先尝试SmartDNS（如果可用）
        if self.smartdns.started:
            self.stats['smartdns_queries'] += 1
            result = self.smartdns.query_domain(domain)
            if result:
                self.cache[domain] = (True, current_time)
                self.stats['valid'] += 1
                return True

        # 2. 尝试多个DNS服务器
        for dns_server in self.dns_servers:
            self.stats['dig_queries'] += 1
            result = await self._dig_query_async(domain, dns_server)
            if result:
                self.cache[domain] = (True, current_time)
                self.stats['valid'] += 1
                return True

        # 3. 最后尝试系统DNS
        self.stats['system_queries'] += 1
        result = await self._system_query_async(domain)
        self.cache[domain] = (result, current_time)
        
        if result:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
            
        return result

    async def _dig_query_async(self, domain, dns_server):
        """异步执行dig查询"""
        try:
            cmd = [
                "dig", f"@{dns_server}",
                domain, "+short", "+time=3", "+tries=1"
            ]

            # 异步执行dig命令
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return process.returncode == 0 and stdout.strip()
        except:
            return False

    async def _system_query_async(self, domain):
        """异步执行系统DNS查询"""
        try:
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

    def save_cache(self):
        """保存缓存到文件"""
        self._save_cache()

# 主处理器
class RuleCleaner:
    def __init__(self):
        # 确保目录存在
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # 初始化组件
        self.smartdns = SmartDNSManager()
        self.processor = AdGuardRuleProcessor()

    async def initialize(self):
        """异步初始化"""
        # 启动SmartDNS
        smartdns_started = self.smartdns.start()
        
        # 初始化验证器
        self.validator = DNSValidator(self.smartdns)

    async def process(self):
        """处理规则文件"""
        log_group("开始处理AdGuard规则文件")
        start_time = time.time()

        try:
            # 处理黑名单文件
            log_info("处理黑名单文件...")
            blocklist_rules = self.read_rules(Config.INPUT_BLOCKLIST)
            valid_blocklist_rules = await self.validate_rules(blocklist_rules)
            self.save_rules(valid_blocklist_rules, Config.OUTPUT_BLOCKLIST)

            # 输出统计信息
            elapsed = time.time() - start_time
            self.print_stats(elapsed)

        finally:
            # 停止SmartDNS
            self.smartdns.stop()
            # 保存缓存
            self.validator.save_cache()
            end_group()

    def read_rules(self, file_path):
        """读取规则文件"""
        rules = []
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rules = f.readlines()
                log_info(f"从 {file_path.name} 读取 {len(rules)} 条规则")
            except Exception as e:
                log_error(f"读取文件 {file_path} 失败: {e}")
        else:
            log_warning(f"文件不存在: {file_path}")

        return rules

    async def validate_rules(self, rules):
        """验证规则有效性"""
        valid_rules = []
        domains_to_validate = {}
        rule_categories = {}
        
        # 分类规则
        for rule in rules:
            domain, category = self.processor.categorize_rule(rule)
            rule_categories[rule] = category
            
            if domain:
                if domain not in domains_to_validate:
                    domains_to_validate[domain] = []
                domains_to_validate[domain].append(rule)
            else:
                # 保留不可验证的规则
                valid_rules.append(rule)

        log_info(f"需要验证 {len(domains_to_validate)} 个域名")

        # 批量验证域名
        valid_domains = await self.validate_domains_batch(list(domains_to_validate.keys()))

        # 构建有效规则列表
        for domain in valid_domains:
            valid_rules.extend(domains_to_validate[domain])

        return valid_rules

    async def validate_domains_batch(self, domains):
        """批量验证域名"""
        valid_domains = set()
        total = len(domains)

        if total == 0:
            return valid_domains

        # 使用信号量控制并发量
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)
        
        async def validate_with_semaphore(domain):
            async with semaphore:
                return await self.validator.validate_domain(domain)
        
        # 分批处理避免内存溢出
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [validate_with_semaphore(domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(results):
                if isinstance(result, bool) and result:
                    valid_domains.add(batch[j])
            
            # 进度报告（在GitHub Actions中减少输出频率）
            processed = min(i + Config.BATCH_SIZE, total)
            if processed % 1000 == 0 or processed == total:
                log_info(f"域名验证进度: {processed}/{total}")

        log_info(f"验证完成: 有效 {len(valid_domains)}/{total} 域名")
        return valid_domains

    def save_rules(self, rules, output_path):
        """保存规则到文件"""
        try:
            # 确保目录存在
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存规则
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(rules)

            log_info(f"已保存 {len(rules)} 条规则到 {output_path}")
        except Exception as e:
            log_error(f"保存规则失败: {e}")

    def print_stats(self, elapsed):
        """输出处理统计信息"""
        stats = self.validator.get_stats()
        
        log_group("处理统计信息")
        log_info(f"总耗时: {elapsed:.2f} 秒")
        log_info(f"处理域名: {stats['total']} 个")
        log_info(f"有效域名: {stats['valid']} 个")
        log_info(f"无效域名: {stats['invalid']} 个")
        log_info(f"缓存命中: {stats['cached']} 次")
        log_info(f"SmartDNS查询: {stats['smartdns_queries']} 次")
        log_info(f"Dig查询: {stats['dig_queries']} 次")
        log_info(f"系统查询: {stats['system_queries']} 次")
        end_group()

# 主函数
async def main():
    cleaner = RuleCleaner()
    await cleaner.initialize()
    await cleaner.process()

if __name__ == '__main__':
    asyncio.run(main())