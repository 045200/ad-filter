#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS的Adblock规则清理器
修复DNS查询问题，确保正确验证域名有效性
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
from typing import Set, List, Dict, Optional, Tuple
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

    # 缓存配置
    CACHE_DIR = BASE_DIR / "data" / "cache"
    BACKUP_DIR = FILTER_DIR / "backups"

    # 性能配置
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 16))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 50))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 1000))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 5))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 2))

    # 功能开关
    USE_SMARTDNS = os.getenv('USE_SMARTDNS', 'true').lower() == 'true'

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

# 规则处理器
class RuleProcessor:
    def __init__(self):
        self.patterns = {
            'domain': re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/]'),
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$'),
            'comment': re.compile(r'^[!#]'),
            'adguard_domain': re.compile(r'^@@?\|\|?([\w.-]+)[\^\$\|\/]'),
        }

    def parse_rule(self, rule: str) -> Optional[str]:
        rule = rule.strip()
        
        if not rule or self.patterns['comment'].match(rule):
            return None
            
        for pattern_name in ['domain', 'hosts', 'adguard_domain']:
            match = self.patterns[pattern_name].match(rule)
            if match:
                return match.group(1)
                
        return None

# DNS验证器
class DNSValidator:
    def __init__(self):
        self.cache = {}
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'cached': 0
        }
        
    async def validate_domain(self, domain):
        self.stats['total'] += 1
        
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]
            
        # 使用系统DNS进行验证
        valid = await self._validate_with_system_dns(domain)
        
        self.cache[domain] = valid
        
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
            
        return valid
        
    async def _validate_with_system_dns(self, domain):
        """使用系统DNS验证域名"""
        loop = asyncio.get_event_loop()
        
        for _ in range(Config.DNS_RETRIES):
            try:
                # 尝试解析A记录
                result = await loop.run_in_executor(
                    None, 
                    lambda: socket.getaddrinfo(domain, None, family=socket.AF_INET)
                )
                if result:
                    return True
                    
                # 尝试解析AAAA记录
                result = await loop.run_in_executor(
                    None, 
                    lambda: socket.getaddrinfo(domain, None, family=socket.AF_INET6)
                )
                if result:
                    return True
                    
            except (socket.gaierror, OSError, Exception):
                pass
                
            # 短暂等待后重试
            await asyncio.sleep(0.1)
            
        return False

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        
    def generate_config(self):
        """生成SmartDNS配置文件"""
        config_content = f"""bind 127.0.0.1:{Config.SMARTDNS_PORT}
bind-tcp 127.0.0.1:{Config.SMARTDNS_PORT}
cache-size 2048
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level error
log-size 128K
speed-check-mode none

# 国内DNS服务器
server 223.5.5.5
server 119.29.29.29
server-tls 1.12.12.12

# 国际DNS服务器
server-tls 1.1.1.1 -group overseas -exclude-default-group
server-tls 8.8.8.8 -group overseas -exclude-default-group

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
            time.sleep(3)

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
            # 使用nslookup测试连接
            cmd = [
                "nslookup", "-timeout=3", 
                "google.com", "127.0.0.1", str(Config.SMARTDNS_PORT)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            return result.returncode == 0 and "Name:" in result.stdout
        except:
            return False

# 主处理器
class RuleCleaner:
    def __init__(self):
        self.validator = DNSValidator()
        self.processor = RuleProcessor()
        self.smartdns = SmartDNSManager()

        # 确保目录存在
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def process(self):
        """处理规则文件"""
        logger.info("开始处理规则文件")
        start_time = time.time()

        # 启动SmartDNS（即使不使用它进行验证，也启动以保持配置一致性）
        smartdns_started = self.smartdns.start()

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
            domain = self.processor.parse_rule(rule)
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

        # 创建信号量限制并发数
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)

        async def validate_with_semaphore(domain):
            async with semaphore:
                return await self.validator.validate_domain(domain)

        # 分批处理
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [validate_with_semaphore(domain) for domain in batch]
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
        stats = self.validator.stats

        logger.info("\n===== 处理统计 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")

# 主函数
async def main():
    cleaner = RuleCleaner()
    await cleaner.process()

if __name__ == '__main__':
    asyncio.run(main())