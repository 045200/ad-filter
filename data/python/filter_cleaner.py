#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard/AdGuard Home规则清理器 - 专注于去除过期无效域名
专为GitHub Actions环境优化
借鉴217heidai/anti-ad项目策略
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
    INPUT_BLOCKLIST = FILTER_DIR / "adblock_filter.txt"  # 输入规则文件
    OUTPUT_BLOCKLIST = FILTER_DIR / "adblock.txt"        # 输出清理后的规则文件

    # SmartDNS配置
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5353))

    # 性能配置
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 20))     # 并发查询数量
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 300))      # 每批处理域名数量
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 6))      # DNS查询超时（秒）

    # 缓存配置
    CACHE_FILE = FILTER_DIR / "domain_cache.json"
    CACHE_TTL = 86400  # 缓存有效期24小时

# 检查是否在GitHub Actions环境中
IS_GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# 日志配置
def setup_logger():
    logger = logging.getLogger('AdGuardCleaner')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
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

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        self.port = Config.SMARTDNS_PORT
        self.started = False

    def generate_config(self):
        """生成SmartDNS配置文件（包含国内外DNS服务器）"""
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
        logger.info("SmartDNS配置文件生成完成")

    def start(self):
        """启动SmartDNS服务"""
        self.generate_config()
        try:
            cmd = [Config.SMARTDNS_BIN, "-c", str(Config.SMARTDNS_CONFIG_FILE), "-x"]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(2)  # 等待服务启动
            if self.test_connection():
                logger.info("SmartDNS服务启动成功")
                self.started = True
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
            self.started = False

    def test_connection(self):
        """测试SmartDNS连接"""
        try:
            cmd = ["dig", "@127.0.0.1", "-p", str(self.port), "google.com", "+short", "+time=3", "+tries=2"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and result.stdout.strip()
        except:
            return False

    def query_domain(self, domain):
        """使用SmartDNS查询域名"""
        try:
            cmd = ["dig", "@127.0.0.1", "-p", str(self.port), domain, "+short", "+time=3", "+tries=1"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=Config.DNS_TIMEOUT)
            return result.returncode == 0 and result.stdout.strip()
        except:
            return False

# 规则处理器
class RuleProcessor:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._compile_patterns()
        return cls._instance

    def _compile_patterns(self):
        """预编译正则表达式模式，清晰区分可验证与不可验证规则"""
        self.validatable_patterns = {
            'domain_rule': re.compile(r'^\|{1,2}([a-zA-Z0-9.-]+)[\^\|\/]'),
            'domain_with_modifiers': re.compile(r'^\|{1,2}([a-zA-Z0-9.-]+)[\^\|\/].*?\$[a-z,-]+'),
            'hosts_format': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+)$'),
        }
        self.non_validatable_patterns = {
            'comment': re.compile(r'^[!#]'),
            'empty': re.compile(r'^\s*$'),
            'regex_rule': re.compile(r'^/.*/$'),
            'exception_rule': re.compile(r'^@@'),
            'script_rule': re.compile(r'#%#'),
            'element_hiding': re.compile(r'#@?#'),
            'html_filter': re.compile(r'\$\$'),
        }
        self.valid_modifiers = {
            'domain', 'third-party', 'script', 'stylesheet', 'image', 'object',
            'xmlhttprequest', 'websocket', 'popup', 'document', 'elemhide', 'generichide', 'important'
        }

    def preprocess_rules(self, rules: List[str]) -> List[str]:
        """
        预处理规则：清洗注释、空行等[citation:4]
        返回需要进一步验证的规则和可直接保留的规则
        """
        validatable_rules = []
        keep_rules = []

        for rule in rules:
            rule_stripped = rule.strip()
            if not rule_stripped:
                continue

            # 检查是否为不可验证规则（直接保留）
            skip_validation = False
            for pattern in self.non_validatable_patterns.values():
                if pattern.match(rule_stripped):
                    keep_rules.append(rule)
                    skip_validation = True
                    break
            if skip_validation:
                continue

            # 检查是否为可验证的域名规则
            domain_extracted = False
            for pattern in self.validatable_patterns.values():
                match = pattern.match(rule_stripped)
                if match:
                    domain = match.group(1)
                    # 检查修饰符是否支持验证
                    if not self._has_unsupported_modifiers(rule_stripped):
                        validatable_rules.append((rule, domain))
                    else:
                        keep_rules.append(rule)  # 有不支持修饰符的规则也直接保留
                    domain_extracted = True
                    break

            # 未匹配任何模式的规则直接保留
            if not domain_extracted:
                keep_rules.append(rule)

        return validatable_rules, keep_rules

    def _has_unsupported_modifiers(self, rule: str) -> bool:
        """检查规则是否包含不支持的修饰符（这些规则不进行DNS验证）"""
        modifier_match = re.search(r'\$([^,\s]+)', rule)
        if not modifier_match:
            return False
        modifiers = modifier_match.group(1).split(',')
        for modifier in modifiers:
            if modifier.startswith('~'):
                modifier = modifier[1:]
            if '=' in modifier:
                modifier = modifier.split('=')[0]
            if modifier not in self.valid_modifiers:
                return True
        return False

# DNS验证器
class DNSValidator:
    def __init__(self, smartdns_manager: SmartDNSManager):
        self.smartdns = smartdns_manager
        self.cache = self._load_cache()
        self.stats = {'total': 0, 'valid': 0, 'invalid': 0, 'cached': 0}

    def _load_cache(self) -> Dict[str, Tuple[bool, float]]:
        """加载域名缓存"""
        if Config.CACHE_FILE.exists():
            try:
                with open(Config.CACHE_FILE, 'r') as f:
                    cached_data = json.load(f)
                    # 清理过期缓存
                    current_time = time.time()
                    return {domain: (result, timestamp) for domain, (result, timestamp) in cached_data.items() if current_time - timestamp < Config.CACHE_TTL}
            except:
                return {}
        return {}

    def _save_cache(self):
        """保存域名缓存"""
        with open(Config.CACHE_FILE, 'w') as f:
            json.dump(self.cache, f)

    async def validate_domain(self, domain: str) -> bool:
        """验证域名有效性（使用缓存和SmartDNS）"""
        self.stats['total'] += 1
        current_time = time.time()

        # 检查缓存
        if domain in self.cache:
            result, timestamp = self.cache[domain]
            if current_time - timestamp < Config.CACHE_TTL:
                self.stats['cached'] += 1
                return result

        # 使用SmartDNS查询
        if self.smartdns.started:
            valid = self.smartdns.query_domain(domain)
        else:
            # 备用方案：使用系统解析
            valid = await self._fallback_validate(domain)

        # 更新缓存和统计
        self.cache[domain] = (valid, current_time)
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1

        return valid

    async def _fallback_validate(self, domain: str) -> bool:
        """备用验证方案"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, None, family=socket.AF_INET))
            return True
        except:
            return False

    def get_stats(self):
        """获取统计信息"""
        return self.stats

    def __del__(self):
        """对象销毁时保存缓存"""
        self._save_cache()

# 主处理器
class RuleCleaner:
    def __init__(self):
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.smartdns = SmartDNSManager()
        self.processor = RuleProcessor()
        self.validator = DNSValidator(self.smartdns)

    async def initialize(self):
        """初始化"""
        log_group("启动SmartDNS服务")
        if not self.smartdns.start():
            logger.warning("SmartDNS启动失败，将使用备用验证方法")
        end_group()

    async def process_rules(self):
        """处理规则文件主流程"""
        log_group("开始处理规则文件")
        start_time = time.time()

        try:
            # 读取规则
            rules = self._read_rules(Config.INPUT_BLOCKLIST)
            if not rules:
                logger.error("未读取到规则，请检查输入文件")
                return

            # 预处理规则
            validatable_rules, keep_rules = self.processor.preprocess_rules(rules)
            logger.info(f"总规则数: {len(rules)}, 需验证规则: {len(validatable_rules)}, 直接保留规则: {len(keep_rules)}")

            # 提取待验证域名
            domains_to_validate = list(set(domain for _, domain in validatable_rules))  # 去重
            logger.info(f"唯一待验证域名数: {len(domains_to_validate)}")

            # 验证域名
            valid_domains = await self._validate_domains(domains_to_validate)

            # 构建有效规则列表
            valid_rules = keep_rules
            for rule, domain in validatable_rules:
                if domain in valid_domains:
                    valid_rules.append(rule)

            # 保存规则
            self._save_rules(valid_rules, Config.OUTPUT_BLOCKLIST)

            # 输出统计
            self._print_stats(start_time, len(valid_rules))

        finally:
            log_group("停止SmartDNS服务")
            self.smartdns.stop()
            end_group()

    def _read_rules(self, file_path: Path) -> List[str]:
        """读取规则文件"""
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.readlines()
        else:
            logger.warning(f"输入文件不存在: {file_path}")
            return []

    async def _validate_domains(self, domains: List[str]) -> Set[str]:
        """批量验证域名"""
        valid_domains = set()
        total = len(domains)
        if total == 0:
            return valid_domains

        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)
        async def validate_with_semaphore(domain):
            async with semaphore:
                return await self.validator.validate_domain(domain)

        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [validate_with_semaphore(domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for j, result in enumerate(results):
                if isinstance(result, bool) and result:
                    valid_domains.add(batch[j])

            processed = min(i + Config.BATCH_SIZE, total)
            if processed % 1000 == 0 or processed == total:  # 减少进度日志输出
                logger.info(f"域名验证进度: {processed}/{total}")

        logger.info(f"域名验证完成: 有效 {len(valid_domains)}/{total}")
        return valid_domains

    def _save_rules(self, rules: List[str], output_path: Path):
        """保存规则到文件"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(rules)
        logger.info(f"规则保存完成: {output_path}")

    def _print_stats(self, start_time: float, valid_rule_count: int):
        """输出统计信息"""
        elapsed = time.time() - start_time
        stats = self.validator.get_stats()
        log_group("处理统计信息")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"总处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")
        logger.info(f"最终保留规则数: {valid_rule_count} 条")
        end_group()

# 主函数
async def main():
    cleaner = RuleCleaner()
    await cleaner.initialize()
    await cleaner.process_rules()

if __name__ == '__main__':
    asyncio.run(main())