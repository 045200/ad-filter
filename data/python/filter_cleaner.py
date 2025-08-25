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

    # 输入输出路径 - 统一为/data/filter/
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

    # 规则源路径
    SMARTDNS_SOURCES_DIR = BASE_DIR / "data" / "sources"

    # 备份路径
    BACKUP_DIR = FILTER_DIR / "backups"

    # 缓存配置
    CACHE_DIR = BASE_DIR / "data" / "cache"
    CACHE_TTL = 86400  # 24小时

    # 性能配置 - 优化参数
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 16))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 100))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 2000))
    MAX_MEMORY_PERCENT = int(os.getenv('MAX_MEMORY_PERCENT', 80))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 3))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 1))

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

# 进度跟踪器
class ProgressTracker:
    def __init__(self):
        self.progress_file = Config.CACHE_DIR / "progress.json"
        self.processed_domains = set()
        
        # 确保缓存目录存在
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        
        if self.progress_file.exists():
            try:
                with open(self.progress_file, 'r') as f:
                    data = json.load(f)
                    self.processed_domains = set(data.get('processed_domains', []))
                logger.info(f"从进度文件加载了 {len(self.processed_domains)} 个已处理域名")
            except Exception as e:
                logger.error(f"加载进度文件失败: {e}")
                self.processed_domains = set()
    
    def save_progress(self, domains):
        self.processed_domains.update(domains)
        try:
            with open(self.progress_file, 'w') as f:
                json.dump({'processed_domains': list(self.processed_domains)}, f)
        except Exception as e:
            logger.error(f"保存进度文件失败: {e}")
    
    def is_processed(self, domain):
        return domain in self.processed_domains

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
            'adguard_css': re.compile(r'.*#\$?#.*'),
            'adguard_js': re.compile(r'.*#@?#.*'),
            'adguard_csp': re.compile(r'.*\$csp='),
            'adguard_redirect': re.compile(r'.*\$redirect(?:-rule)?='),

            # 元素隐藏规则
            'element_hiding': re.compile(r'.*##.*'),
            'element_exception': re.compile(r'.*#@#.*'),

            # 复杂模式
            'regex_pattern': re.compile(r'^/.*/$'),
            'wildcard_pattern': re.compile(r'.*[*^].*'),
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

        # 检查是否为元素隐藏规则（不支持）
        if (self.regex_patterns['element_hiding'].match(rule) or 
            self.regex_patterns['element_exception'].match(rule)):
            logger.debug(f"跳过元素隐藏规则: {rule}")
            return None, None

        # 检查是否为CSS/JS规则（不支持）
        if (self.regex_patterns['adguard_css'].match(rule) or 
            self.regex_patterns['adguard_js'].match(rule)):
            logger.debug(f"跳过CSS/JS规则: {rule}")
            return None, None

        # 检查是否为CSP规则（不支持）
        if self.regex_patterns['adguard_csp'].match(rule):
            logger.debug(f"跳过CSP规则: {rule}")
            return None, None

        # 检查是否为重定向规则（不支持）
        if self.regex_patterns['adguard_redirect'].match(rule):
            logger.debug(f"跳过重定向规则: {rule}")
            return None, None

        # 检查是否为正则表达式规则（不支持）
        if self.regex_patterns['regex_pattern'].match(rule):
            logger.debug(f"跳过正则表达式规则: {rule}")
            return None, None

        # 提取域名
        domain = None
        for pattern_name in ['domain', 'hosts', 'adguard_domain']:
            match = self.regex_patterns[pattern_name].match(rule)
            if match:
                domain = match.group(1)
                break

        if not domain:
            # 尝试处理通配符模式
            if self.regex_patterns['wildcard_pattern'].match(rule):
                logger.debug(f"跳过通配符规则: {rule}")
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
            else:
                logger.debug(f"跳过不支持的修饰符: {mod}")

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
                logger.debug(f"从规则提取域名: {rule} -> {domain}")

        return domains

# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        self.port = Config.SMARTDNS_PORT

    def generate_config(self):
        """生成优化的SmartDNS配置文件"""
        config_content = f"""bind 127.0.0.1:{self.port}
bind-tcp 127.0.0.1:{self.port}
cache-size 2048
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level error
log-size 128K
speed-check-mode none  # 禁用速度检查以加快响应
max-reply-ip-num 1  # 只返回一个IP以减少响应大小

# 优化的DNS服务器配置
server 223.5.5.5 -exclude-default-group
server 119.29.29.29 -exclude-default-group
server-tls 1.12.12.12 -exclude-default-group

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

# 异步DNS验证器
class AsyncDNSValidator:
    def __init__(self, smartdns_manager):
        self.smartdns = smartdns_manager
        self.resolver = aiodns.DNSResolver()
        self.resolver.nameservers = ['127.0.0.1']
        self.resolver.port = Config.SMARTDNS_PORT
        self.cache = {}
        self.semaphore = asyncio.Semaphore(Config.DNS_WORKERS)
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
            result = await self._async_query_domain(domain)
        else:
            # 备用验证方法
            self.stats['fallback_queries'] += 1
            result = await self._fallback_validate(domain)

        # 缓存结果
        self.cache[domain] = result

        if result:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1

        return result

    async def _async_query_domain(self, domain):
        """使用aiodns进行异步DNS查询"""
        async with self.semaphore:
            try:
                # 查询A记录
                result = await asyncio.wait_for(
                    self.resolver.query(domain, 'A'),
                    timeout=Config.DNS_TIMEOUT
                )
                return bool(result)
            except (aiodns.error.DNSError, asyncio.TimeoutError, Exception):
                return False

    async def _fallback_validate(self, domain):
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
        self.smartdns = SmartDNSManager()
        self.validator = AsyncDNSValidator(self.smartdns)
        self.processor = EnhancedRuleProcessor()
        self.progress = ProgressTracker()

        # 确保目录存在
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
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
            domain, modifiers = self.processor.parse_rule(rule)
            if domain:
                # 跳过已处理的域名
                if not self.progress.is_processed(domain):
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

        # 更新进度
        self.progress.save_progress(domains_to_validate)

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