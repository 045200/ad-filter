#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS和aiodns的AdBlock/AdGuard规则清理器
专为GitHub Actions环境优化，支持国内外域名规则
"""

import os
import re
import sys
import time
import logging
import asyncio
import aiodns
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
    INPUT_ALLOWLIST = FILTER_DIR / "allow_filter.txt"
    OUTPUT_BLOCKLIST = FILTER_DIR / "adblock.txt"
    OUTPUT_ALLOWLIST = FILTER_DIR / "allow.txt"

    # SmartDNS配置
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5354))  # 避免53端口冲突
    SMARTDNS_LOG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.log"

    # 缓存与备份
    CACHE_DIR = BASE_DIR / "data" / "cache"
    BACKUP_DIR = FILTER_DIR / "backups"

    # 性能配置
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 30))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 5))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 3))

    # 功能开关
    USE_SMARTDNS = os.getenv('USE_SMARTDNS', 'true').lower() == 'true'


# 日志配置
def setup_logger():
    logger = logging.getLogger('AdblockCleaner')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()


# AdBlock/AdGuard规则处理器
class AdblockRuleProcessor:
    def __init__(self):
        self.patterns = {
            'adblock_domain': re.compile(r'^(?:@@)?\|{1,2}([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$\|\/]'),
            'hosts_format': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])$'),
            'adguard_domain': re.compile(r'^(?:@@)?\|\|([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$]'),
            'comment': re.compile(r'^[!#]'),
            'empty': re.compile(r'^\s*$'),
            'element_hiding': re.compile(r'.*##.*'),
            'element_exception': re.compile(r'.*#@#.*'),
            'script_rule': re.compile(r'.*\$\$.*'),
        }

    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        rule = rule.strip()
        
        # 跳过注释、空行、元素隐藏/脚本规则
        if (not rule or self.patterns['comment'].match(rule) or 
            self.patterns['empty'].match(rule) or self.patterns['element_hiding'].match(rule) or 
            self.patterns['element_exception'].match(rule) or self.patterns['script_rule'].match(rule)):
            return None
            
        # 提取域名
        for pattern_name in ['adblock_domain', 'hosts_format', 'adguard_domain']:
            match = self.patterns[pattern_name].match(rule)
            if match:
                domain = match.group(1)
                if self._is_valid_domain(domain):
                    return domain
                    
        return None
        
    def _is_valid_domain(self, domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            return False
        for label in domain.split('.'):
            if not label or len(label) > 63 or label.startswith('-') or label.endswith('-'):
                return False
        return True


# 高性能DNS验证器（使用aiodns + SmartDNS）
class SmartDNSValidator:
    def __init__(self):
        self.cache = {}
        self.stats = {
            'total': 0, 'valid': 0, 'invalid': 0, 'cached': 0,
            'timeout': 0, 'smartdns_queries': 0, 'system_dns_queries': 0
        }
        # 初始化解析器（默认公共DNS，后续测试后更新）
        self.resolver = aiodns.DNSResolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5', '119.29.29.29']
        self.smartdns_available = None  # 异步测试后赋值

    async def test_smartdns(self) -> bool:
        """异步测试SmartDNS可用性，避免事件循环冲突"""
        if not Config.USE_SMARTDNS:
            self.smartdns_available = False
            return False
            
        try:
            # 使用当前事件循环测试SmartDNS
            test_resolver = aiodns.DNSResolver()
            test_resolver.nameservers = ['127.0.0.1']
            test_resolver.port = Config.SMARTDNS_PORT
            
            # 异步查询已知域名
            result = await asyncio.wait_for(
                test_resolver.query("baidu.com", "A"),
                timeout=3
            )
            
            if result:
                logger.info("SmartDNS可用，将使用SmartDNS进行域名验证")
                self.smartdns_available = True
                # 更新主解析器为SmartDNS
                self.resolver.nameservers = ['127.0.0.1']
                self.resolver.port = Config.SMARTDNS_PORT
                return True
            else:
                logger.warning("SmartDNS测试查询返回空结果")
                self.smartdns_available = False
                return False
                
        except Exception as e:
            logger.warning(f"SmartDNS不可用: {e}")
            self.smartdns_available = False
            logger.info("使用公共DNS进行域名验证")
            return False

    async def validate_domain(self, domain: str) -> bool:
        self.stats['total'] += 1
        
        # 缓存命中
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]
            
        # 异步验证域名
        valid = await self._dns_query(domain)
        self.cache[domain] = valid
        
        # 更新统计
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
            
        return valid
        
    async def _dns_query(self, domain: str) -> bool:
        """异步DNS查询，支持多记录类型重试"""
        record_types = ['A', 'AAAA', 'CNAME']
        
        for record_type in record_types:
            for attempt in range(Config.DNS_RETRIES):
                try:
                    result = await asyncio.wait_for(
                        self.resolver.query(domain, record_type),
                        timeout=Config.DNS_TIMEOUT
                    )
                    if result:
                        # 更新查询统计
                        if self.smartdns_available:
                            self.stats['smartdns_queries'] += 1
                        else:
                            self.stats['system_dns_queries'] += 1
                        return True
                except asyncio.TimeoutError:
                    self.stats['timeout'] += 1
                    if attempt == Config.DNS_RETRIES - 1:
                        logger.debug(f"域名查询超时: {domain}")
                    continue
                except aiodns.error.DNSError as e:
                    if e.args[0] == 4:  # NXDOMAIN（域名不存在）
                        return False
                    logger.debug(f"域名 {domain} DNS错误: {e}")
                    continue
                except Exception as e:
                    logger.debug(f"域名 {domain} 查询异常: {str(e)}")
                    continue
                    
        # 终极备用：系统DNS（异步执行）
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(domain, None, family=socket.AF_INET)
            )
            if result:
                logger.debug(f"域名 {domain} 通过系统DNS验证成功")
                self.stats['system_dns_queries'] += 1
                return True
        except Exception as e:
            logger.debug(f"系统DNS验证 {domain} 失败: {e}")
        
        return False


# SmartDNS管理器（异步化改造）
class SmartDNSManager:
    def __init__(self):
        self.process = None
        
    def generate_config(self):
        """生成SmartDNS分流配置"""
        config_content = f"""bind 127.0.0.1:{Config.SMARTDNS_PORT}
bind-tcp 127.0.0.1:{Config.SMARTDNS_PORT}
cache-size 2048
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level error
log-size 128K
log-file {Config.SMARTDNS_LOG_FILE}
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
nameserver /baidu.com/223.5.5.5
nameserver /aliyun.com/223.5.5.5
nameserver /weibo.com/223.5.5.5
nameserver /google.com/overseas
nameserver /youtube.com/overseas
nameserver /facebook.com/overseas
nameserver /twitter.com/overseas
nameserver /instagram.com/overseas
nameserver /amazon.com/overseas
nameserver /microsoft.com/overseas
nameserver /github.com/overseas
"""
        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(Config.SMARTDNS_CONFIG_FILE, 'w') as f:
            f.write(config_content)
        logger.info("SmartDNS配置文件生成完成")

    async def start(self) -> bool:
        """异步启动SmartDNS（避免同步阻塞）"""
        if not Config.USE_SMARTDNS:
            logger.info("SmartDNS功能已禁用")
            return False
            
        self.generate_config()

        try:
            cmd = [Config.SMARTDNS_BIN, "-c", str(Config.SMARTDNS_CONFIG_FILE), "-x"]
            logger.info(f"启动SmartDNS: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            # 异步等待服务启动（替换time.sleep）
            await asyncio.sleep(3)
            
            # 检查进程状态
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                logger.error(f"SmartDNS进程退出，返回值: {self.process.returncode}")
                if stdout:
                    logger.error(f"STDOUT: {stdout}")
                if stderr:
                    logger.error(f"STDERR: {stderr}")
                return False
                
            # 异步测试连接
            if await self.test_connection():
                logger.info("SmartDNS服务启动成功")
                return True
            else:
                logger.error("SmartDNS启动但无法连接")
                if Config.SMARTDNS_LOG_FILE.exists():
                    try:
                        with open(Config.SMARTDNS_LOG_FILE, 'r') as f:
                            logger.error(f"SmartDNS日志: {f.read()}")
                    except Exception as e:
                        logger.error(f"读取日志失败: {e}")
                return False
                
        except Exception as e:
            logger.error(f"启动SmartDNS出错: {e}")
            return False
            
    async def test_connection(self) -> bool:
        """异步测试SmartDNS连接（避免阻塞事件循环）"""
        try:
            cmd = [
                "dig", "@127.0.0.1", "-p", str(Config.SMARTDNS_PORT),
                "baidu.com", "+short", "+time=3", "+tries=2"
            ]
            
            # 异步执行dig命令
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, text=True
            )
            stdout, stderr = await process.communicate(timeout=5)
            
            success = process.returncode == 0 and len(stdout.strip()) > 0
            if not success:
                logger.warning(f"dig测试失败: {stderr}")
            return success
        except Exception as e:
            logger.error(f"连接测试异常: {e}")
            return False
            
    def stop(self):
        """停止SmartDNS服务"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
                logger.info("SmartDNS服务已停止")
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.warning("强制终止SmartDNS服务")


# 主处理器
class AdblockCleaner:
    def __init__(self):
        self.validator = SmartDNSValidator()
        self.processor = AdblockRuleProcessor()
        self.smartdns = SmartDNSManager()
        # 初始化目录
        for dir_path in [Config.FILTER_DIR, Config.BACKUP_DIR, Config.CACHE_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

    async def process(self):
        """异步处理规则文件"""
        logger.info("开始处理AdBlock/AdGuard规则文件")
        start_time = time.time()
        
        # 异步测试并启动SmartDNS
        smartdns_started = False
        if Config.USE_SMARTDNS:
            await self.validator.test_smartdns()  # 异步测试可用性
            smartdns_started = await self.smartdns.start()  # 异步启动服务
            if not smartdns_started:
                logger.warning("SmartDNS启动失败，使用备用DNS")
        
        try:
            # 处理黑名单
            logger.info("处理黑名单文件...")
            blocklist_rules = self.read_rules(Config.INPUT_BLOCKLIST)
            valid_blocklist = await self.validate_rules(blocklist_rules)
            self.save_rules(valid_blocklist, Config.OUTPUT_BLOCKLIST, Config.INPUT_BLOCKLIST)
            
            # 处理白名单
            logger.info("处理白名单文件...")
            allowlist_rules = self.read_rules(Config.INPUT_ALLOWLIST)
            valid_allowlist = await self.validate_rules(allowlist_rules)
            self.save_rules(valid_allowlist, Config.OUTPUT_ALLOWLIST, Config.INPUT_ALLOWLIST)
            
            # 输出统计
            self.print_stats(time.time() - start_time)
            
        finally:
            # 确保SmartDNS停止
            if smartdns_started:
                self.smartdns.stop()
                
    def read_rules(self, file_path: Path) -> List[str]:
        """读取规则文件"""
        if not file_path.exists():
            logger.warning(f"文件不存在: {file_path}")
            return []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                rules = f.readlines()
            logger.info(f"从 {file_path.name} 读取 {len(rules)} 条规则")
            return rules
        except Exception as e:
            logger.error(f"读取文件 {file_path} 失败: {e}")
            return []
        
    async def validate_rules(self, rules: List[str]) -> List[str]:
        """异步验证规则有效性"""
        valid_rules = []
        domain_to_rules = {}
        
        # 提取域名并分组
        for rule in rules:
            domain = self.processor.extract_domain_from_rule(rule)
            if domain:
                if domain not in domain_to_rules:
                    domain_to_rules[domain] = []
                domain_to_rules[domain].append(rule)
            else:
                # 保留无法提取域名的规则（注释、特殊规则）
                valid_rules.append(rule)
                
        logger.info(f"需验证域名数量: {len(domain_to_rules)}")
        if not domain_to_rules:
            return valid_rules
        
        # 批量异步验证域名
        valid_domains = await self.validate_domains_batch(list(domain_to_rules.keys()))
        
        # 组装有效规则
        for domain in valid_domains:
            valid_rules.extend(domain_to_rules[domain])
            
        return valid_rules
        
    async def validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量异步验证域名（限制并发）"""
        valid_domains = set()
        total = len(domains)
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)  # 限制并发数
        
        async def validate_with_sem(domain):
            async with semaphore:
                return domain, await self.validator.validate_domain(domain)
        
        # 分批处理
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i+Config.BATCH_SIZE]
            tasks = [validate_with_sem(d) for d in batch]
            results = await asyncio.gather(*tasks)
            
            for domain, is_valid in results:
                if is_valid:
                    valid_domains.add(domain)
            
            # 输出进度
            processed = min(i+Config.BATCH_SIZE, total)
            logger.info(f"验证进度: {processed}/{total} 域名（有效: {len(valid_domains)}）")
        
        logger.info(f"域名验证完成: 有效 {len(valid_domains)}/{total}")
        return valid_domains
        
    def save_rules(self, rules: List[str], output_path: Path, input_path: Path):
        """保存规则并备份原文件"""
        try:
            # 备份原文件
            if input_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = Config.BACKUP_DIR / f"{input_path.stem}_backup_{timestamp}.txt"
                backup_path.write_text(input_path.read_text(encoding='utf-8', errors='ignore'))
            
            # 保存新规则
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(rules)
            logger.info(f"已保存 {len(rules)} 条规则到 {output_path}")
        except Exception as e:
            logger.error(f"保存规则失败: {e}")
            
    def print_stats(self, elapsed: float):
        """输出处理统计"""
        stats = self.validator.stats
        logger.info("\n===== 处理统计 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")
        logger.info(f"查询超时: {stats['timeout']} 次")
        logger.info(f"SmartDNS查询: {stats['smartdns_queries']} 次")
        logger.info(f"系统DNS查询: {stats['system_dns_queries']} 次")


# 主函数
async def main():
    cleaner = AdblockCleaner()
    await cleaner.process()
    
if __name__ == '__main__':
    asyncio.run(main())
