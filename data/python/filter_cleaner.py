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
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from datetime import datetime
import socket

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

    # 缓存与备份
    CACHE_DIR = BASE_DIR / "data" / "cache"
    BACKUP_DIR = FILTER_DIR / "backups"

    # 性能配置
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 50))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 1000))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 3))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 2))

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
        # 定义AdBlock/AdGuard规则的正则表达式模式
        self.patterns = {
            # 基础Adblock语法 (||example.com^)
            'adblock_domain': re.compile(r'^(?:@@)?\|{1,2}([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$\|\/]'),
            # Hosts格式 (0.0.0.0 example.com)
            'hosts_format': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])$'),
            # AdGuard语法 (||example.com^$third-party)
            'adguard_domain': re.compile(r'^(?:@@)?\|\|([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$]'),
            # 注释行
            'comment': re.compile(r'^[!#]'),
            # 空行
            'empty': re.compile(r'^\s*$'),
            # 元素隐藏规则 (example.com##.ad)
            'element_hiding': re.compile(r'.*##.*'),
            # 元素隐藏例外 (example.com#@#.ad)
            'element_exception': re.compile(r'.*#@#.*'),
            # 脚本规则 (example.com$$script)
            'script_rule': re.compile(r'.*\$\$.*'),
        }

    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """
        从AdBlock/AdGuard规则中提取域名
        返回: 提取的域名或None（如果是注释、空行或无法提取）
        """
        rule = rule.strip()
        
        # 跳过注释和空行
        if not rule or self.patterns['comment'].match(rule) or self.patterns['empty'].match(rule):
            return None
            
        # 跳过元素隐藏规则和脚本规则
        if (self.patterns['element_hiding'].match(rule) or 
            self.patterns['element_exception'].match(rule) or 
            self.patterns['script_rule'].match(rule)):
            return None
            
        # 尝试匹配各种域名规则
        for pattern_name in ['adblock_domain', 'hosts_format', 'adguard_domain']:
            match = self.patterns[pattern_name].match(rule)
            if match:
                domain = match.group(1)
                # 验证域名格式
                if self._is_valid_domain(domain):
                    return domain
                    
        return None
        
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式是否有效"""
        # 简单的域名格式验证
        if not domain or len(domain) > 253:
            return False
            
        # 检查是否包含非法字符
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            return False
            
        # 检查标签长度和格式
        labels = domain.split('.')
        for label in labels:
            if not label or len(label) > 63 or label.startswith('-') or label.endswith('-'):
                return False
                
        return True


# 高性能DNS验证器（使用aiodns + SmartDNS）
class SmartDNSValidator:
    def __init__(self):
        self.cache = {}
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'cached': 0,
            'timeout': 0
        }
        
        # 初始化DNS解析器
        self.resolver = aiodns.DNSResolver()
        if Config.USE_SMARTDNS:
            # 使用SmartDNS作为解析器
            self.resolver.nameservers = ['127.0.0.1']
            self.resolver.port = Config.SMARTDNS_PORT
        else:
            # 使用公共DNS作为备用
            self.resolver.nameservers = [
                '8.8.8.8',        # Google DNS
                '1.1.1.1',        # Cloudflare DNS
                '223.5.5.5',      # AliDNS
                '119.29.29.29'    # DNSPod
            ]
        
    async def validate_domain(self, domain: str) -> bool:
        """验证域名是否有效（可解析）"""
        self.stats['total'] += 1
        
        # 检查缓存
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]
            
        # 执行DNS查询
        valid = await self._dns_query(domain)
        
        # 更新缓存和统计
        self.cache[domain] = valid
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
            
        return valid
        
    async def _dns_query(self, domain: str) -> bool:
        """执行DNS查询，尝试多种记录类型"""
        record_types = ['A', 'AAAA', 'CNAME']
        
        for record_type in record_types:
            for attempt in range(Config.DNS_RETRIES):
                try:
                    # 执行异步DNS查询
                    result = await asyncio.wait_for(
                        self.resolver.query(domain, record_type),
                        timeout=Config.DNS_TIMEOUT
                    )
                    if result:
                        return True
                except asyncio.TimeoutError:
                    self.stats['timeout'] += 1
                    if attempt == Config.DNS_RETRIES - 1:
                        logger.debug(f"域名查询超时: {domain}")
                    continue
                except aiodns.error.DNSError as e:
                    # NXDOMAIN表示域名不存在
                    if e.args[0] == 4:  # NXDOMAIN
                        return False
                    continue
                except Exception as e:
                    logger.debug(f"域名查询异常 {domain}: {str(e)}")
                    continue
                    
        return False


# SmartDNS管理器
class SmartDNSManager:
    def __init__(self):
        self.process = None
        
    def generate_config(self):
        """生成SmartDNS配置文件，支持国内外域名分流"""
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

# 域名分流规则 - 国内域名
nameserver /cn/223.5.5.5
nameserver /taobao.com/223.5.5.5
nameserver /qq.com/119.29.29.29
nameserver /baidu.com/223.5.5.5
nameserver /aliyun.com/223.5.5.5
nameserver /weibo.com/223.5.5.5

# 域名分流规则 - 国际域名
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

    def start(self) -> bool:
        """启动SmartDNS服务"""
        if not Config.USE_SMARTDNS:
            logger.info("SmartDNS功能已禁用")
            return False
            
        self.generate_config()

        try:
            # 启动SmartDNS
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
            if self.test_connection():
                logger.info("SmartDNS服务启动成功")
                return True
            else:
                logger.error("SmartDNS服务启动失败")
                return False
                
        except Exception as e:
            logger.error(f"启动SmartDNS服务时出错: {e}")
            return False
            
    def test_connection(self) -> bool:
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
            
    def stop(self):
        """停止SmartDNS服务"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            logger.info("SmartDNS服务已停止")


# 主处理器
class AdblockCleaner:
    def __init__(self):
        self.validator = SmartDNSValidator()
        self.processor = AdblockRuleProcessor()
        self.smartdns = SmartDNSManager()
        
        # 确保目录存在
        Config.FILTER_DIR.mkdir(parents=True, exist_ok=True)
        Config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    async def process(self):
        """处理规则文件"""
        logger.info("开始处理AdBlock/AdGuard规则文件")
        start_time = time.time()
        
        # 启动SmartDNS
        smartdns_started = False
        if Config.USE_SMARTDNS:
            smartdns_started = self.smartdns.start()
            if not smartdns_started:
                logger.warning("SmartDNS启动失败，将使用公共DNS进行验证")
        
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
                
    def read_rules(self, file_path: Path) -> List[str]:
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
        
    async def validate_rules(self, rules: List[str]) -> List[str]:
        """验证规则有效性"""
        valid_rules = []
        domains_to_validate = set()
        domain_to_rules = {}
        
        # 提取域名并分组
        for rule in rules:
            domain = self.processor.extract_domain_from_rule(rule)
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
            
        # 创建信号量限制并发数
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)
        
        async def validate_with_semaphore(domain):
            async with semaphore:
                return domain, await self.validator.validate_domain(domain)
                
        # 分批处理
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i + Config.BATCH_SIZE]
            tasks = [validate_with_semaphore(domain) for domain in batch]
            results = await asyncio.gather(*tasks)
            
            for domain, is_valid in results:
                if is_valid:
                    valid_domains.add(domain)
                    
            # 输出进度
            processed = min(i + Config.BATCH_SIZE, total)
            valid_count = len(valid_domains)
            logger.info(f"进度: {processed}/{total} 域名 (有效: {valid_count})")
            
        logger.info(f"验证完成: 有效 {len(valid_domains)}/{total} 域名")
        return valid_domains
        
    def save_rules(self, rules: List[str], output_path: Path, input_path: Path):
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
            
    def print_stats(self, elapsed: float):
        """输出统计信息"""
        stats = self.validator.stats
        
        logger.info("\n===== 处理统计 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个")
        logger.info(f"无效域名: {stats['invalid']} 个")
        logger.info(f"缓存命中: {stats['cached']} 次")
        logger.info(f"查询超时: {stats['timeout']} 次")


# 主函数
async def main():
    cleaner = AdblockCleaner()
    await cleaner.process()
    
if __name__ == '__main__':
    asyncio.run(main())