#!/usr/bin/env python3
"""
高效黑名单处理器 - GitHub Actions 优化版
支持完整 AdGuard Home 语法 | 特殊语法跳过验证 | 极速 DNS 验证
"""

# ======================
# 配置区
# ======================
INPUT_FILE = "adblock.txt"         # 输入文件（仓库根目录）
OUTPUT_ADGUARD = "dns.txt"         # AdGuard输出（仓库根目录）
OUTPUT_HOSTS = "hosts.txt"         # Hosts输出（仓库根目录）
MAX_WORKERS = 6                    # 优化线程数（GitHub Actions 推荐）
TIMEOUT = 1.5                      # DNS查询超时（1.5秒）
DNS_VALIDATION = True              # DNS验证开关
BATCH_SIZE = 10000                 # 分批处理大小（内存优化）

# ======================
# 脚本主体
# ======================
import os
import sys
import re
import time
import logging
import concurrent.futures
import asyncio
import aiodns
from pathlib import Path
from typing import Tuple, Optional, List, Set, Iterator

# 预编译正则表达式 - 提升性能
ADG_SPECIAL = re.compile(r'^!|^\$|^@@|^/.*/$|^\|\|.*\^|\*\.|^\|\|.*/|^\|http?://|^##|^#\?#|^\?|\|\|.*\^\$')
ADG_DOMAIN = re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)|^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\$|^\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)')
HOSTS_RULE = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#]+)')
COMMENT_RULE = re.compile(r'^[!#]|^\[Adblock')
EXCEPTION_RULE = re.compile(r'^@@')

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DNSValidator:
    """高性能异步DNS验证器"""
    DNS_SERVERS = [
        "223.5.5.5",        # 阿里DNS（亚洲）
        "119.29.29.29",     # 腾讯DNS（亚洲）
        "1.1.1.1",          # Cloudflare（全球）
        "8.8.8.8",          # Google DNS（全球）
    ]
    
    def __init__(self):
        self.resolver = None
        self.valid_cache = set()
        self.invalid_cache = set()
        
    async def setup(self):
        """初始化异步解析器"""
        loop = asyncio.get_running_loop()
        self.resolver = aiodns.DNSResolver(loop=loop, timeout=TIMEOUT)
        # 随机化服务器列表
        self.resolver.nameservers = self.DNS_SERVERS.copy()
        random.shuffle(self.resolver.nameservers)
    
    async def is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        # 检查缓存
        if domain in self.valid_cache:
            return True
        if domain in self.invalid_cache:
            return False
            
        # 异步DNS查询
        try:
            await self.resolver.query(domain, 'A')
            self.valid_cache.add(domain)
            return True
        except (aiodns.error.DNSError, asyncio.TimeoutError):
            try:
                # 尝试CNAME记录
                await self.resolver.query(domain, 'CNAME')
                self.valid_cache.add(domain)
                return True
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                self.invalid_cache.add(domain)
                return False

class RuleProcessor:
    """规则处理器（无状态）"""
    @staticmethod
    def parse_rule(rule: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """解析单条规则"""
        # 跳过注释和头部声明
        if COMMENT_RULE.match(rule):
            return None, None

        # 跳过例外规则
        if EXCEPTION_RULE.match(rule):
            return None, None

        # 特殊语法直接写入
        if ADG_SPECIAL.match(rule):
            return rule, None

        # 尝试解析为AdGuard规则
        if domain := RuleProcessor._parse_adguard(rule):
            return rule, [f"0.0.0.0 {domain}"]

        # 尝试解析为Hosts规则
        if result := RuleProcessor._parse_hosts(rule):
            ip, domains = result
            return f"{ip} {' '.join(domains)}", [f"{ip} {d}" for d in domains]

        # 无法识别的规则直接写入
        return rule, None

    @staticmethod
    def _parse_adguard(rule: str) -> Optional[str]:
        """解析AdGuard规则"""
        if match := ADG_DOMAIN.match(rule):
            return next((g for g in match.groups() if g), "").lower()
        return None

    @staticmethod
    def _parse_hosts(rule: str) -> Optional[Tuple[str, List[str]]]:
        """解析Hosts规则"""
        if match := HOSTS_RULE.match(rule):
            ip = match.group(1)
            domains = [d.lower() for d in match.group(2).split()]
            return ip, domains
        return None

class BlacklistProcessor:
    """黑名单处理器"""
    def __init__(self):
        self.adguard_rules = set()
        self.hosts_rules = set()
        self.processed_count = 0
        self.start_time = time.time()
        self.dns_validator = DNSValidator()
        
    async def process(self):
        """主处理流程"""
        logger.info("🚀 启动规则处理引擎")
        
        # 获取工作区路径
        workspace = self._get_workspace()
        input_path = workspace / INPUT_FILE
        logger.info(f"📂 输入文件: {input_path}")
        
        # 检查文件是否存在
        if not input_path.exists():
            logger.error(f"❌ 输入文件不存在: {input_path}")
            logger.info("💡 请确保文件位于仓库根目录")
            sys.exit(1)
        
        # 初始化DNS验证器
        if DNS_VALIDATION:
            logger.info("🔍 初始化DNS验证器...")
            await self.dns_validator.setup()
        
        # 处理规则
        await self._process_file(input_path)
        
        # 保存结果
        self._save_results(workspace)
        self._print_summary()
    
    def _get_workspace(self) -> Path:
        """获取工作区路径"""
        if "GITHUB_WORKSPACE" in os.environ:
            return Path(os.environ["GITHUB_WORKSPACE"])
        return Path.cwd()
    
    async def _process_file(self, input_path: Path):
        """处理输入文件"""
        batch_count = 0
        for batch in self._read_batches(input_path):
            batch_count += 1
            await self._process_batch(batch, batch_count)
    
    def _read_batches(self, input_path: Path) -> Iterator[List[str]]:
        """分批读取文件"""
        batch = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if stripped := line.strip():
                    batch.append(stripped)
                    if len(batch) >= BATCH_SIZE:
                        yield batch
                        batch = []
            if batch:
                yield batch
    
    async def _process_batch(self, batch: List[str], batch_num: int):
        """处理一批规则"""
        batch_start = time.time()
        valid_count = 0
        
        # 处理规则
        for rule in batch:
            adguard_rule, hosts_rules = RuleProcessor.parse_rule(rule)
            
            # 验证规则
            if adguard_rule and hosts_rules and DNS_VALIDATION:
                domain = rule.split()[-1] if hosts_rules else ""
                if domain and not await self.dns_validator.is_valid_domain(domain):
                    continue
                
            # 添加有效规则
            if adguard_rule:
                self.adguard_rules.add(adguard_rule)
            if hosts_rules:
                self.hosts_rules.update(hosts_rules)
                
            self.processed_count += 1
            valid_count += 1
        
        # 记录进度
        batch_time = time.time() - batch_start
        total_time = time.time() - self.start_time
        logger.info(
            f"📦 批次 #{batch_num} | "
            f"规则: {valid_count}/{len(batch)} | "
            f"批次耗时: {batch_time:.2f}s | "
            f"累计: {self.processed_count} | "
            f"总耗时: {total_time:.1f}s"
        )
    
    def _save_results(self, workspace: Path):
        """保存结果文件"""
        # AdGuard规则
        adguard_path = workspace / OUTPUT_ADGUARD
        adguard_path.parent.mkdir(parents=True, exist_ok=True)
        with open(adguard_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.adguard_rules)))
        
        # Hosts规则
        hosts_path = workspace / OUTPUT_HOSTS
        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.hosts_rules)))
    
    def _print_summary(self):
        """打印摘要信息"""
        total_time = time.time() - self.start_time
        logger.info("✅ 处理完成!")
        logger.info(f"⏱️ 总耗时: {total_time:.1f}秒")
        logger.info(f"📊 处理规则: {self.processed_count}")
        logger.info(f"🛡️ AdGuard规则: {len(self.adguard_rules)}")
        logger.info(f"💾 Hosts规则: {len(self.hosts_rules)}")
        logger.info(f"💾 输出文件: {OUTPUT_ADGUARD}, {OUTPUT_HOSTS}")

if __name__ == "__main__":
    import random
    try:
        processor = BlacklistProcessor()
        asyncio.run(processor.process())
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("⛔ 处理已中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"🔥 处理失败: {str(e)}")
        sys.exit(1)