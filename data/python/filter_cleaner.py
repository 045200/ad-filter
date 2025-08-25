#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS的Adblock规则清理器（修复启动问题）
适配GitHub Actions环境，自动处理SmartDNS安装与配置
"""

import os
import re
import sys
import time
import logging
import asyncio
import subprocess
import socket
from pathlib import Path
from typing import Set, List, Dict, Optional
from datetime import datetime

# 配置类
class Config:
    # 基础路径（适配GitHub Actions）
    GITHUB_WORKSPACE = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    BASE_DIR = GITHUB_WORKSPACE

    # 输入输出路径
    FILTER_DIR = BASE_DIR / "data" / "filter"
    INPUT_BLOCKLIST = FILTER_DIR / "adblock_filter.txt"
    INPUT_ALLOWLIST = FILTER_DIR / "allow_filter.txt"
    OUTPUT_BLOCKLIST = FILTER_DIR / "adblock.txt"
    OUTPUT_ALLOWLIST = FILTER_DIR / "allow.txt"

    # SmartDNS配置（优化路径与端口）
    SMARTDNS_BIN = os.getenv('SMARTDNS_BIN', '/usr/bin/smartdns')  # 调整默认路径
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5354))  # 避开常见占用端口

    # 缓存与备份
    CACHE_DIR = BASE_DIR / "data" / "cache"
    BACKUP_DIR = FILTER_DIR / "backups"

    # 性能配置（适配GitHub Actions资源）
    MAX_WORKERS = int(os.getenv('MAX_WORKERS', 8))
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 30))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 3))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 1))

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


# 规则处理器（支持AdGuard/Adblock全语法）
class RuleProcessor:
    def __init__(self):
        self.patterns = {
            # Adblock基础语法（含白名单@@）
            'adblock_base': re.compile(r'^(?:@@)?\|{1,2}([\w.-]+)[\^\$\|\/;]'),
            # Hosts格式（0.0.0.0/127.0.0.1/::1）
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$'),
            # AdGuard IP映射语法（如1.2.3.4 example.com）
            'adguard_ip': re.compile(r'^\d+\.\d+\.\d+\.\d+\s+([\w.-]+)$'),
            # AdGuard通配符语法（如*.example.com）
            'adguard_wildcard': re.compile(r'^\*\.([\w.-]+)$'),
            # 纯域名规则（如example.com）
            'pure_domain': re.compile(r'^([\w.-]+)$'),
            # 注释行（跳过）
            'comment': re.compile(r'^[!#;]'),
        }

    def parse_rule(self, rule: str) -> Optional[str]:
        rule = rule.strip()
        if not rule or self.patterns['comment'].match(rule):
            return None
        
        # 按优先级匹配规则
        for pattern_key in ['adblock_base', 'hosts', 'adguard_ip', 'adguard_wildcard', 'pure_domain']:
            match = self.patterns[pattern_key].match(rule)
            if match:
                return match.group(1)
        return None


# DNS验证器（保留aiodns逻辑，优化超时）
class DNSValidator:
    def __init__(self):
        self.cache = {}
        self.stats = {'total': 0, 'valid': 0, 'invalid': 0, 'cached': 0}

    async def validate_domain(self, domain: str) -> bool:
        self.stats['total'] += 1
        if domain in self.cache:
            self.stats['cached'] += 1
            return self.cache[domain]
        
        # 系统DNS验证（适配无SmartDNS场景）
        valid = await self._system_dns_check(domain)
        self.cache[domain] = valid
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
        return valid

    async def _system_dns_check(self, domain: str) -> bool:
        loop = asyncio.get_event_loop()
        for _ in range(Config.DNS_RETRIES):
            try:
                # 并行检查A/AAAA记录
                task_a = loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, None, socket.AF_INET))
                task_aaaa = loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, None, socket.AF_INET6))
                result_a, result_aaaa = await asyncio.gather(task_a, task_aaaa, return_exceptions=True)
                if isinstance(result_a, list) or isinstance(result_aaaa, list):
                    return True
            except (socket.gaierror, OSError, Exception):
                pass
            await asyncio.sleep(0.1)
        return False


# SmartDNS管理器（修复启动问题）
class SmartDNSManager:
    def __init__(self):
        self.process = None

    def _check_smartdns_installed(self) -> bool:
        """检查SmartDNS是否安装，未安装则自动安装（GitHub Actions Ubuntu环境）"""
        if Path(Config.SMARTDNS_BIN).exists():
            logger.info(f"SmartDNS已存在：{Config.SMARTDNS_BIN}")
            return True
        
        logger.info("SmartDNS未安装，开始自动安装（适配Ubuntu）")
        try:
            # GitHub Actions需sudo权限，且apt更新
            subprocess.run(
                ["sudo", "apt", "update", "-y"],
                check=True, capture_output=True, text=True
            )
            # 安装SmartDNS（Ubuntu官方源或第三方源）
            subprocess.run(
                ["sudo", "apt", "install", "-y", "smartdns"],
                check=True, capture_output=True, text=True
            )
            if Path(Config.SMARTDNS_BIN).exists():
                logger.info("SmartDNS安装成功")
                return True
            else:
                logger.error("SmartDNS安装后未找到二进制文件")
                return False
        except subprocess.CalledProcessError as e:
            logger.error(f"SmartDNS安装失败：{e.stderr}")
            return False

    def generate_config(self):
        """生成正确语法的SmartDNS配置"""
        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # 修正语法：参数无空格（如bind-tcp而非bind - tcp）
        config_content = f"""
bind 127.0.0.1:{Config.SMARTDNS_PORT}
bind-tcp 127.0.0.1:{Config.SMARTDNS_PORT}
cache-size 1024
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level error
log-size 64K
speed-check-mode none

# 国内DNS（优化稳定性）
server 223.5.5.5:53
server 119.29.29.29:53
server-tls 223.5.5.5:853

# 国际DNS（规避污染）
server-tls 1.1.1.1:853 -group overseas -exclude-default-group
server-tls 8.8.8.8:853 -group overseas -exclude-default-group

# 域名分流（覆盖国内外常见域名）
nameserver /cn/223.5.5.5
nameserver /taobao.com/223.5.5.5
nameserver /qq.com/119.29.29.29
nameserver /google.com/overseas
nameserver /youtube.com/overseas
nameserver /facebook.com/overseas
        """.strip()

        with open(Config.SMARTDNS_CONFIG_FILE, 'w', encoding='utf-8') as f:
            f.write(config_content)
        logger.info("SmartDNS配置文件生成完成（语法修正）")

    def start(self) -> bool:
        """启动SmartDNS（含安装检查、语法修正）"""
        if not Config.USE_SMARTDNS:
            logger.info("SmartDNS功能已禁用")
            return False
        
        # 先检查安装
        if not self._check_smartdns_installed():
            logger.error("SmartDNS安装失败，无法启动")
            return False
        
        # 生成正确配置
        self.generate_config()

        try:
            cmd = [Config.SMARTDNS_BIN, "-c", str(Config.SMARTDNS_CONFIG_FILE), "-x"]
            # 捕获stderr日志，便于定位启动错误
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(2)  # 缩短启动等待（适配CI环境）

            # 检查进程是否存活
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                logger.error(f"SmartDNS启动退出，stderr：{stderr.strip()}")
                return False

            # 测试连接（用dig替代nslookup，更稳定）
            if self._test_connection():
                logger.info("SmartDNS服务启动成功")
                return True
            else:
                logger.error("SmartDNS服务启动但无法连接")
                return False
        except Exception as e:
            logger.error(f"SmartDNS启动异常：{str(e)}")
            return False

    def _test_connection(self) -> bool:
        """用dig测试SmartDNS连接（比nslookup更稳定）"""
        try:
            cmd = [
                "dig", f"@127.0.0.1", "-p", str(Config.SMARTDNS_PORT),
                "baidu.com", "+short", "+timeout=2"
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3
            )
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except Exception:
            return False

    def stop(self):
        """停止SmartDNS服务"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
            logger.info("SmartDNS服务已停止")


# 主处理器（逻辑不变，优化日志）
class RuleCleaner:
    def __init__(self):
        self.validator = DNSValidator()
        self.processor = RuleProcessor()
        self.smartdns = SmartDNSManager()
        # 初始化目录
        for dir_path in [Config.FILTER_DIR, Config.BACKUP_DIR, Config.CACHE_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

    async def process(self):
        logger.info("=== 开始清理SmartDNS规则 ===")
        start_time = time.time()
        smartdns_started = False

        try:
            # 启动SmartDNS（失败不中断规则处理）
            if Config.USE_SMARTDNS:
                smartdns_started = self.smartdns.start()
            else:
                logger.info("跳过SmartDNS启动（功能已禁用）")

            # 处理黑名单
            await self._process_single_list(
                input_path=Config.INPUT_BLOCKLIST,
                output_path=Config.OUTPUT_BLOCKLIST,
                list_type="黑名单"
            )

            # 处理白名单
            await self._process_single_list(
                input_path=Config.INPUT_ALLOWLIST,
                output_path=Config.OUTPUT_ALLOWLIST,
                list_type="白名单"
            )

            # 输出统计
            self._print_stats(time.time() - start_time)
        finally:
            # 确保停止SmartDNS
            if smartdns_started:
                self.smartdns.stop()

    async def _process_single_list(self, input_path: Path, output_path: Path, list_type: str):
        logger.info(f"处理{list_type}文件：{input_path.name}")
        # 读取规则
        rules = self._read_rules(input_path)
        if not rules:
            logger.warning(f"{list_type}文件无有效规则")
            return

        # 提取域名并验证
        domain_rule_map, raw_rules = self._extract_domains(rules)
        logger.info(f"{list_type}需验证域名：{len(domain_rule_map.keys())} 个")
        valid_domains = await self._validate_domains_batch(list(domain_rule_map.keys()))

        # 构建有效规则（保留原始格式）
        valid_rules = raw_rules  # 保留无域名规则（注释等）
        for domain in valid_domains:
            valid_rules.extend(domain_rule_map[domain])

        # 保存结果
        self._save_rules(valid_rules, output_path, input_path, list_type)

    def _read_rules(self, file_path: Path) -> List[str]:
        if not file_path.exists():
            logger.warning(f"文件不存在：{file_path}")
            return []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                rules = [line for line in f if line.strip()]
            logger.info(f"读取到 {len(rules)} 条规则")
            return rules
        except Exception as e:
            logger.error(f"读取文件失败：{str(e)}")
            return []

    def _extract_domains(self, rules: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
        """提取域名-规则映射，分离无域名规则"""
        domain_map = {}
        raw_rules = []
        for rule in rules:
            domain = self.processor.parse_rule(rule)
            if domain:
                if domain not in domain_map:
                    domain_map[domain] = []
                domain_map[domain].append(rule)
            else:
                raw_rules.append(rule)
        return domain_map, raw_rules

    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量验证域名（带并发控制）"""
        valid_domains = set()
        total = len(domains)
        if total == 0:
            return valid_domains

        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)
        async def _validate(domain):
            async with semaphore:
                return domain, await self.validator.validate_domain(domain)

        # 分批处理（避免内存溢出）
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i+Config.BATCH_SIZE]
            tasks = [_validate(d) for d in batch]
            results = await asyncio.gather(*tasks)
            valid_domains.update([d for d, valid in results if valid])

            # 输出进度
            processed = min(i + Config.BATCH_SIZE, total)
            logger.info(f"域名验证进度：{processed}/{total}（已有效：{len(valid_domains)}）")
        return valid_domains

    def _save_rules(self, rules: List[str], output_path: Path, input_path: Path, list_type: str):
        """保存规则并备份原文件"""
        # 备份原文件
        if input_path.exists():
            backup_path = Config.BACKUP_DIR / f"{input_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            input_path.rename(backup_path)
            logger.info(f"原{list_type}文件已备份：{backup_path.name}")

        # 保存新规则
        with open(output_path, 'w', encoding='utf-8') as f:
            f.writelines(rules)
        logger.info(f"{list_type}处理完成，保存 {len(rules)} 条规则到：{output_path.name}")

    def _print_stats(self, elapsed: float):
        """输出最终统计"""
        stats = self.validator.stats
        logger.info("\n=== 处理完成统计 ===")
        logger.info(f"总耗时：{elapsed:.2f} 秒")
        logger.info(f"域名总数量：{stats['total']} 个")
        logger.info(f"有效域名：{stats['valid']} 个（{stats['valid']/stats['total']*100:.1f}%）")
        logger.info(f"无效域名：{stats['invalid']} 个（已删除对应规则）")
        logger.info(f"缓存命中：{stats['cached']} 次")


# 主函数
async def main():
    try:
        cleaner = RuleCleaner()
        await cleaner.process()
    except KeyboardInterrupt:
        logger.info("用户中断处理")
    except Exception as e:
        logger.error(f"处理异常：{str(e)}", exc_info=True)

if __name__ == '__main__':
    asyncio.run(main())
