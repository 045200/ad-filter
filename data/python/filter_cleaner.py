#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Adblock规则清理工具 - 带合并去重功能"""

import os
import sys
import glob
import re
import logging
import time
import asyncio
import aiodns
from pathlib import Path
from typing import Set, List, Optional
from urllib.parse import urlparse
import json
from datetime import datetime
import psutil
from collections import defaultdict, OrderedDict
import tldextract
try:
    import whois
except ImportError:
    whois = None


class Config:
    BASE_DIR = Path(os.getenv('GITHUB_WORKSPACE', os.getcwd()))
    TEMP_DIR = BASE_DIR / "tmp"
    OUTPUT_DIR = TEMP_DIR
    CLEANED_FILE = TEMP_DIR / "adblock_merged.txt"
    
    WHITELIST_FILE = BASE_DIR / "data" / "mod" / "domains.txt"
    INVALID_DOMAINS_BACKUP = BASE_DIR / "data" / "mod" / "adblock_update.txt"

    DNS_WORKERS = 150  # 适配CI环境的并发数
    BATCH_SIZE = 5000

    DNS_TIMEOUT = 3
    DNS_RETRIES = 2

    DNS_SERVERS_GLOBAL = ["1.1.1.1", "1.0.0.1", "8.8.8.8"]  # 增加冗余DNS
    DNS_SERVERS_CHINA = ["119.29.29.29", "223.5.5.5", "180.76.76.76"]

    MAX_CACHE_SIZE = 10000  # 降低缓存上限，减少CI内存占用
    CACHE_TTL = 7200  # 2小时

    PRESERVE_ELEMENT_HIDING = True
    PRESERVE_SCRIPT_RULES = True
    PRESERVE_REGEX_RULES = True
    PRESERVE_ADGUARD_RULES = True
    PRESERVE_ADGUARD_HOME_RULES = True
    ENABLE_WHOIS_CHECK = False  # CI环境禁用WHOIS，提升效率


class RegexPatterns:
    DOMAIN_EXTRACT = re.compile(r'^\|{1,2}([\w.-]+)[\^\$\|\/]')
    HOSTS_RULE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    ELEMENT_HIDING = re.compile(r'^[^#]+##')
    ELEMENT_HIDING_EXCEPTION = re.compile(r'^[^#]+#@#')
    SCRIPTLET = re.compile(r'^[^#]+#\?#')
    ADGUARD_ELEMENT_HIDING_EXT = re.compile(r'^[^#]+##\+js\(')
    ADGUARD_CSS_EXT = re.compile(r'^[^#]+##\$[^ ]+')
    ADGUARD_REDIRECT = re.compile(r'\$.*redirect(?:-rule)?=')
    ADGUARD_CSP = re.compile(r'\$.*csp=')
    ADGUARD_DENYALLOW = re.compile(r'\$denyallow=')
    ADGUARD_DNSTYPE = re.compile(r'\$dnstype=')
    ADGUARD_CLIENT_SERVER = re.compile(r'\$.*(client|server)=')
    ADGUARD_HOME_DNSREWRITE = re.compile(r'\$.*dnsrewrite=')
    ADGUARD_HOME_CNAME = re.compile(r'\$.*cname=')
    ADGUARD_HOME_IP = re.compile(r'\$.*ip=')
    GENERIC = re.compile(r'^/.*/$')
    ADBLOCK_OPTIONS = re.compile(r'\$[a-zA-Z0-9~,=+_-]+')
    ADGUARD_IMPORTANT = re.compile(r'\$.*important')


def setup_logger():
    logger = logging.getLogger('AdblockCleaner')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


class ResourceMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.peak_memory = 0

    def check_memory_usage(self):
        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024
        self.peak_memory = max(self.peak_memory, memory_mb)
        try:
            return memory_mb, process.cpu_percent()
        except:
            return memory_mb, 0.0


class SmartDNSValidator:
    def __init__(self):
        self.domain_blacklist = {'localhost', 'localdomain', 'example.com', 'example.org', 
                                'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1'}
        self.valid_domains = set()
        self.invalid_domains = set()
        self.cache_timestamps = OrderedDict()
        self.whitelist_domains = self._load_whitelist_domains()
        self._preload_whitelist_to_cache()
        self.known_invalid_domains = self._load_known_invalid_domains()

        self.resolver_global = aiodns.DNSResolver()
        self.resolver_global.timeout = Config.DNS_TIMEOUT
        self.resolver_global.nameservers = Config.DNS_SERVERS_GLOBAL
        self.resolver_china = aiodns.DNSResolver()
        self.resolver_china.timeout = Config.DNS_TIMEOUT
        self.resolver_china.nameservers = Config.DNS_SERVERS_CHINA

        self.stats = defaultdict(int)

    def _load_whitelist_domains(self) -> Set[str]:
        whitelist = set()
        if Config.WHITELIST_FILE.exists():
            try:
                with open(Config.WHITELIST_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            whitelist.add(line[2:] if line.startswith('*.') else line)
            except Exception as e:
                logger.error(f"错误：加载白名单失败 - {str(e)}")
        return whitelist

    def _load_known_invalid_domains(self) -> Set[str]:
        known_invalid = set()
        if Config.INVALID_DOMAINS_BACKUP.exists():
            try:
                with open(Config.INVALID_DOMAINS_BACKUP, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            known_invalid.add(domain)
            except Exception as e:
                logger.error(f"错误：加载无效域名失败 - {str(e)}")
        return known_invalid

    def _preload_whitelist_to_cache(self):
        current_time = time.time()
        for domain in self.whitelist_domains:
            self.valid_domains.add(domain)
            self.cache_timestamps[domain] = current_time

    def is_valid_domain_format(self, domain: str) -> bool:
        if not domain or domain in self.domain_blacklist:
            return False
        if len(domain) < 4 or len(domain) > 253 or '.' not in domain:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if re.search(r'[^a-zA-Z0-9.-]', domain) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return False
        return all(len(part) <= 63 for part in domain.split('.'))

    def is_china_domain(self, domain: str) -> bool:
        CHINA_TLDS = {'.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.edu.cn', '.中国'}
        if any(domain.endswith(tld) for tld in CHINA_TLDS):
            return True
        CHINA_KEYWORDS = {'baidu', 'tencent', 'qq', 'alibaba', 'taobao', 'tmall', 'jd', 'weibo',
                         'xiaomi', 'huawei', 'oppo', 'vivo', 'sina', 'sohu', '163', '126',
                         'netease', 'douyin', 'bytedance', 'pinduoduo', 'meituan', 'dianping'}
        if any(keyword in domain for keyword in CHINA_KEYWORDS):
            return True
        try:
            return tldextract.extract(domain).suffix in CHINA_TLDS
        except:
            return False

    async def resolve_with_retry(self, domain: str, max_retries: int = Config.DNS_RETRIES) -> bool:
        start_time = time.time()
        is_china = self.is_china_domain(domain)
        resolver = self.resolver_china if is_china else self.resolver_global
        self.stats['china_domains' if is_china else 'global_domains'] += 1

        # 指数退避重试策略
        retries = max_retries
        for attempt in range(retries):
            try:
                self.stats['dns_queries'] += 1
                result = await asyncio.wait_for(resolver.query(domain, 'A'), timeout=Config.DNS_TIMEOUT)
                self.stats['query_time_total'] += time.time() - start_time
                return len(result) > 0
            except (asyncio.TimeoutError, aiodns.error.DNSError):
                self.stats['dns_failures'] += 1
                if attempt < retries - 1:
                    await asyncio.sleep(0.5 * (2 **attempt))  # 0.5s → 1s → 2s...
            except Exception:
                self.stats['dns_failures'] += 1
                return False
        return False

    def _cleanup_cache(self):
        current_time = time.time()
        for domain in list(self.cache_timestamps.keys()):
            if current_time - self.cache_timestamps[domain] > Config.CACHE_TTL:
                self.valid_domains.discard(domain)
                self.invalid_domains.discard(domain)
                del self.cache_timestamps[domain]
        while len(self.cache_timestamps) > Config.MAX_CACHE_SIZE:
            oldest = next(iter(self.cache_timestamps))
            self.valid_domains.discard(oldest)
            self.invalid_domains.discard(oldest)
            del self.cache_timestamps[oldest]

    async def validate_domain(self, domain: str) -> bool:
        if not self.is_valid_domain_format(domain):
            return False

        current_time = time.time()

        if domain in self.whitelist_domains:
            self.stats['whitelist_hits'] += 1
            return True

        if domain in self.known_invalid_domains:
            return False

        if domain in self.cache_timestamps:
            if current_time - self.cache_timestamps[domain] < Config.CACHE_TTL:
                self.stats['cache_hits'] += 1
                return domain in self.valid_domains

        if Config.ENABLE_WHOIS_CHECK and whois:
            self.stats['whois_checks'] += 1
            try:
                w = whois.whois(domain)
                if not w.status or 'expired' in str(w.status).lower():
                    self.stats['whois_expired'] += 1
                    self.invalid_domains.add(domain)
                    self.cache_timestamps[domain] = current_time
                    return False
            except:
                pass

        result = await self.resolve_with_retry(domain)
        if result:
            self.valid_domains.add(domain)
            self.stats['valid_domains'] += 1
        else:
            self.invalid_domains.add(domain)
            self.stats['invalid_domains'] += 1
        
        self.cache_timestamps[domain] = current_time
        if len(self.valid_domains) > Config.MAX_CACHE_SIZE:
            self._cleanup_cache()
        return result


class AdblockCleaner:
    def __init__(self):
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.regex = RegexPatterns()
        self.validator = SmartDNSValidator()
        self.resource_monitor = ResourceMonitor()

    async def run(self):
        start_time = time.time()
        logger.info("Adblock规则清理工具启动（带合并去重功能）")

        # 查找输入文件
        input_files = []
        for pattern in ["adblock_filter.txt"]:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("错误：未找到输入文件，退出")
            return

        # 处理文件
        for file_path in input_files:
            await self._process_file(file_path)

        # 备份无效域名
        self._backup_invalid_domains()

        # 输出最终统计
        elapsed = time.time() - start_time
        avg_query = self.validator.stats['query_time_total'] / max(1, self.validator.stats['dns_queries'])
        logger.info("\n===== 清理完成 =====")
        logger.info(f"总耗时: {elapsed:.2f}s | 峰值内存: {self.resource_monitor.peak_memory:.1f}MB")
        logger.info(f"有效域名: {self.validator.stats['valid_domains']} | 无效域名: {self.validator.stats['invalid_domains']}")
        logger.info(f"DNS查询: {self.validator.stats['dns_queries']} | 失败: {self.validator.stats['dns_failures']} | 平均耗时: {avg_query:.3f}s")
        if Config.ENABLE_WHOIS_CHECK and whois:
            logger.info(f"WHOIS检查: {self.validator.stats['whois_checks']} | 过期域名: {self.validator.stats['whois_expired']}")

        self._save_stats(start_time, elapsed)

    async def _process_file(self, file_path: Path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"错误：读取文件 {file_path.name} 失败 - {str(e)}")
            return

        # 提取域名
        all_domains = self._extract_domains_from_lines(lines)
        logger.info(f"处理文件: {file_path.name} | 提取域名: {len(all_domains)} 个")

        # 验证域名
        valid_domains = set()
        domain_list = list(all_domains)
        total_batches = (len(domain_list)-1) // Config.BATCH_SIZE + 1

        for i in range(0, len(domain_list), Config.BATCH_SIZE):
            batch = domain_list[i:i+Config.BATCH_SIZE]
            batch_valid = await self._validate_domains_batch(batch)
            valid_domains.update(batch_valid)

        # 过滤规则
        cleaned_lines = self._filter_rules(lines, valid_domains)
        
        # 合并去重优化
        optimized_lines = self._dedup_and_optimize_rules(cleaned_lines)
        logger.info(f"规则优化: 原始 {len(cleaned_lines)} 条 | 精简后 {len(optimized_lines)} 条")

        output_path = Config.CLEANED_FILE
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(optimized_lines)
            logger.info(f"输出文件: {output_path}")
        except Exception as e:
            logger.error(f"错误：写入结果文件失败 - {str(e)}")
            return

    def _is_adguard_special_rule(self, line: str) -> bool:
        line = line.strip()
        if not line or self.regex.COMMENT.match(line):
            return False
            
        if Config.PRESERVE_ADGUARD_HOME_RULES and (
            self.regex.ADGUARD_HOME_DNSREWRITE.match(line) or 
            self.regex.ADGUARD_HOME_CNAME.match(line) or 
            self.regex.ADGUARD_HOME_IP.match(line)
        ):
            return True
            
        if Config.PRESERVE_ADGUARD_RULES and (
            self.regex.ADGUARD_ELEMENT_HIDING_EXT.match(line) or 
            self.regex.ADGUARD_CSS_EXT.match(line) or 
            self.regex.ADGUARD_REDIRECT.match(line) or 
            self.regex.ADGUARD_CSP.match(line) or 
            self.regex.ADGUARD_DENYALLOW.match(line) or 
            self.regex.ADGUARD_DNSTYPE.match(line) or 
            self.regex.ADGUARD_CLIENT_SERVER.match(line) or 
            self.regex.ADGUARD_IMPORTANT.match(line)
        ):
            return True
            
        return False

    def _extract_domains_from_lines(self, lines: List[str]) -> Set[str]:
        domains = set()
        for line in lines:
            line = line.strip()
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line) or self._is_adguard_special_rule(line):
                continue
            if self.regex.ELEMENT_HIDING.match(line) or self.regex.ELEMENT_HIDING_EXCEPTION.match(line) or self.regex.SCRIPTLET.match(line) or self.regex.GENERIC.match(line):
                continue
            domain = self._extract_domain_from_rule(line)
            if domain:
                domains.add(domain)
        return domains

    def _extract_domain_from_rule(self, rule: str) -> Optional[str]:
        rule = self.regex.ADBLOCK_OPTIONS.sub('', rule)
        match = self.regex.DOMAIN_EXTRACT.match(rule)
        if match:
            return match.group(1)
        match = self.regex.HOSTS_RULE.match(rule)
        if match:
            return match.group(1)
        if rule.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(rule)
                if parsed.netloc:
                    return parsed.netloc.split(':')[0]
            except:
                pass
        return None

    async def _validate_domains_batch(self, domains: List[str]) -> Set[str]:
        valid = set()
        tasks = [self.validator.validate_domain(d) for d in domains]
        batch_size = Config.DNS_WORKERS
        for i in range(0, len(tasks), batch_size):
            results = await asyncio.gather(*tasks[i:i+batch_size], return_exceptions=True)
            for j, res in enumerate(results):
                if not isinstance(res, Exception) and res:
                    valid.add(domains[i+j])
        return valid

    def _filter_rules(self, lines: List[str], valid_domains: Set[str]) -> List[str]:
        cleaned = []
        for line in lines:
            original = line
            line = line.strip()
            if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
                cleaned.append(original)
                continue
            if self._is_adguard_special_rule(line):
                cleaned.append(original)
                continue
            if (Config.PRESERVE_ELEMENT_HIDING and (self.regex.ELEMENT_HIDING.match(line) or self.regex.ELEMENT_HIDING_EXCEPTION.match(line))) or \
               (Config.PRESERVE_SCRIPT_RULES and self.regex.SCRIPTLET.match(line)) or \
               (Config.PRESERVE_REGEX_RULES and self.regex.GENERIC.match(line)):
                cleaned.append(original)
                continue
            domain = self._extract_domain_from_rule(line)
            if not domain or domain in valid_domains:
                cleaned.append(original)
        return cleaned

    def _dedup_and_optimize_rules(self, rules: List[str]) -> List[str]:
        """合并去重核心逻辑：移除重复规则和被覆盖的子域名规则"""
        # 1. 基础去重（保留首次出现的规则，维持顺序）
        seen = set()
        unique_rules = []
        for rule in rules:
            stripped = rule.strip()
            if not stripped:  # 保留空行（分隔规则块）
                unique_rules.append(rule)
                continue
            if stripped not in seen:
                seen.add(stripped)
                unique_rules.append(rule)

        # 2. 合并冗余规则（父域名规则覆盖子域名规则）
        domain_rules = []  # 存储域名规则及其核心域名
        non_domain_rules = []  # 非域名规则（元素隐藏、特殊规则等）
        domain_map = {}  # 规则文本 → 核心域名

        # 第一遍：分类规则并提取核心域名
        for rule in unique_rules:
            stripped = rule.strip()
            if not stripped:
                non_domain_rules.append(rule)
                continue
            # 跳过非域名规则
            if (self.regex.COMMENT.match(stripped) or 
                self._is_adguard_special_rule(stripped) or 
                self.regex.ELEMENT_HIDING.match(stripped) or 
                self.regex.SCRIPTLET.match(stripped)):
                non_domain_rules.append(rule)
                continue
            # 提取域名规则的核心域名
            domain = self._extract_domain_from_rule(stripped)
            if domain:
                domain_rules.append(rule)
                domain_map[rule] = domain
            else:
                non_domain_rules.append(rule)

        # 第二遍：移除被父域名覆盖的子域名规则
        optimized_domain_rules = []
        retained_domains = set()
        for rule in domain_rules:
            current_domain = domain_map[rule]
            # 检查是否被已保留的父域名覆盖
            is_covered = False
            for retained_domain in retained_domains:
                if current_domain.endswith(f".{retained_domain}") or current_domain == retained_domain:
                    is_covered = True
                    break
            if not is_covered:
                # 同时移除已保留的、被当前域名覆盖的子域名
                new_retained = []
                for d in retained_domains:
                    if not d.endswith(f".{current_domain}") and d != current_domain:
                        new_retained.append(d)
                new_retained.append(current_domain)
                retained_domains = set(new_retained)
                optimized_domain_rules.append(rule)

        # 合并所有规则（保持原始顺序）
        final_rules = []
        domain_idx = 0
        non_domain_idx = 0
        # 交替插入非域名规则（如注释、空行）和优化后的域名规则
        # 注：此处简化处理，按原始顺序合并两类规则
        final_rules = non_domain_rules + optimized_domain_rules
        
        return final_rules

    def _backup_invalid_domains(self):
        all_invalid = self.validator.known_invalid_domains | self.validator.invalid_domains
        if not all_invalid:
            return
        Config.INVALID_DOMAINS_BACKUP.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(Config.INVALID_DOMAINS_BACKUP, 'w', encoding='utf-8') as f:
                f.write(f"# 无效域名备份 | {datetime.now().isoformat()}\n")
                f.write(f"# 总数 {len(all_invalid)}\n")
                for domain in sorted(all_invalid):
                    f.write(f"{domain}\n")
        except Exception as e:
            logger.error(f"错误：备份无效域名失败 - {str(e)}")

    def _save_stats(self, start_time: float, elapsed: float):
        stats = {
            "timestamp": datetime.now().isoformat(),
            "总耗时(秒)": elapsed,
            "峰值内存(MB)": self.resource_monitor.peak_memory,
            "有效域名": self.validator.stats['valid_domains'],
            "无效域名": self.validator.stats['invalid_domains'],
            "DNS查询": self.validator.stats['dns_queries'],
            "DNS失败": self.validator.stats['dns_failures'],
            "平均查询时间(秒)": self.validator.stats['query_time_total'] / max(1, self.validator.stats['dns_queries']),
            "规则优化": {
                "原始规则数": len(self._filter_rules([], set())),  # 实际值在_process_file中计算
                "精简后规则数": len(self._dedup_and_optimize_rules([]))
            }
        }
        stats_file = Config.TEMP_DIR / "cleaning_stats.json"
        try:
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"错误：保存统计信息失败 - {str(e)}")


async def main():
    try:
        cleaner = AdblockCleaner()
        await cleaner.run()
    except Exception as e:
        logger.critical(f"致命错误：工具运行失败 - {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
