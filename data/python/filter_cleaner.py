#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于SmartDNS和aiodns的AdBlock/AdGuard规则清理器
优化点：支持通配符/IDN域名、动态DNS配置、端口检查、缓存过期
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

# 配置类（新增动态配置、缓存过期等）
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

    # SmartDNS配置（动态化改造）
    SMARTDNS_BIN = "/usr/local/bin/smartdns"
    SMARTDNS_CONFIG_DIR = BASE_DIR / "data" / "smartdns"
    SMARTDNS_CONFIG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.conf"
    SMARTDNS_PORT = int(os.getenv('SMARTDNS_PORT', 5354))
    SMARTDNS_LOG_FILE = SMARTDNS_CONFIG_DIR / "smartdns.log"
    # 动态DNS服务器列表（可外部配置）
    DOMESTIC_DNS = [
        '223.5.5.5',
        '119.29.29.29',
        'server-tls 1.12.12.12'
    ]
    OVERSEAS_DNS = [
        'server-tls 1.1.1.1 -group overseas -exclude-default-group',
        'server-tls 8.8.8.8 -group overseas -exclude-default-group'
    ]
    # 动态分流域名列表
    DOMESTIC_DOMAINS = ['cn', 'taobao.com', 'qq.com', 'baidu.com', 'aliyun.com', 'weibo.com']
    OVERSEAS_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com', 'amazon.com', 'microsoft.com', 'github.com']

    # 缓存与备份（新增缓存过期）
    CACHE_DIR = BASE_DIR / "data" / "cache"
    BACKUP_DIR = FILTER_DIR / "backups"
    CACHE_TTL = int(os.getenv('CACHE_TTL', 300))  # 缓存过期时间（秒）

    # 性能与日志配置
    DNS_WORKERS = int(os.getenv('DNS_WORKERS', 30))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 500))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 5))
    DNS_RETRIES = int(os.getenv('DNS_RETRIES', 3))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()  # 可配置日志级别

    # 功能开关
    USE_SMARTDNS = os.getenv('USE_SMARTDNS', 'true').lower() == 'true'


# 日志配置（支持可配置级别）
def setup_logger():
    logger = logging.getLogger('AdblockCleaner')
    # 动态设置日志级别
    log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)
    logger.setLevel(log_level)
    
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()


# AdBlock/AdGuard规则处理器（支持通配符、IDN域名）
class AdblockRuleProcessor:
    def __init__(self):
        # 正则优化：支持通配符（如*.example.com）
        self.rule_patterns = {
            'adblock_domain': re.compile(r'^(?:@@)?\|{1,2}\*?([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$\|\/]'),
            'hosts_format': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+\*?([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])$'),
            'adguard_domain': re.compile(r'^(?:@@)?\|\|*?([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])[\^\$]'),
            'comment': re.compile(r'^[!#]'),
            'empty': re.compile(r'^\s*$'),
            'element_hiding': re.compile(r'.*##.*'),
            'element_exception': re.compile(r'.*#@#.*'),
            'script_rule': re.compile(r'.*\$\$.*'),
        }

    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        rule = rule.strip()
        
        # 跳过无效规则
        if (not rule or self.rule_patterns['comment'].match(rule) or 
            self.rule_patterns['empty'].match(rule) or self.rule_patterns['element_hiding'].match(rule) or 
            self.rule_patterns['element_exception'].match(rule) or self.rule_patterns['script_rule'].match(rule)):
            return None
            
        # 提取域名
        for pattern_name in ['adblock_domain', 'hosts_format', 'adguard_domain']:
            match = self.rule_patterns[pattern_name].match(rule)
            if match:
                domain = match.group(1)
                # 处理国际化域名（IDN）
                domain = self._process_idn_domain(domain)
                if self._is_valid_domain(domain):
                    return domain
                    
        return None
        
    def _process_idn_domain(self, domain: str) -> str:
        """处理国际化域名（转为Punycode）"""
        try:
            import idna
            return idna.encode(domain).decode('ascii')
        except ImportError:
            logger.warning("未安装idna库，无法处理国际化域名（如中文域名）")
        except idna.IDNAError as e:
            logger.debug(f"国际化域名处理失败: {domain}, 错误: {e}")
        return domain
        
    def _is_valid_domain(self, domain: str) -> bool:
        """增强域名验证（支持Punycode）"""
        if not domain or len(domain) > 253:
            return False
        # 允许Punycode前缀（xn--）
        if re.search(r'[^a-zA-Z0-9.-xn--]', domain):
            return False
        for label in domain.split('.'):
            if not label or len(label) > 63 or label.startswith('-') or label.endswith('-'):
                return False
        return True


# 高性能DNS验证器（新增缓存过期）
class SmartDNSValidator:
    def __init__(self):
        # 缓存格式：{domain: (is_valid, expire_time)}
        self.cache = {}
        self.stats = {
            'total': 0, 'valid': 0, 'invalid': 0, 'cached': 0, 'expired_cache': 0,
            'timeout': 0, 'smartdns_queries': 0, 'system_dns_queries': 0
        }
        # 初始化解析器（默认公共DNS）
        self.resolver = aiodns.DNSResolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '223.5.5.5', '119.29.29.29']
        self.smartdns_available = None

    async def test_smartdns(self) -> bool:
        """异步测试SmartDNS可用性"""
        if not Config.USE_SMARTDNS:
            self.smartdns_available = False
            return False
            
        try:
            test_resolver = aiodns.DNSResolver()
            test_resolver.nameservers = ['127.0.0.1']
            test_resolver.port = Config.SMARTDNS_PORT
            
            result = await asyncio.wait_for(
                test_resolver.query("baidu.com", "A"),
                timeout=3
            )
            
            if result:
                logger.info("SmartDNS可用，将使用SmartDNS进行域名验证")
                self.smartdns_available = True
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
        
        # 检查缓存（含过期判断）
        if domain in self.cache:
            is_valid, expire_time = self.cache[domain]
            if time.time() < expire_time:
                self.stats['cached'] += 1
                return is_valid
            else:
                # 缓存过期，删除
                del self.cache[domain]
                self.stats['expired_cache'] += 1
            
        # 异步验证域名
        valid = await self._dns_query(domain)
        # 设置缓存（带过期时间）
        expire_time = time.time() + Config.CACHE_TTL
        self.cache[domain] = (valid, expire_time)
        
        # 更新统计
        if valid:
            self.stats['valid'] += 1
        else:
            self.stats['invalid'] += 1
            
        return valid
        
    async def _dns_query(self, domain: str) -> bool:
        """异步DNS查询（支持多记录类型）"""
        record_types = ['A', 'AAAA', 'CNAME']
        
        for record_type in record_types:
            for attempt in range(Config.DNS_RETRIES):
                try:
                    result = await asyncio.wait_for(
                        self.resolver.query(domain, record_type),
                        timeout=Config.DNS_TIMEOUT
                    )
                    if result:
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


# SmartDNS管理器（新增配置校验、动态配置）
class SmartDNSManager:
    def __init__(self):
        self.process = None
        
    def generate_config(self):
        """生成动态SmartDNS配置（从Config读取列表）"""
        config_content = f"""bind 127.0.0.1:{Config.SMARTDNS_PORT}
bind-tcp 127.0.0.1:{Config.SMARTDNS_PORT}
cache-size 2048
prefetch-domain yes
serve-expired yes
rr-ttl-min 300
log-level {Config.LOG_LEVEL.lower()}  # 动态日志级别
log-size 128K
log-file {Config.SMARTDNS_LOG_FILE}
speed-check-mode none

# 国内DNS服务器（动态加载）
"""
        # 添加国内DNS服务器
        for dns in Config.DOMESTIC_DNS:
            config_content += f"server {dns}\n"
        # 添加国际DNS服务器
        config_content += "\n# 国际DNS服务器（动态加载）\n"
        for dns in Config.OVERSEAS_DNS:
            config_content += f"{dns}\n"
        # 添加国内分流规则
        config_content += "\n# 国内域名分流规则（动态加载）\n"
        for domain in Config.DOMESTIC_DOMAINS:
            config_content += f"nameserver /{domain}/223.5.5.5\n"
        # 添加国际分流规则
        config_content += "\n# 国际域名分流规则（动态加载）\n"
        for domain in Config.OVERSEAS_DOMAINS:
            config_content += f"nameserver /{domain}/overseas\n"

        # 生成配置文件并设置权限（0600防篡改）
        Config.SMARTDNS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(Config.SMARTDNS_CONFIG_FILE, 'w') as f:
            f.write(config_content)
        os.chmod(Config.SMARTDNS_CONFIG_FILE, 0o600)
        logger.info(f"SmartDNS配置文件生成完成（权限0600）: {Config.SMARTDNS_CONFIG_FILE}")

    def validate_config(self) -> bool:
        """校验SmartDNS配置文件语法（关键改进）"""
        if not Config.SMARTDNS_CONFIG_FILE.exists():
            logger.error(f"配置文件不存在: {Config.SMARTDNS_CONFIG_FILE}")
            return False
        try:
            # 使用SmartDNS自带校验参数（-t）
            cmd = [Config.SMARTDNS_BIN, "-c", str(Config.SMARTDNS_CONFIG_FILE), "-t"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info("SmartDNS配置文件语法校验通过")
                return True
            else:
                logger.error(f"配置文件语法错误: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"校验配置文件失败: {e}")
            return False

    async def start(self) -> bool:
        """异步启动SmartDNS（含配置校验、端口检查）"""
        if not Config.USE_SMARTDNS:
            logger.info("SmartDNS功能已禁用")
            return False
            
        # 生成并校验配置文件
        self.generate_config()
        if not self.validate_config():
            logger.error("SmartDNS配置文件校验失败，终止启动")
            return False

        try:
            cmd = [Config.SMARTDNS_BIN, "-c", str(Config.SMARTDNS_CONFIG_FILE), "-x"]  # -x=守护进程模式
            logger.info(f"启动SmartDNS: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            # 异步等待服务就绪（替换同步sleep）
            await asyncio.sleep(3)
            
            # 检查进程状态
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                logger.error(f"SmartDNS进程异常退出，返回值: {self.process.returncode}")
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
                            logger.error(f"SmartDNS日志内容: {f.read()[:1000]}")  # 限制日志长度
                    except Exception as e:
                        logger.error(f"读取日志文件失败: {e}")
                return False
                
        except Exception as e:
            logger.error(f"启动SmartDNS服务出错: {e}")
            return False
            
    async def test_connection(self) -> bool:
        """异步测试SmartDNS连接（避免阻塞）"""
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
                logger.warning(f"dig测试失败（端口{Config.SMARTDNS_PORT}）: {stderr}")
            return success
        except Exception as e:
            logger.error(f"SmartDNS连接测试异常: {e}")
            return False
            
    def stop(self):
        """安全停止SmartDNS服务（处理僵尸进程）"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                # 等待进程退出
                self.process.wait(timeout=5)
                logger.info("SmartDNS服务正常停止")
            except subprocess.TimeoutExpired:
                # 强制终止僵尸进程
                self.process.kill()
                logger.warning("SmartDNS服务超时，已强制终止")


# 主处理器（新增端口检查、增强错误处理）
class AdblockCleaner:
    def __init__(self):
        self.validator = SmartDNSValidator()
        self.processor = AdblockRuleProcessor()
        self.smartdns = SmartDNSManager()
        # 初始化必要目录
        for dir_path in [Config.FILTER_DIR, Config.BACKUP_DIR, Config.CACHE_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def check_port_available(self, port: int) -> bool:
        """检查端口是否可用（避免冲突）"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 允许端口复用（避免TIME_WAIT问题）
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 尝试连接，返回0表示端口被占用
            return s.connect_ex(('127.0.0.1', port)) != 0

    async def process(self):
        """异步处理规则文件（整合所有改进）"""
        logger.info("=" * 50)
        logger.info("开始处理AdBlock/AdGuard规则文件")
        logger.info(f"日志级别: {Config.LOG_LEVEL}, 缓存过期时间: {Config.CACHE_TTL}秒")
        logger.info("=" * 50)
        start_time = time.time()
        
        # 1. 端口检查（关键前置校验）
        smartdns_started = False
        if Config.USE_SMARTDNS:
            if not self.check_port_available(Config.SMARTDNS_PORT):
                logger.error(f"错误：SmartDNS端口 {Config.SMARTDNS_PORT} 已被占用，无法启动服务")
                sys.exit(1)
            # 2. 测试SmartDNS可用性
            await self.validator.test_smartdns()
            # 3. 启动SmartDNS
            smartdns_started = await self.smartdns.start()
            if not smartdns_started:
                logger.warning("SmartDNS启动失败，将使用公共DNS完成验证")
        
        try:
            # 4. 处理黑名单
            logger.info("\n[1/2] 处理黑名单文件...")
            blocklist_rules = self.read_rules(Config.INPUT_BLOCKLIST)
            valid_blocklist = await self.validate_rules(blocklist_rules)
            self.save_rules(valid_blocklist, Config.OUTPUT_BLOCKLIST, Config.INPUT_BLOCKLIST)
            
            # 5. 处理白名单
            logger.info("\n[2/2] 处理白名单文件...")
            allowlist_rules = self.read_rules(Config.INPUT_ALLOWLIST)
            valid_allowlist = await self.validate_rules(allowlist_rules)
            self.save_rules(valid_allowlist, Config.OUTPUT_ALLOWLIST, Config.INPUT_ALLOWLIST)
            
            # 6. 输出统计报告
            self.print_stats(time.time() - start_time)
            
        finally:
            # 确保SmartDNS停止（资源释放）
            if smartdns_started:
                self.smartdns.stop()
        logger.info("\n规则处理完成！")
                
    def read_rules(self, file_path: Path) -> List[str]:
        """读取规则文件（增强错误处理）"""
        if not file_path.exists():
            logger.warning(f"规则文件不存在: {file_path}，将返回空列表")
            return []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                rules = f.readlines()
            # 去重（避免重复规则）
            rules = list(dict.fromkeys(rules))
            logger.info(f"从 {file_path.name} 读取并去重后，共 {len(rules)} 条规则")
            return rules
        except PermissionError:
            logger.error(f"权限不足，无法读取文件: {file_path}")
            return []
        except Exception as e:
            logger.error(f"读取文件 {file_path} 失败: {str(e)}")
            return []
        
    async def validate_rules(self, rules: List[str]) -> List[str]:
        """异步验证规则有效性（保持并发控制）"""
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
                # 保留无法提取域名的有效规则（注释、特殊规则）
                valid_rules.append(rule)
                
        logger.info(f"需验证的域名数量: {len(domain_to_rules)}")
        if not domain_to_rules:
            return valid_rules
        
        # 批量异步验证域名（限制并发）
        valid_domains = await self.validate_domains_batch(list(domain_to_rules.keys()))
        
        # 组装有效规则
        for domain in valid_domains:
            valid_rules.extend(domain_to_rules[domain])
            
        return valid_rules
        
    async def validate_domains_batch(self, domains: List[str]) -> Set[str]:
        """批量异步验证域名（优化进度显示）"""
        valid_domains = set()
        total = len(domains)
        semaphore = asyncio.Semaphore(Config.DNS_WORKERS)  # 限制并发数
        
        async def validate_with_sem(domain):
            async with semaphore:
                return domain, await self.validator.validate_domain(domain)
        
        # 分批处理（优化内存占用）
        for i in range(0, total, Config.BATCH_SIZE):
            batch = domains[i:i+Config.BATCH_SIZE]
            tasks = [validate_with_sem(d) for d in batch]
            results = await asyncio.gather(*tasks)
            
            for domain, is_valid in results:
                if is_valid:
                    valid_domains.add(domain)
            
            # 输出进度（百分比）
            processed = min(i+Config.BATCH_SIZE, total)
            progress = (processed / total) * 100
            logger.info(f"域名验证进度: {processed}/{total} ({progress:.1f}%)，有效域名: {len(valid_domains)}")
        
        logger.info(f"域名验证完成: 有效 {len(valid_domains)}/{total}")
        return valid_domains
        
    def save_rules(self, rules: List[str], output_path: Path, input_path: Path):
        """保存规则并备份（增强容错）"""
        try:
            # 1. 备份原文件（仅当原文件存在）
            if input_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = Config.BACKUP_DIR / f"{input_path.stem}_backup_{timestamp}.txt"
                # 备份时保留原编码
                with open(input_path, 'r', encoding='utf-8', errors='replace') as f_in:
                    with open(backup_path, 'w', encoding='utf-8') as f_out:
                        f_out.write(f_in.read())
                logger.info(f"已备份原文件到: {backup_path.name}")
            
            # 2. 保存新规则
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(rules)
            # 设置文件权限（防篡改）
            os.chmod(output_path, 0o644)
            logger.info(f"已保存 {len(rules)} 条规则到 {output_path}（权限0644）")
        except PermissionError:
            logger.error(f"权限不足，无法保存文件: {output_path}")
        except Exception as e:
            logger.error(f"保存规则失败: {str(e)}")
            
    def print_stats(self, elapsed: float):
        """输出详细统计报告（新增缓存过期统计）"""
        stats = self.validator.stats
        logger.info("\n" + "=" * 50)
        logger.info("===== 规则处理统计报告 =====")
        logger.info(f"总耗时: {elapsed:.2f} 秒")
        logger.info(f"处理域名总数: {stats['total']} 个")
        logger.info(f"有效域名: {stats['valid']} 个 ({(stats['valid']/stats['total']*100):.1f}%)")
        logger.info(f"无效域名: {stats['invalid']} 个 ({(stats['invalid']/stats['total']*100):.1f}%)")
        logger.info(f"缓存命中: {stats['cached']} 次 ({(stats['cached']/stats['total']*100):.1f}%)")
        logger.info(f"过期缓存: {stats['expired_cache']} 次")
        logger.info(f"查询超时: {stats['timeout']} 次")
        logger.info(f"SmartDNS查询: {stats['smartdns_queries']} 次")
        logger.info(f"公共DNS查询: {stats['system_dns_queries']} 次")
        logger.info("=" * 50)


# 主函数
async def main():
    # 检查依赖（aiodns）
    try:
        import aiodns
    except ImportError:
        logger.error("未安装依赖库 'aiodns'，请先执行: pip install aiodns")
        sys.exit(1)
    
    cleaner = AdblockCleaner()
    await cleaner.process()
    
if __name__ == '__main__':
    asyncio.run(main())
