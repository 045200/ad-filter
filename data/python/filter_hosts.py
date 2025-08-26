import os
import re
import sys
import glob
import logging
import asyncio
import aiofiles
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import List, Optional, Dict, Any, Tuple, Set

# ==================== 配置区 ====================
class HostsConfig:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './'))
    
    # 输入文件模式
    HOSTS_PATTERNS = []
    ADBLOCK_PATTERNS = ['adblock_adg.txt']  # 也处理AdBlock文件
    
    # 输出文件名
    OUTPUT_HOSTS = 'hosts.txt'
    
    # 默认阻塞IP
    DEFAULT_BLOCK_IP = '0.0.0.0'
    DEFAULT_BLOCK_IPV6 = '::'
    
    # AdBlock转换配置
    CONVERT_ADBLOCK = True  # 是否转换AdBlock规则
    ADBLOCK_DOMAIN_PATTERNS = [
        r'^\|\|([a-zA-Z0-9.-]+)\^(\$[^,]+)?$',  # ||example.com^ 或 ||example.com^$domain=example.org
        r'^([a-zA-Z0-9.-]+)$',                  # example.com
        r'^@@\|\|([a-zA-Z0-9.-]+)\^(\$[^,]+)?$',# @@||example.com^ (允许规则，不转换)
        r'^([a-zA-Z0-9.-]+)\^(\$[^,]+)?$',      # example.com^ 或 example.com^$domain=example.org
        r'^\|https?://([a-zA-Z0-9.-]+)/.*$',    # |http://example.com/ads.js
        r'^/([a-zA-Z0-9.-]+)/$',                # /example.com/
        r'^[^#]+\$domain=([a-zA-Z0-9.-]+)',     # 任何包含$domain=example.com的规则
    ]
    
    # 异步I/O配置
    ASYNC_ENABLED = True
    ASYNC_BUFFER_SIZE = 8192
    MAX_CONCURRENT_FILES = 5
    
    # 日志配置
    LOG_LEVEL = logging.INFO
    
    # 重试配置
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # 秒
    
    # 进度显示配置
    PROGRESS_UPDATE_INTERVAL = 1000  # 每处理多少行更新一次进度

# ==================== 初始化日志 ====================
def setup_logging():
    """配置日志系统"""
    logging.basicConfig(
        level=HostsConfig.LOG_LEVEL,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== Hosts处理器 ====================
class HostsProcessor:
    """处理Hosts文件和AdBlock文件的处理器"""
    
    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^#\s]+)(?:\s+#.*)?$')
    HOSTS_IPV6_REGEX = re.compile(r'^\s*([0-9a-fA-F:]+)\s+([^#\s]+)(?:\s+#.*)?$')
    COMMENT_REGEX = re.compile(r'^\s*[!#]')
    HOSTS_MULTI_DOMAIN = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\s+([^#]+)')
    ADBLOCK_DOMAIN_REGEXES = [
        re.compile(pattern) for pattern in HostsConfig.ADBLOCK_DOMAIN_PATTERNS
    ]
    DOMAIN_VALIDATION_REGEX = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    SIMPLE_DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$')
    
    def __init__(self):
        self.hosts_entries: Set[Tuple[str, str]] = set()  # 存储hosts条目 (ip, domain)
        self.domains: Set[str] = set()  # 存储所有域名用于去重
        self.stats = {
            'total_processed': 0,
            'hosts_entries': 0,
            'adblock_converted': 0,
            'duplicate_entries': 0,
            'ipv4_entries': 0,
            'ipv6_entries': 0,
            'adblock_processed': 0,
            'adblock_skipped': 0,
            'invalid_domains': 0,
            'files_processed': 0,
            'files_failed': 0
        }
        self.last_progress_update = 0
    
    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)
    
    def parse_hosts_line(self, line: str) -> List[Tuple[str, str]]:
        """解析hosts行，返回(ip, domain)元组列表"""
        results = []
        
        # 尝试匹配IPv4 hosts规则
        match = self.HOSTS_REGEX.match(line)
        if match:
            ip, domain = match.groups()
            results.append((ip, domain))
            return results
        
        # 尝试匹配IPv6 hosts规则
        match = self.HOSTS_IPV6_REGEX.match(line)
        if match:
            ip, domain = match.groups()
            results.append((ip, domain))
            return results
            
        # 尝试匹配多域名hosts规则
        match = self.HOSTS_MULTI_DOMAIN.match(line)
        if match:
            ip, domains_str = match.groups()
            domains = domains_str.split()
            for domain in domains:
                if domain.startswith('#'):  # 跳过注释
                    break
                results.append((ip, domain))
            return results
            
        return results
    
    def parse_adblock_line(self, line: str) -> Optional[str]:
        """解析AdBlock行，返回域名"""
        # 跳过注释和空行
        if self.is_comment_or_empty(line):
            return None
            
        # 跳过允许规则 (@@开头)
        if line.startswith('@@'):
            self.stats['adblock_skipped'] += 1
            return None
            
        # 尝试匹配各种AdBlock域名模式
        for regex in self.ADBLOCK_DOMAIN_REGEXES:
            match = regex.match(line)
            if match:
                domain = match.group(1)
                # 验证域名有效性
                if self.is_valid_domain(domain):
                    return domain
                else:
                    self.stats['invalid_domains'] += 1
                    logger.debug(f"无效域名: {domain} (来自规则: {line.strip()})")
                    
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if not domain or len(domain) > 253:
            return False
        
        # 移除可能的前缀和后缀
        domain = domain.lower().strip()
        
        # 移除常见的广告跟踪参数
        if '&' in domain:
            domain = domain.split('&')[0]
        
        # 检查是否是有效的域名
        if self.DOMAIN_VALIDATION_REGEX.match(domain):
            return True
            
        # 允许本地域名
        if self.SIMPLE_DOMAIN_REGEX.match(domain):
            return True
            
        return False
    
    def add_hosts_entry(self, ip: str, domain: str) -> bool:
        """添加hosts条目"""
        # 标准化域名
        domain = domain.lower().strip()
        
        # 检查是否重复
        if domain in self.domains:
            self.stats['duplicate_entries'] += 1
            return False
            
        self.hosts_entries.add((ip, domain))
        self.domains.add(domain)
        self.stats['hosts_entries'] += 1
        
        # 统计IPv4和IPv6条目
        if ':' in ip:
            self.stats['ipv6_entries'] += 1
        else:
            self.stats['ipv4_entries'] += 1
            
        return True
    
    async def process_file_with_retry(self, file_path: Path, is_hosts: bool = True, is_async: bool = True) -> int:
        """带重试机制的文件处理"""
        for attempt in range(HostsConfig.MAX_RETRIES):
            try:
                return await self.process_file(file_path, is_hosts, is_async)
            except Exception as e:
                if attempt < HostsConfig.MAX_RETRIES - 1:
                    logger.warning(f"处理文件 {file_path} 失败 (尝试 {attempt + 1}/{HostsConfig.MAX_RETRIES}): {e}")
                    await asyncio.sleep(HostsConfig.RETRY_DELAY * (attempt + 1))
                else:
                    logger.error(f"处理文件 {file_path} 失败 (最终尝试): {e}")
                    self.stats['files_failed'] += 1
                    return 0
        return 0
    
    def update_progress(self, current: int, total: int = None):
        """更新进度显示"""
        if total is None or current % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0 or current == total:
            if total:
                logger.info(f"处理进度: {current}/{total} ({current/total*100:.1f}%)")
            else:
                logger.info(f"已处理: {current} 行")
    
    async def process_file(self, file_path: Path, is_hosts: bool = True, is_async: bool = True) -> int:
        """处理单个文件（支持同步和异步）"""
        logger.info(f"处理文件: {file_path}")
        count = 0

        async def process_hosts_async():
            nonlocal count
            try:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    async for line in f:
                        line_count += 1
                        self.stats['total_processed'] += 1
                        
                        # 更新进度
                        if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                            self.update_progress(line_count)
                        
                        if self.is_comment_or_empty(line):
                            continue
                        
                        # 解析hosts行
                        entries = self.parse_hosts_line(line)
                        for ip, domain in entries:
                            if self.add_hosts_entry(ip, domain):
                                count += 1
            except UnicodeDecodeError:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                        line_count = 0
                        async for line in f:
                            line_count += 1
                            self.stats['total_processed'] += 1
                            
                            # 更新进度
                            if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                                self.update_progress(line_count)
                            
                            if self.is_comment_or_empty(line):
                                continue
                            
                            # 解析hosts行
                            entries = self.parse_hosts_line(line)
                            for ip, domain in entries:
                                if self.add_hosts_entry(ip, domain):
                                    count += 1
                except Exception as e:
                    logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
                    raise
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
                raise
            finally:
                self.update_progress(line_count, line_count)

        async def process_adblock_async():
            nonlocal count
            try:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    async for line in f:
                        line_count += 1
                        self.stats['total_processed'] += 1
                        self.stats['adblock_processed'] += 1
                        
                        # 更新进度
                        if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                            self.update_progress(line_count)
                        
                        # 解析AdBlock行
                        domain = self.parse_adblock_line(line)
                        if domain:
                            if self.add_hosts_entry(HostsConfig.DEFAULT_BLOCK_IP, domain):
                                count += 1
                                self.stats['adblock_converted'] += 1
            except UnicodeDecodeError:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                        line_count = 0
                        async for line in f:
                            line_count += 1
                            self.stats['total_processed'] += 1
                            self.stats['adblock_processed'] += 1
                            
                            # 更新进度
                            if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                                self.update_progress(line_count)
                            
                            # 解析AdBlock行
                            domain = self.parse_adblock_line(line)
                            if domain:
                                if self.add_hosts_entry(HostsConfig.DEFAULT_BLOCK_IP, domain):
                                    count += 1
                                    self.stats['adblock_converted'] += 1
                except Exception as e:
                    logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
                    raise
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
                raise
            finally:
                self.update_progress(line_count, line_count)

        def process_hosts_sync():
            nonlocal count
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    for line in f:
                        line_count += 1
                        self.stats['total_processed'] += 1
                        
                        # 更新进度
                        if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                            self.update_progress(line_count)
                        
                        if self.is_comment_or_empty(line):
                            continue
                        
                        # 解析hosts行
                        entries = self.parse_hosts_line(line)
                        for ip, domain in entries:
                            if self.add_hosts_entry(ip, domain):
                                count += 1
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                        line_count = 0
                        for line in f:
                            line_count += 1
                            self.stats['total_processed'] += 1
                            
                            # 更新进度
                            if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                                self.update_progress(line_count)
                            
                            if self.is_comment_or_empty(line):
                                continue
                            
                            # 解析hosts行
                            entries = self.parse_hosts_line(line)
                            for ip, domain in entries:
                                if self.add_hosts_entry(ip, domain):
                                    count += 1
                except Exception as e:
                    logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
                    raise
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
                raise
            finally:
                self.update_progress(line_count, line_count)

        def process_adblock_sync():
            nonlocal count
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    for line in f:
                        line_count += 1
                        self.stats['total_processed'] += 1
                        self.stats['adblock_processed'] += 1
                        
                        # 更新进度
                        if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                            self.update_progress(line_count)
                        
                        # 解析AdBlock行
                        domain = self.parse_adblock_line(line)
                        if domain:
                            if self.add_hosts_entry(HostsConfig.DEFAULT_BLOCK_IP, domain):
                                count += 1
                                self.stats['adblock_converted'] += 1
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                        line_count = 0
                        for line in f:
                            line_count += 1
                            self.stats['total_processed'] += 1
                            self.stats['adblock_processed'] += 1
                            
                            # 更新进度
                            if line_count % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                                self.update_progress(line_count)
                            
                            # 解析AdBlock行
                            domain = self.parse_adblock_line(line)
                            if domain:
                                if self.add_hosts_entry(HostsConfig.DEFAULT_BLOCK_IP, domain):
                                    count += 1
                                    self.stats['adblock_converted'] += 1
                except Exception as e:
                    logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
                    raise
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
                raise
            finally:
                self.update_progress(line_count, line_count)

        try:
            if is_async:
                if is_hosts:
                    await process_hosts_async()
                else:
                    await process_adblock_async()
            else:
                if is_hosts:
                    process_hosts_sync()
                else:
                    process_adblock_sync()
                    
            self.stats['files_processed'] += 1
            logger.info(f"从 {file_path} 添加了 {count} 条条目")
            return count
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生错误: {e}")
            self.stats['files_failed'] += 1
            return 0
    
    async def process_files_async(self) -> int:
        """异步处理所有文件"""
        tasks = []
        file_list = []
        
        # 收集hosts文件
        for pattern in HostsConfig.HOSTS_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), True))
        
        # 收集AdBlock文件
        for pattern in HostsConfig.ADBLOCK_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), False))
        
        logger.info(f"找到 {len(file_list)} 个文件需要处理")
        
        # 为每个文件创建处理任务
        for file_path, is_hosts in file_list:
            tasks.append(self.process_file_with_retry(file_path, is_hosts, True))
        
        # 使用信号量限制并发数量
        semaphore = asyncio.Semaphore(HostsConfig.MAX_CONCURRENT_FILES)

        async def limited_task(task):
            async with semaphore:
                return await task

        # 执行所有任务
        results = await asyncio.gather(*[limited_task(task) for task in tasks], return_exceptions=True)

        # 统计结果
        total_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"文件处理任务出错: {result}")
            else:
                total_count += result

        return total_count
    
    def process_files_sync(self) -> int:
        """同步处理所有文件"""
        total_count = 0
        file_list = []
        
        # 收集hosts文件
        for pattern in HostsConfig.HOSTS_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), True))
        
        # 收集AdBlock文件
        for pattern in HostsConfig.ADBLOCK_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), False))
        
        logger.info(f"找到 {len(file_list)} 个文件需要处理")
        
        # 处理每个文件
        for i, (file_path, is_hosts) in enumerate(file_list):
            logger.info(f"处理文件 {i+1}/{len(file_list)}: {file_path.name}")
            total_count += self.process_file_with_retry(file_path, is_hosts, False)
        
        return total_count
    
    def get_sorted_entries(self) -> List[str]:
        """获取排序后的hosts条目"""
        # 按域名排序
        sorted_entries = sorted(self.hosts_entries, key=lambda x: x[1])
        
        # 转换为字符串格式
        return [f"{ip} {domain}" for ip, domain in sorted_entries]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        return self.stats

# ==================== 输入输出区 ====================
def ensure_directories():
    """确保输入输出目录存在"""
    HostsConfig.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    HostsConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def write_hosts_with_retry(entries: List[str]) -> bool:
    """带重试机制的异步写入"""
    for attempt in range(HostsConfig.MAX_RETRIES):
        try:
            return await write_hosts_async(entries)
        except Exception as e:
            if attempt < HostsConfig.MAX_RETRIES - 1:
                logger.warning(f"写入hosts文件失败 (尝试 {attempt + 1}/{HostsConfig.MAX_RETRIES}): {e}")
                await asyncio.sleep(HostsConfig.RETRY_DELAY * (attempt + 1))
            else:
                logger.error(f"写入hosts文件失败 (最终尝试): {e}")
                return False
    return False

async def write_hosts_async(entries: List[str]) -> bool:
    """异步将hosts条目写入文件（无文件头）"""
    try:
        async with aiofiles.open(HostsConfig.OUTPUT_DIR / HostsConfig.OUTPUT_HOSTS, 'w', encoding='utf-8', newline='\n') as f:
            for i, entry in enumerate(entries):
                await f.write(f"{entry}\n")
                # 每1000行更新一次进度
                if (i + 1) % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                    logger.info(f"写入进度: {i + 1}/{len(entries)} ({(i + 1)/len(entries)*100:.1f}%)")
    except Exception as e:
        logger.error(f"写入hosts文件时出错: {e}")
        return False
        
    logger.info(f"写入 {len(entries)} 条hosts条目到 {HostsConfig.OUTPUT_HOSTS}")
    return True

def write_hosts_sync_with_retry(entries: List[str]) -> bool:
    """带重试机制的同步写入"""
    for attempt in range(HostsConfig.MAX_RETRIES):
        try:
            return write_hosts_sync(entries)
        except Exception as e:
            if attempt < HostsConfig.MAX_RETRIES - 1:
                logger.warning(f"写入hosts文件失败 (尝试 {attempt + 1}/{HostsConfig.MAX_RETRIES}): {e}")
                import time
                time.sleep(HostsConfig.RETRY_DELAY * (attempt + 1))
            else:
                logger.error(f"写入hosts文件失败 (最终尝试): {e}")
                return False
    return False

def write_hosts_sync(entries: List[str]) -> bool:
    """同步将hosts条目写入文件（无文件头）"""
    try:
        with open(HostsConfig.OUTPUT_DIR / HostsConfig.OUTPUT_HOSTS, 'w', encoding='utf-8', newline='\n') as f:
            for i, entry in enumerate(entries):
                f.write(f"{entry}\n")
                # 每1000行更新一次进度
                if (i + 1) % HostsConfig.PROGRESS_UPDATE_INTERVAL == 0:
                    logger.info(f"写入进度: {i + 1}/{len(entries)} ({(i + 1)/len(entries)*100:.1f}%)")
    except Exception as e:
        logger.error(f"写入hosts文件时出错: {e}")
        return False
        
    logger.info(f"写入 {len(entries)} 条hosts条目到 {HostsConfig.OUTPUT_HOSTS}")
    return True

# ==================== 主程序 ====================
async def main_async():
    """异步主函数"""
    logger.info("开始处理hosts和AdBlock文件")
    start_time = datetime.now()

    ensure_directories()

    processor = HostsProcessor()

    if HostsConfig.ASYNC_ENABLED:
        await processor.process_files_async()
    else:
        processor.process_files_sync()

    entries = processor.get_sorted_entries()

    if HostsConfig.ASYNC_ENABLED:
        success = await write_hosts_with_retry(entries)
    else:
        success = write_hosts_sync_with_retry(entries)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = processor.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"文件处理: {stats['files_processed']} 成功, {stats['files_failed']} 失败")
    logger.info(f"总计: {len(entries)} 条hosts条目")
    logger.info(f"处理统计: {stats['total_processed']} 行已处理, {stats['hosts_entries']} 条hosts条目")
    logger.info(f"IP统计: {stats['ipv4_entries']} 条IPv4条目, {stats['ipv6_entries']} 条IPv6条目")
    logger.info(f"AdBlock处理: {stats['adblock_processed']} 条AdBlock规则处理, {stats['adblock_converted']} 条已转换")
    logger.info(f"其他: {stats['adblock_skipped']} 条跳过, {stats['duplicate_entries']} 条重复条目, {stats['invalid_domains']} 无效域名")
    
    if not success:
        logger.error("写入输出文件失败")
        sys.exit(1)

def main_sync():
    """同步主函数"""
    logger.info("开始处理hosts和AdBlock文件")
    start_time = datetime.now()

    ensure_directories()

    processor = HostsProcessor()
    processor.process_files_sync()

    entries = processor.get_sorted_entries()
    success = write_hosts_sync_with_retry(entries)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = processor.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"文件处理: {stats['files_processed']} 成功, {stats['files_failed']} 失败")
    logger.info(f"总计: {len(entries)} 条hosts条目")
    logger.info(f"处理统计: {stats['total_processed']} 行已处理, {stats['hosts_entries']} 条hosts条目")
    logger.info(f"IP统计: {stats['ipv4_entries']} 条IPv4条目, {stats['ipv6_entries']} 条IPv6条目")
    logger.info(f"AdBlock处理: {stats['adblock_processed']} 条AdBlock规则处理, {stats['adblock_converted']} 条已转换")
    logger.info(f"其他: {stats['adblock_skipped']} 条跳过, {stats['duplicate_entries']} 条重复条目, {stats['invalid_domains']} 无效域名")
    
    if not success:
        logger.error("写入输出文件失败")
        sys.exit(1)

if __name__ == '__main__':
    try:
        if HostsConfig.ASYNC_ENABLED:
            asyncio.run(main_async())
        else:
            main_sync()
    except KeyboardInterrupt:
        logger.info("用户中断处理")
        sys.exit(1)
    except Exception as e:
        logger.error(f"处理过程中发生未预期错误: {e}")
        sys.exit(1)