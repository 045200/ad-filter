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

# ==================== 配置区 ====================
class HostsConfig:
    # 输入输出路径
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './'))
    
    # 输入文件模式
    HOSTS_PATTERNS = ['hosts*', '*-hosts*']
    
    # 输出文件名
    OUTPUT_HOSTS = 'hosts_filter.txt'
    
    # 默认阻塞IP
    DEFAULT_BLOCK_IP = '0.0.0.0'
    DEFAULT_BLOCK_IPV6 = '::'
    
    # 异步I/O配置
    ASYNC_ENABLED = True
    ASYNC_BUFFER_SIZE = 8192
    MAX_CONCURRENT_FILES = 5
    
    # 日志配置
    LOG_LEVEL = logging.INFO

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
    """专门处理Hosts文件的处理器"""
    
    # 预编译正则表达式
    HOSTS_REGEX = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^#\s]+)(?:\s+#.*)?$')
    HOSTS_IPV6_REGEX = re.compile(r'^\s*([0-9a-fA-F:]+)\s+([^#\s]+)(?:\s+#.*)?$')
    COMMENT_REGEX = re.compile(r'^\s*[!#]')
    HOSTS_MULTI_DOMAIN = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\s+([^#]+)')
    
    def __init__(self):
        self.hosts_entries = set()  # 存储hosts条目 (ip, domain)
        self.domains = set()  # 存储所有域名用于去重
        self.stats = {
            'total_processed': 0,
            'hosts_entries': 0,
            'duplicate_entries': 0,
            'ipv4_entries': 0,
            'ipv6_entries': 0
        }
    
    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        line = line.strip()
        return not line or self.COMMENT_REGEX.match(line)
    
    def parse_hosts_line(self, line: str) -> List[tuple]:
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
    
    def add_hosts_entry(self, ip: str, domain: str):
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
    
    async def process_file_async(self, file_path: Path):
        """异步处理hosts文件"""
        logger.info(f"处理hosts文件: {file_path}")
        count = 0
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    self.stats['total_processed'] += 1
                    
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
                    async for line in f:
                        self.stats['total_processed'] += 1
                        
                        if self.is_comment_or_empty(line):
                            continue
                        
                        # 解析hosts行
                        entries = self.parse_hosts_line(line)
                        for ip, domain in entries:
                            if self.add_hosts_entry(ip, domain):
                                count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
            
        logger.info(f"从 {file_path} 添加了 {count} 条hosts条目")
        return count
    
    def process_file_sync(self, file_path: Path):
        """同步处理hosts文件"""
        logger.info(f"处理hosts文件: {file_path}")
        count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    self.stats['total_processed'] += 1
                    
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
                    for line in f:
                        self.stats['total_processed'] += 1
                        
                        if self.is_comment_or_empty(line):
                            continue
                        
                        # 解析hosts行
                        entries = self.parse_hosts_line(line)
                        for ip, domain in entries:
                            if self.add_hosts_entry(ip, domain):
                                count += 1
            except Exception as e:
                logger.error(f"处理文件 {file_path} 时出错 (latin-1编码): {e}")
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时发生未知错误: {e}")
            
        logger.info(f"从 {file_path} 添加了 {count} 条hosts条目")
        return count
    
    async def process_files_async(self):
        """异步处理所有文件"""
        tasks = []
        
        # 处理hosts文件
        for pattern in HostsConfig.HOSTS_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                tasks.append(self.process_file_async(Path(file_path)))
        
        semaphore = asyncio.Semaphore(HostsConfig.MAX_CONCURRENT_FILES)

        async def limited_task(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[limited_task(task) for task in tasks], return_exceptions=True)

        total_count = 0
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"文件处理任务出错: {result}")
            else:
                total_count += result

        return total_count
    
    def process_files_sync(self):
        """同步处理所有文件"""
        total_count = 0
        
        # 处理hosts文件
        for pattern in HostsConfig.HOSTS_PATTERNS:
            for file_path in glob.glob(str(HostsConfig.INPUT_DIR / pattern)):
                total_count += self.process_file_sync(Path(file_path))
        
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

async def write_hosts_async(entries: List[str]):
    """异步将hosts条目写入文件"""
    try:
        async with aiofiles.open(HostsConfig.OUTPUT_DIR / HostsConfig.OUTPUT_HOSTS, 'w', encoding='utf-8', newline='\n') as f:
            # 添加hosts文件头
            await f.write("# Generated hosts file\n")
            await f.write("# Date: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            await f.write("# Total entries: {}\n\n".format(len(entries)))
            
            for entry in entries:
                await f.write(f"{entry}\n")
    except Exception as e:
        logger.error(f"写入hosts文件时出错: {e}")
        return False
        
    logger.info(f"写入 {len(entries)} 条hosts条目到 {HostsConfig.OUTPUT_HOSTS}")
    return True

def write_hosts_sync(entries: List[str]):
    """同步将hosts条目写入文件"""
    try:
        with open(HostsConfig.OUTPUT_DIR / HostsConfig.OUTPUT_HOSTS, 'w', encoding='utf-8', newline='\n') as f:
            # 添加hosts文件头
            f.write("# Generated hosts file\n")
            f.write("# Date: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("# Total entries: {}\n\n".format(len(entries)))
            
            for entry in entries:
                f.write(f"{entry}\n")
    except Exception as e:
        logger.error(f"写入hosts文件时出错: {e}")
        return False
        
    logger.info(f"写入 {len(entries)} 条hosts条目到 {HostsConfig.OUTPUT_HOSTS}")
    return True

# ==================== 主程序 ====================
async def main_async():
    """异步主函数"""
    logger.info("开始处理hosts文件")
    start_time = datetime.now()

    ensure_directories()

    processor = HostsProcessor()

    if HostsConfig.ASYNC_ENABLED:
        await processor.process_files_async()
    else:
        processor.process_files_sync()

    entries = processor.get_sorted_entries()

    if HostsConfig.ASYNC_ENABLED:
        await write_hosts_async(entries)
    else:
        write_hosts_sync(entries)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = processor.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(entries)} 条hosts条目")
    logger.info(f"处理统计: {stats['total_processed']} 行已处理, {stats['hosts_entries']} 条hosts条目, {stats['ipv4_entries']} 条IPv4条目, {stats['ipv6_entries']} 条IPv6条目, {stats['duplicate_entries']} 条重复条目")

def main_sync():
    """同步主函数"""
    logger.info("开始处理hosts文件")
    start_time = datetime.now()

    ensure_directories()

    processor = HostsProcessor()
    processor.process_files_sync()

    entries = processor.get_sorted_entries()
    write_hosts_sync(entries)

    end_time = datetime.now()
    duration = end_time - start_time
    stats = processor.get_stats()

    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"总计: {len(entries)} 条hosts条目")
    logger.info(f"处理统计: {stats['total_processed']} 行已处理, {stats['hosts_entries']} 条hosts条目, {stats['ipv4_entries']} 条IPv4条目, {stats['ipv6_entries']} 条IPv6条目, {stats['duplicate_entries']} 条重复条目")

if __name__ == '__main__':
    if HostsConfig.ASYNC_ENABLED:
        asyncio.run(main_async())
    else:
        main_sync()