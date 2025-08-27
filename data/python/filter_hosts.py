import os
import re
import sys
import glob
import logging
import asyncio
import aiofiles
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Set, Tuple

# ==================== 配置区 ====================
class Config:
    INPUT_DIR = Path(os.getenv('INPUT_DIR', './'))
    OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', './'))
    OUTPUT_FILE = 'hosts.txt'
    BLOCK_IP = '0.0.0.0'
    BLOCK_IPV6 = '::'
    
    # 文件模式
    HOSTS_PATTERNS = []
    ADBLOCK_PATTERNS = ['adblock_adg.txt']
    
    # 异步设置
    ASYNC_ENABLED = True
    MAX_CONCURRENT_FILES = 5

# ==================== 初始化日志 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== Hosts处理器 ====================
class HostsProcessor:
    """处理Hosts和AdBlock文件的处理器"""
    
    # AdBlock规则模式字符串 - 直接在类级别定义
    ADBLOCK_REGEX_STRINGS = [
        r'^\|\|([a-zA-Z0-9.-]+)\^',
        r'^([a-zA-Z0-9.-]+)\^',
        r'^\|https?://([a-zA-Z0-9.-]+)/',
    ]
    
    def __init__(self):
        self.hosts_entries: Set[Tuple[str, str]] = set()
        self.domains: Set[str] = set()
        self.stats = {
            'files_processed': 0,
            'entries_added': 0,
            'duplicates_skipped': 0,
            'hosts_rules_found': 0,
            'adblock_rules_converted': 0
        }
        
        # 预编译正则表达式
        self.hosts_regex = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\s+([^#\s]+)')
        self.comment_regex = re.compile(r'^\s*[!#]')
        self.domain_regex = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        
        # 预编译AdBlock正则表达式
        self.adblock_regexes = [re.compile(pattern) for pattern in self.ADBLOCK_REGEX_STRINGS]
    
    def is_comment_or_empty(self, line: str) -> bool:
        """检查是否是注释或空行"""
        return not line.strip() or self.comment_regex.match(line)
    
    def parse_hosts_line(self, line: str) -> List[Tuple[str, str]]:
        """解析hosts行"""
        results = []
        match = self.hosts_regex.match(line)
        if match:
            ip, domain = match.groups()
            # 处理可能的多域名情况
            domains = domain.split()
            for d in domains:
                if not d.startswith('#'):  # 跳过注释
                    results.append((ip, d))
        return results
    
    def parse_adblock_line(self, line: str) -> Optional[str]:
        """解析AdBlock行"""
        if self.is_comment_or_empty(line) or line.startswith('@@'):
            return None
            
        for regex in self.adblock_regexes:
            match = regex.match(line)
            if match:
                domain = match.group(1)
                if self.domain_regex.match(domain):
                    return domain
        return None
    
    def add_entry(self, ip: str, domain: str) -> bool:
        """添加hosts条目"""
        domain = domain.lower().strip()
        
        if domain in self.domains:
            self.stats['duplicates_skipped'] += 1
            return False
            
        self.hosts_entries.add((ip, domain))
        self.domains.add(domain)
        self.stats['entries_added'] += 1
        return True
    
    async def process_file(self, file_path: Path, is_hosts: bool = True) -> int:
        """处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        count = 0
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                async for line in f:
                    if self.is_comment_or_empty(line):
                        continue
                    
                    # 首先尝试解析为hosts规则
                    hosts_entries = self.parse_hosts_line(line)
                    if hosts_entries:
                        self.stats['hosts_rules_found'] += len(hosts_entries)
                        for ip, domain in hosts_entries:
                            if self.add_entry(ip, domain):
                                count += 1
                        continue  # 如果找到hosts规则，跳过AdBlock解析
                    
                    # 如果不是hosts文件，尝试解析AdBlock规则
                    if not is_hosts:
                        domain = self.parse_adblock_line(line)
                        if domain and self.add_entry(Config.BLOCK_IP, domain):
                            count += 1
                            self.stats['adblock_rules_converted'] += 1
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")
            return 0
        
        self.stats['files_processed'] += 1
        logger.info(f"从 {file_path} 添加了 {count} 条条目")
        return count
    
    async def process_files(self) -> int:
        """处理所有文件"""
        file_list = []
        
        # 收集hosts文件
        for pattern in Config.HOSTS_PATTERNS:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), True))
        
        # 收集AdBlock文件
        for pattern in Config.ADBLOCK_PATTERNS:
            for file_path in glob.glob(str(Config.INPUT_DIR / pattern)):
                file_list.append((Path(file_path), False))
        
        logger.info(f"找到 {len(file_list)} 个文件需要处理")
        
        # 处理文件
        total_count = 0
        for file_path, is_hosts in file_list:
            total_count += await self.process_file(file_path, is_hosts)
        
        return total_count
    
    def get_sorted_entries(self) -> List[str]:
        """获取排序后的hosts条目"""
        sorted_entries = sorted(self.hosts_entries, key=lambda x: x[1])
        return [f"{ip} {domain}" for ip, domain in sorted_entries]

# ==================== 主程序 ====================
async def main():
    """主函数"""
    logger.info("开始处理hosts和AdBlock文件")
    start_time = datetime.now()

    # 确保目录存在
    Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    processor = HostsProcessor()
    await processor.process_files()
    entries = processor.get_sorted_entries()

    # 写入输出文件
    try:
        async with aiofiles.open(Config.OUTPUT_DIR / Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for entry in entries:
                await f.write(f"{entry}\n")
        logger.info(f"写入 {len(entries)} 条hosts条目到 {Config.OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"写入输出文件时出错: {e}")
        sys.exit(1)

    # 输出统计信息
    end_time = datetime.now()
    duration = end_time - start_time
    stats = processor.stats
    
    logger.info(f"处理完成，耗时: {duration}")
    logger.info(f"文件处理: {stats['files_processed']} 个文件")
    logger.info(f"条目统计: {stats['entries_added']} 条添加, {stats['duplicates_skipped']} 条重复跳过")
    logger.info(f"规则类型: {stats['hosts_rules_found']} 条hosts规则, {stats['adblock_rules_converted']} 条AdBlock规则转换")
    logger.info(f"总计: {len(entries)} 条hosts条目")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("用户中断处理")
        sys.exit(1)
    except Exception as e:
        logger.error(f"处理过程中发生错误: {e}")
        sys.exit(1)