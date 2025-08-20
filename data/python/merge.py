#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Adblock规则合并去重工具 - 高性能优化版
针对GitHub Actions 4核16G环境优化，专注于初筛和标准化转换
"""

import os
import sys
import glob
import re
import logging
import time
import hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, List, Set, Dict, Generator
from collections import defaultdict


# ============== 配置集中管理 ==============
class Config:
    """规则处理配置参数（针对4核16G环境优化）"""
    # 路径配置
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')  # 输入输出目录
    OUTPUT_FILE = TEMP_DIR / "adblock_merged.txt"  # 最终输出文件

    # 处理参数（针对4核16G优化）
    MAX_WORKERS = 4  # 与CPU核心数匹配
    CHUNK_SIZE = 10000  # 处理文件的块大小（行数）
    RULE_LEN_RANGE = (4, 253)  # 域名长度范围（最小，最大）.com是4字符，最大域名253字符
    MAX_FILESIZE_MB = 100  # 单个文件最大处理大小（MB）- 增加以适应大文件
    INPUT_PATTERNS = ["*.txt", "*.list"]  # 输入文件匹配模式

    # 域名黑名单（不过滤的规则）
    DOMAIN_BLACKLIST = {
        'localhost', 'localdomain', 'example.com', 'example.org', 
        'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
        '::1', '255.255.255.255', 'localhost.localdomain'
    }

    # 性能调优参数
    MAX_RULES_IN_MEMORY = 2000000  # 内存中最大规则数（约200万条）
    HASH_SALT = "adblock_salt_2024"  # 哈希盐值，用于减少哈希碰撞


# ============== 预编译正则 ==============
class RegexPatterns:
    """预编译正则表达式，提高匹配性能"""
    # 基础规则
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    
    # Adblock规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    
    # 过滤项
    COMMENT = re.compile(r'^[!#]')  # 注释行（! 或 # 开头）
    EMPTY_LINE = re.compile(r'^\s*$')  # 空行
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')  # IP地址


# ============== 日志配置 ==============
def setup_logger():
    """配置高性能日志"""
    logger = logging.getLogger('AdblockMerger')
    logger.setLevel(logging.INFO)
    
    # 使用内存高效的处理器
    handler = logging.StreamHandler(sys.stdout)
    
    # 适配GitHub Actions日志格式
    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '[%(levelname)s] %(message)s'
    handler.setFormatter(logging.Formatter(fmt))
    
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ============== 高性能工具函数 ==============
def gh_group(name: str):
    """GitHub Actions分组显示（轻量级实现）"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    """结束GitHub Actions分组"""
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


def file_chunk_reader(file_path: Path, chunk_size: int = Config.CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件，减少内存使用"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:  # 处理最后一块
            yield chunk


def efficient_hash(rule: str) -> str:
    """高效哈希函数，用于去重"""
    # 使用更快的哈希算法，加盐减少碰撞
    return hashlib.md5((rule + Config.HASH_SALT).encode('utf-8')).hexdigest()


# ============== 规则处理核心 ==============
class AdblockMerger:
    def __init__(self):
        # 确保目录存在
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()  # 用于文件内容去重

    def run(self):
        """主流程：处理所有规则文件，合并去重后输出"""
        start_time = time.time()
        gh_group("Adblock规则合并去重 - 高性能模式")
        logger.info(f"工作目录: {Config.TEMP_DIR}")
        
        # 获取所有输入文件
        self._discover_input_files()
        if not self.input_files:
            logger.error("未找到输入文件")
            gh_endgroup()
            return

        logger.info(f"发现 {len(self.input_files)} 个输入文件，开始处理...")
        
        # 处理文件（并行+分块）
        all_rules, total_stats = self._process_files_parallel()
        
        # 写入最终结果
        self._write_output(all_rules)
        
        # 清理输入文件
        self._cleanup_input_files()

        # 输出汇总信息
        elapsed = time.time() - start_time
        self._print_summary(total_stats, elapsed)
        
        # GitHub Actions输出
        if os.getenv('GITHUB_ACTIONS') == 'true':
            self._github_actions_output()
            
        gh_endgroup()

    def _discover_input_files(self):
        """发现输入文件，并过滤重复内容"""
        for pattern in Config.INPUT_PATTERNS:
            for file_path in glob.glob(str(Config.TEMP_DIR / pattern)):
                path_obj = Path(file_path)
                if path_obj == Config.OUTPUT_FILE:  # 跳过输出文件
                    continue
                    
                # 文件内容去重：计算文件哈希，跳过内容完全相同的文件
                file_hash = self._calculate_file_hash(path_obj)
                if file_hash in self.file_hashes:
                    logger.info(f"跳过重复文件: {path_obj.name}")
                    continue
                    
                self.file_hashes.add(file_hash)
                self.input_files.append(path_obj)

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件内容的哈希值，用于去重"""
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                # 只读取文件前部分和文件大小作为哈希，平衡准确性和性能
                hasher.update(f.read(1024))
                hasher.update(str(file_path.stat().st_size).encode())
                return hasher.hexdigest()
        except Exception:
            return str(file_path)  # 出错时使用文件名作为fallback

    def _process_files_parallel(self) -> Tuple[List[str], Dict]:
        """并行处理所有文件"""
        all_rules = []
        global_cache = set()
        total_stats = self._empty_stats()
        processed_files = 0
        
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # 提交所有文件处理任务
            future_to_file = {}
            for file_path in self.input_files:
                future = executor.submit(self._process_file, file_path)
                future_to_file[future] = file_path

            # 处理完成的任务
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    rules, stats = future.result()
                    # 全局去重
                    new_rules = []
                    for rule in rules:
                        rule_hash = efficient_hash(rule)
                        if rule_hash not in global_cache:
                            new_rules.append(rule)
                            global_cache.add(rule_hash)
                    
                    all_rules.extend(new_rules)
                    total_stats = self._merge_stats(total_stats, stats)
                    
                    processed_files += 1
                    if processed_files % 5 == 0:  # 每处理5个文件报告一次进度
                        logger.info(f"进度: {processed_files}/{len(self.input_files)} 文件, "
                                   f"当前规则数: {len(all_rules)}")
                                   
                except Exception as e:
                    logger.error(f"处理文件 {file_path.name} 失败: {str(e)}")
                    
                # 内存控制：如果规则数过多，先写入临时文件
                if len(all_rules) >= Config.MAX_RULES_IN_MEMORY:
                    self._write_temp_rules(all_rules)
                    all_rules = []
                    logger.info("内存控制: 规则数超限，已写入临时文件")

        return all_rules, total_stats

    def _process_file(self, file_path: Path) -> Tuple[List[str], Dict]:
        """处理单个文件，返回有效规则和统计信息"""
        stats = self._empty_stats()
        rules = []
        
        # 检查文件大小
        try:
            file_size = file_path.stat().st_size
            if file_size > Config.MAX_FILESIZE_MB * 1024 * 1024:
                logger.warning(f"跳过过大文件: {file_path.name} ({file_size/(1024*1024):.1f}MB)")
                return [], stats
        except OSError:
            return [], stats

        # 分块处理文件
        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                rule = self._process_line(line, stats)
                if rule:
                    rules.append(rule)
                    
        return rules, stats

    def _process_line(self, line: str, stats: Dict) -> str:
        """处理单行规则，返回标准化后的Adblock规则"""
        stats['total'] += 1

        # 快速过滤：空行和注释
        if not line or self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return ""

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return ""

        # 转换为Adblock格式
        return self._to_adblock(line, stats) or ""

    def _to_adblock(self, line: str, stats: Dict) -> str:
        """将规则转换为纯净的Adblock域名规则"""
        # 1. 转换Hosts规则
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                stats['converted_hosts'] += 1
                return f"||{domain}^"

        # 2. 转换纯域名
        elif self.regex.PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                stats['converted_plain'] += 1
                return f"||{line}^"

        # 3. 识别标准Adblock规则
        elif self.regex.ADBLOCK_DOMAIN.match(line) or self.regex.ADBLOCK_WHITELIST.match(line):
            # 提取域名部分进行验证
            domain_match = re.search(r'\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
            if domain_match and self._is_valid_domain(domain_match.group(1)):
                stats['native_adblock'] += 1
                return line

        # 4. 无法识别的规则
        stats['unsupported'] += 1
        return ""

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        # 过滤黑名单域名
        if domain in Config.DOMAIN_BLACKLIST:
            return False
            
        # 过滤IP地址
        if self.regex.IP_ADDRESS.match(domain):
            return False
            
        # 基本长度检查
        if len(domain) < 4 or len(domain) > 253:
            return False
            
        # 必须包含点号且不以点号开头或结尾
        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
            return False
            
        return True

    def _write_output(self, rules: List[str]):
        """写入最终输出文件"""
        # 如果有多批规则（由于内存控制），先合并
        temp_files = list(Config.TEMP_DIR.glob("temp_rules_*.txt"))
        if temp_files:
            logger.info(f"合并 {len(temp_files)} 个临时文件...")
            with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
                # 先写入内存中的规则
                if rules:
                    out_f.write('\n'.join(rules) + '\n')
                
                # 追加临时文件内容
                for temp_file in temp_files:
                    with open(temp_file, 'r', encoding='utf-8') as in_f:
                        out_f.write(in_f.read())
                    temp_file.unlink()  # 删除临时文件
        else:
            # 直接写入内存中的规则
            with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(rules) + '\n')
                
        logger.info(f"已写入 {len(rules)} 条规则到 {Config.OUTPUT_FILE}")

    def _write_temp_rules(self, rules: List[str]):
        """将规则写入临时文件（内存控制）"""
        temp_file = Config.TEMP_DIR / f"temp_rules_{int(time.time())}.txt"
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')

    def _cleanup_input_files(self):
        """清理输入文件"""
        gh_group("清理输入文件")
        deleted, skipped = 0, 0
        
        for file_path in self.input_files:
            if file_path == Config.OUTPUT_FILE or not file_path.exists():
                skipped += 1
                continue
                
            try:
                file_path.unlink()
                deleted += 1
            except Exception as e:
                logger.warning(f"删除失败 {file_path.name}: {str(e)}")
                skipped += 1
                
        logger.info(f"清理完成: 删除 {deleted} 个文件, 跳过 {skipped} 个文件")
        gh_endgroup()

    def _print_summary(self, stats: Dict, elapsed: float):
        """输出处理摘要"""
        logger.info("\n===== 处理摘要 =====")
        logger.info(f"处理文件: {len(self.input_files)} 个")
        logger.info(f"总行数: {stats['total']} 行")
        logger.info(f"有效规则: {stats['converted_hosts'] + stats['converted_plain'] + stats['native_adblock']} 条")
        logger.info(f"  - 来自Hosts转换: {stats['converted_hosts']}")
        logger.info(f"  - 来自纯域名转换: {stats['converted_plain']}")
        logger.info(f"  - 原生Adblock规则: {stats['native_adblock']}")
        logger.info(f"过滤行数: {stats['filtered'] + stats['unsupported']}")
        logger.info(f"  - 注释/空行: {stats['filtered']}")
        logger.info(f"  - 不支持格式: {stats['unsupported']}")
        logger.info(f"耗时: {elapsed:.2f} 秒")
        logger.info(f"平均速度: {stats['total']/elapsed:.0f} 行/秒")

    def _github_actions_output(self):
        """GitHub Actions输出"""
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"merged_file={Config.OUTPUT_FILE}\n")
                f.write(f"temp_dir={Config.TEMP_DIR}\n")

    # ============== 统计辅助方法 ==============
    @staticmethod
    def _empty_stats() -> Dict:
        return {
            'total': 0, 
            'filtered': 0, 
            'unsupported': 0,
            'converted_hosts': 0,
            'converted_plain': 0,
            'native_adblock': 0
        }

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        for key in total:
            total[key] += new[key]
        return total


# ============== 主入口 ==============
if __name__ == '__main__':
    try:
        merger = AdblockMerger()
        merger.run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"脚本执行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)