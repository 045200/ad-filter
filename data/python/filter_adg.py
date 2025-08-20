#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AdGuard规则转换工具（高性能优化版）"""

import os
import sys
import glob
import re
import logging
import time
import hashlib
from pathlib import Path
from typing import Tuple, List, Set, Dict, Generator
from collections import defaultdict


class Config:
    """配置参数（针对4核16G环境优化）"""
    # 优先读取GitHub环境变量
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    # 路径配置 - 使用与初筛脚本相同的目录结构
    DATA_DIR = Path(GITHUB_WORKSPACE) / os.getenv('DATA_DIR', 'data')
    TEMP_DIR = Path(GITHUB_WORKSPACE) / os.getenv('TEMP_DIR', 'tmp')
    
    # 输出文件 - 放在根目录
    OUTPUT_FILE = Path(GITHUB_WORKSPACE) / "adblock_adg.txt"  # 拦截规则
    ALLOW_FILE = Path(GITHUB_WORKSPACE) / "allow_adg.txt"     # 白名单规则
    
    # 性能参数
    MAX_WORKERS = 4  # 与CPU核心数匹配
    CHUNK_SIZE = 50000  # 处理文件的块大小（行数）
    RULE_LEN_RANGE = (4, 253)  # 域名长度范围
    MAX_FILESIZE_MB = 100  # 单个文件最大处理大小（MB）
    INPUT_PATTERNS = ["adblock_merged.txt"]
    
    # 内存控制
    MAX_RULES_IN_MEMORY = 1000000  # 内存中最大规则数
    HASH_SALT = "adguard_salt_2024"  # 哈希盐值
    
    # 域名黑名单（不过滤的规则）
    DOMAIN_BLACKLIST = {
        'localhost', 'localdomain', 'example.com', 'example.org', 
        'example.net', 'test.com', 'invalid.com', '0.0.0.0', '127.0.0.1',
        '::1', '255.255.255.255', 'localhost.localdomain'
    }


class RegexPatterns:
    """预编译正则表达式，提高匹配性能"""
    # 基础规则
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    PLAIN_DOMAIN = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
    
    # Adblock规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
    
    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')  # IP地址
    
    # AdGuard特定规则
    ADGUARD_CSP = re.compile(r'^.+\$csp=')
    ADGUARD_REDIRECT = re.compile(r'^.+\$redirect=')
    ADGUARD_OTHER = re.compile(r'^.+\$(popup|document|script|stylesheet|object|xmlhttprequest|subdocument|ping|media|other|webrtc|websocket)$')


def setup_logger():
    """配置高性能日志"""
    logger = logging.getLogger('AdGuardMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('[%(levelname)s] %(message)s')

    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


def gh_group(name: str):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::endgroup::")


def file_chunk_reader(file_path: Path, chunk_size: int = Config.CHUNK_SIZE) -> Generator[List[str], None, None]:
    """分块读取文件，减少内存使用"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            chunk = []
            for line in f:
                chunk.append(line.strip())
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:  # 处理最后一块
                yield chunk
    except Exception as e:
        logger.error(f"读取文件失败 {file_path}: {str(e)}")
        yield []


def efficient_hash(rule: str) -> str:
    """高效哈希函数，用于去重"""
    return hashlib.md5((rule + Config.HASH_SALT).encode('utf-8')).hexdigest()


class AdGuardMerger:
    def __init__(self):
        # 确保目录存在
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        # 清理原有输出文件
        for output_file in [Config.OUTPUT_FILE, Config.ALLOW_FILE]:
            if output_file.exists():
                output_file.unlink()
                
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE
        self.input_files = []
        self.file_hashes = set()  # 用于文件内容去重

    def run(self):
        """主处理流程"""
        start_time = time.time()
        gh_group("AdGuard规则转换 - 高性能模式")
        logger.info(f"工作目录: {Config.TEMP_DIR}")
        logger.info(f"输出目录: {Path(Config.GITHUB_WORKSPACE)}")

        # 获取输入文件
        self._discover_input_files()
        if not self.input_files:
            logger.error("未找到输入文件")
            gh_endgroup()
            return

        logger.info(f"发现 {len(self.input_files)} 个输入文件，开始处理...")
        
        # 处理文件
        rules, allows, stats = self._process_files()
        
        # 写入输出文件
        self._write_output_files(rules, allows)
        
        # 输出统计信息
        elapsed = time.time() - start_time
        self._print_summary(stats, elapsed, len(rules), len(allows))
        
        # GitHub Actions输出
        if os.getenv('GITHUB_ACTIONS') == 'true':
            self._github_actions_output()
            
        gh_endgroup()

    def _discover_input_files(self):
        """发现输入文件，并过滤重复内容"""
        for pattern in Config.INPUT_PATTERNS:
            for file_path in glob.glob(str(Config.TEMP_DIR / pattern)):
                path_obj = Path(file_path)
                if path_obj == Config.OUTPUT_FILE or path_obj == Config.ALLOW_FILE:
                    continue  # 跳过输出文件
                    
                if path_obj.is_file():
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

    def _process_files(self) -> Tuple[List[str], List[str], Dict]:
        """处理所有文件"""
        rules = []
        allows = []
        rules_cache = set()
        allows_cache = set()
        stats = self._empty_stats()
        
        for file_path in self.input_files:
            file_rules, file_allows, file_stats = self._process_file(file_path)
            
            # 全局去重
            new_rules = []
            for rule in file_rules:
                rule_hash = efficient_hash(rule)
                if rule_hash not in rules_cache:
                    new_rules.append(rule)
                    rules_cache.add(rule_hash)
            
            new_allows = []
            for allow in file_allows:
                allow_hash = efficient_hash(allow)
                if allow_hash not in allows_cache:
                    new_allows.append(allow)
                    allows_cache.add(allow_hash)
            
            # 添加到结果
            rules.extend(new_rules)
            allows.extend(new_allows)
            
            # 合并统计信息
            stats = self._merge_stats(stats, file_stats)
            
            # 内存控制
            if len(rules) + len(allows) >= Config.MAX_RULES_IN_MEMORY:
                self._write_temp_data(rules, allows)
                rules, allows = [], []
                logger.info("内存控制: 数据量超限，已写入临时文件")
        
        return rules, allows, stats

    def _process_file(self, file_path: Path) -> Tuple[List[str], List[str], Dict]:
        """处理单个文件"""
        stats = self._empty_stats()
        rules = []
        allows = []
        rules_cache = set()
        allows_cache = set()
        
        # 检查文件大小
        try:
            file_size = file_path.stat().st_size
            if file_size > Config.MAX_FILESIZE_MB * 1024 * 1024:
                logger.warning(f"跳过过大文件: {file_path.name} ({file_size/(1024*1024):.1f}MB)")
                return [], [], stats
        except OSError:
            return [], [], stats

        # 分块处理文件
        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                rule, is_allow = self._process_line(line, stats)
                if rule:
                    rule_hash = efficient_hash(rule)
                    if is_allow:
                        if rule_hash not in allows_cache:
                            allows.append(rule)
                            allows_cache.add(rule_hash)
                    else:
                        if rule_hash not in rules_cache:
                            rules.append(rule)
                            rules_cache.add(rule_hash)
        
        logger.info(f"处理完成: {file_path.name} - 规则: {len(rules)}, 白名单: {len(allows)}")
        return rules, allows, stats

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, bool]:
        """处理单行规则"""
        stats['total'] += 1

        # 快速过滤：空行和注释
        if not line or self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None, False

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None, False

        # 转换为AdGuard格式
        adguard_rule, is_allow = self._to_adguard(line)
        if not adguard_rule:
            stats['unsupported'] += 1
            return None, False

        stats['valid'] += 1
        return adguard_rule, is_allow

    def _to_adguard(self, line: str) -> Tuple[str, bool]:
        """将规则转换为AdGuard格式"""
        # 白名单规则（@@开头）
        if line.startswith('@@'):
            normalized = line[2:]
            if self.regex.ADBLOCK_DOMAIN.match(normalized):
                return normalized, True
            return line, True

        # Hosts规则转换
        hosts_match = self.regex.HOSTS_RULE.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                return f"||{domain}^", False

        # 纯域名转换
        if self.regex.PLAIN_DOMAIN.match(line):
            if self._is_valid_domain(line):
                return f"||{line}^", False

        # 保留AdGuard特有规则
        if (self.regex.ADGUARD_CSP.match(line) or 
            self.regex.ADGUARD_REDIRECT.match(line) or 
            self.regex.ADGUARD_OTHER.match(line)):
            return line, False

        # 保留标准Adblock规则
        if self.regex.ADBLOCK_DOMAIN.match(line):
            # 提取域名部分进行验证
            domain_match = re.search(r'\|\|([a-z0-9.-]+)\^?', line, re.IGNORECASE)
            if domain_match and self._is_valid_domain(domain_match.group(1)):
                return line, False

        return None, False

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

    def _write_output_files(self, rules: List[str], allows: List[str]):
        """写入输出文件"""
        # 检查是否有临时文件需要合并
        temp_files = list(Path(Config.GITHUB_WORKSPACE).glob("temp_rules_*.txt"))
        temp_allow_files = list(Path(Config.GITHUB_WORKSPACE).glob("temp_allow_*.txt"))
        
        # 写入规则文件
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            # 先写入内存中的规则
            if rules:
                f.write('\n'.join(rules) + '\n')
            
            # 追加临时文件内容
            for temp_file in temp_files:
                try:
                    with open(temp_file, 'r', encoding='utf-8') as in_f:
                        f.write(in_f.read())
                    temp_file.unlink()
                except Exception as e:
                    logger.warning(f"处理临时文件失败 {temp_file.name}: {str(e)}")
                
        # 写入白名单文件
        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            # 先写入内存中的白名单
            if allows:
                f.write('\n'.join(allows) + '\n')
            
            # 追加临时文件内容
            for temp_file in temp_allow_files:
                try:
                    with open(temp_file, 'r', encoding='utf-8') as in_f:
                        f.write(in_f.read())
                    temp_file.unlink()
                except Exception as e:
                    logger.warning(f"处理临时文件失败 {temp_file.name}: {str(e)}")
                
        logger.info(f"已写入规则: {Config.OUTPUT_FILE.name} ({len(rules)} 条)")
        logger.info(f"已写入白名单: {Config.ALLOW_FILE.name} ({len(allows)} 条)")

    def _write_temp_data(self, rules: List[str], allows: List[str]):
        """将数据写入临时文件（内存控制）"""
        timestamp = int(time.time())
        
        if rules:
            temp_file = Path(Config.GITHUB_WORKSPACE) / f"temp_rules_{timestamp}.txt"
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(rules) + '\n')
            except Exception as e:
                logger.error(f"写入临时文件失败: {str(e)}")
                
        if allows:
            temp_file = Path(Config.GITHUB_WORKSPACE) / f"temp_allow_{timestamp}.txt"
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(allows) + '\n')
            except Exception as e:
                logger.error(f"写入临时文件失败: {str(e)}")

    def _print_summary(self, stats: Dict, elapsed: float, rule_count: int, allow_count: int):
        """输出处理摘要"""
        logger.info("\n===== 处理摘要 =====")
        logger.info(f"处理文件: {len(self.input_files)} 个")
        logger.info(f"总行数: {stats['total']} 行")
        logger.info(f"有效规则: {stats['valid']} 条")
        logger.info(f"  - 拦截规则: {rule_count} 条")
        logger.info(f"  - 白名单规则: {allow_count} 条")
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
                f.write(f"adguard_file={Config.OUTPUT_FILE}\n")
                f.write(f"adguard_allow_file={Config.ALLOW_FILE}\n")

    @staticmethod
    def _empty_stats() -> Dict:
        return {'total': 0, 'valid': 0, 'filtered': 0, 'unsupported': 0}

    @staticmethod
    def _merge_stats(total: Dict, new: Dict) -> Dict:
        for key in total:
            total[key] += new[key]
        return total


if __name__ == '__main__':
    try:
        merger = AdGuardMerger()
        merger.run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"脚本执行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)