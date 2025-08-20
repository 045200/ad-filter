#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdGuard规则转换工具（无头部信息） - 优化版
"""

import os
import sys
import glob
import re
import logging
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, List, Set, Dict, Generator


# ============== 配置集中管理 ==============
class Config:
    """规则处理配置（适配GitHub Actions）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", "")
    INPUT_DIR = Path(os.getenv("INPUT_DIR", Path(GITHUB_WORKSPACE) / "tmp" if GITHUB_WORKSPACE else "tmp"))
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", GITHUB_WORKSPACE if GITHUB_WORKSPACE else "."))
    OUTPUT_FILE = OUTPUT_DIR / "adblock_adg.txt"
    ALLOW_FILE = OUTPUT_DIR / "allow_adg.txt"
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 4096)
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["adblock_merged.txt"]

    # 域名与格式验证
    VALID_DOMAIN_CHARS = re.compile(r'^[a-zA-Z0-9.-_*]+$')
    TOP_LEVEL_DOMAINS = re.compile(r'\.[a-zA-Z]{2,}$')


# ============== 预编译正则 ==============
class RegexPatterns:
    """预编译正则表达式，提升匹配性能"""
    # 核心规则
    ADBLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)(\^|(\$[\w,-]+))?$')
    ADBLOCK_WHITELIST = re.compile(r'^@@\|\|([\w.-]+)(\^|(\$[\w,-]+))?$')

    # 元素隐藏
    ELEMENT_HIDE = re.compile(r'^([\w.-*]+)##(.+)$')
    ELEMENT_HIDE_EXCEPT = re.compile(r'^([\w.-*]+)#@#(.+)$')

    # Hosts规则
    HOSTS_IPV4 = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
    HOSTS_IPV6 = re.compile(r'^(::1)\s+([\w.-]+)$')

    # 域名与通配符
    PLAIN_DOMAIN = re.compile(r'^(\*\.|)([\w.-]+)\.[a-zA-Z]{2,}$')
    ADBLOCK_WILDCARD = re.compile(r'^\*([\w.-]+)\*$')
    ADBLOCK_PREFIX = re.compile(r'^([\w.-]+)\*$')
    ADBLOCK_SUFFIX = re.compile(r'^\*([\w.-]+)$')

    # AdGuard特有
    ADGUARD_CSP = re.compile(r'^[\w.-]+\$csp=.+$')
    ADGUARD_REDIRECT = re.compile(r'^[\w.-]+\$redirect=.+$')
    ADGUARD_MODIFIER = re.compile(r'^[\w.-]+\$[\w,-]+=.+$')

    # 过滤项
    COMMENT = re.compile(r'^[!#]')
    EMPTY_LINE = re.compile(r'^\s*$')
    IP_ADDRESS = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger('AdGuardMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)

    fmt = '%(message)s' if os.getenv('GITHUB_ACTIONS') == 'true' else '%(asctime)s [%(levelname)s] %(message)s'
    handler.setFormatter(logging.Formatter(fmt, datefmt='%H:%M:%S'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()


# ============== GitHub Actions 分组 ==============
def gh_group(name: str):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")


# ============== 工具函数 ==============
def file_chunk_reader(file_path: Path, chunk_size: int = 10000) -> Generator[List[str], None, None]:
    """分块读取文件，降低内存占用"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


def check_file_size(file_path: Path) -> bool:
    """检查文件大小是否超出限制"""
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > Config.MAX_FILESIZE_MB:
            logger.warning(f"跳过大文件 {file_path.name}（{size_mb:.1f}MB）")
            return False
        return True
    except Exception as e:
        logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
        return False


# ============== 核心处理类 ==============
class AdGuardMerger:
    def __init__(self):
        # 初始化目录与清理旧文件
        Config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self._cleanup_outputs()
        
        # 正则与配置
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE
        
        # 去重集合（主规则+白名单）
        self.rule_cache: Set[str] = set()
        self.allow_cache: Set[str] = set()
        
        # 统计信息
        self.stats = {
            'total_lines': 0,
            'valid_rules': 0,
            'allow_rules': 0,
            'converted_hosts': 0,
            'converted_domains': 0,
            'preserved_adblock': 0,
            'element_hide': 0,
            'filtered': 0,
            'unsupported': 0
        }

    def _cleanup_outputs(self):
        """清理旧输出文件"""
        for file in [Config.OUTPUT_FILE, Config.ALLOW_FILE]:
            if file.exists():
                file.unlink()
                logger.info(f"已清理旧文件: {file.name}")

    def _discover_input_files(self) -> List[Path]:
        """发现所有符合条件的输入文件"""
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            for path in glob.glob(str(Config.INPUT_DIR / pattern)):
                file_path = Path(path)
                if file_path.is_file() and check_file_size(file_path):
                    input_files.append(file_path)
        return list(set(input_files))  # 去重文件路径

    def run(self):
        start_time = time.time()
        gh_group("===== AdGuard规则转换 =====")
        logger.info(f"输入目录: {Config.INPUT_DIR}")
        logger.info(f"输出规则: {Config.OUTPUT_FILE}")
        logger.info(f"输出白名单: {Config.ALLOW_FILE}")

        # 获取输入文件
        input_files = self._discover_input_files()
        if not input_files:
            logger.error("未找到输入文件，退出")
            gh_endgroup()
            return
        logger.info(f"发现 {len(input_files)} 个文件，开始处理...")

        # 并行处理文件
        self._process_files_parallel(input_files)

        # 写入最终结果
        self._write_results()

        # 输出统计
        self._print_summary(time.time() - start_time)

        # GitHub Actions输出变量
        self._github_output()

        gh_endgroup()

    def _process_files_parallel(self, input_files: List[Path]):
        """并行处理所有输入文件"""
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._process_single_file, file): file
                for file in input_files
            }

            for future in as_completed(futures):
                file = futures[future]
                try:
                    results = future.result()
                    # 合并结果到全局缓存
                    self._merge_results(results)
                    logger.info(f"完成处理: {file.name}")
                except Exception as e:
                    logger.error(f"处理文件失败 {file.name}: {str(e)}")

    def _process_single_file(self, file_path: Path) -> Dict:
        """处理单个文件，返回规则与统计"""
        file_stats = self.stats.copy()
        file_stats.update({k: 0 for k in file_stats})  # 重置为0

        rules = []
        allows = []

        for chunk in file_chunk_reader(file_path):
            for line in chunk:
                file_stats['total_lines'] += 1
                processed = self._process_line(line, file_stats)
                if processed:
                    rule_type, rule = processed
                    if rule_type == 'rule' and rule not in self.rule_cache:
                        rules.append(rule)
                    elif rule_type == 'allow' and rule not in self.allow_cache:
                        allows.append(rule)

        return {
            'rules': rules,
            'allows': allows,
            'stats': file_stats
        }

    def _process_line(self, line: str, stats: Dict) -> Tuple[str, str] or None:
        """处理单行规则，返回(类型, 规则)或None"""
        # 过滤空行/注释
        if self.regex.EMPTY_LINE.match(line) or self.regex.COMMENT.match(line):
            stats['filtered'] += 1
            return None

        # 长度过滤
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return None

        # 处理白名单规则（优先）
        if self.regex.ADBLOCK_WHITELIST.match(line):
            stats['allow_rules'] += 1
            return ('allow', line)

        # 处理Adblock标准规则（保留）
        if self.regex.ADBLOCK_DOMAIN.match(line):
            stats['preserved_adblock'] += 1
            return ('rule', line)

        # 处理元素隐藏规则（保留）
        if self.regex.ELEMENT_HIDE.match(line) or self.regex.ELEMENT_HIDE_EXCEPT.match(line):
            stats['element_hide'] += 1
            return ('rule', line)

        # 处理Hosts规则（转换）
        hosts_match = self.regex.HOSTS_IPV4.match(line) or self.regex.HOSTS_IPV6.match(line)
        if hosts_match:
            domain = hosts_match.group(2)
            if self._is_valid_domain(domain):
                stats['converted_hosts'] += 1
                return ('rule', f"||{domain}^")
            else:
                stats['filtered'] += 1
                return None

        # 处理纯域名（转换）
        if self.regex.PLAIN_DOMAIN.match(line):
            domain = line.strip('*').lstrip('.')  # 移除可能的通配符前缀
            if self._is_valid_domain(domain):
                stats['converted_domains'] += 1
                return ('rule', f"||{domain}^")
            else:
                stats['filtered'] += 1
                return None

        # 处理AdGuard特有规则（保留）
        if (self.regex.ADGUARD_CSP.match(line) or 
            self.regex.ADGUARD_REDIRECT.match(line) or 
            self.regex.ADGUARD_MODIFIER.match(line)):
            stats['preserved_adblock'] += 1
            return ('rule', line)

        # 未支持的规则
        stats['unsupported'] += 1
        return None

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性"""
        if self.regex.IP_ADDRESS.match(domain):
            return False
        if not Config.VALID_DOMAIN_CHARS.match(domain):
            return False
        return bool(Config.TOP_LEVEL_DOMAINS.search(domain))  # 确保有顶级域名

    def _merge_results(self, results: Dict):
        """合并单文件处理结果到全局"""
        # 合并规则
        for rule in results['rules']:
            if rule not in self.rule_cache:
                self.rule_cache.add(rule)
                self.stats['valid_rules'] += 1
        for allow in results['allows']:
            if allow not in self.allow_cache:
                self.allow_cache.add(allow)
                self.stats['allow_rules'] += 1

        # 合并统计
        for k, v in results['stats'].items():
            self.stats[k] += v

    def _write_results(self):
        """写入规则与白名单文件"""
        # 写入主规则
        with open(Config.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.rule_cache) + '\n')
        # 写入白名单
        with open(Config.ALLOW_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.allow_cache) + '\n')

    def _print_summary(self, elapsed: float):
        """输出处理摘要"""
        logger.info("\n===== 处理摘要 =====")
        logger.info(f"总处理行数: {self.stats['total_lines']}")
        logger.info(f"有效规则数: {self.stats['valid_rules']}")
        logger.info(f"白名单规则数: {self.stats['allow_rules']}")
        logger.info(f"转换自Hosts: {self.stats['converted_hosts']}")
        logger.info(f"转换自纯域名: {self.stats['converted_domains']}")
        logger.info(f"保留Adblock规则: {self.stats['preserved_adblock']}")
        logger.info(f"元素隐藏规则: {self.stats['element_hide']}")
        logger.info(f"过滤行数: {self.stats['filtered']}")
        logger.info(f"不支持规则: {self.stats['unsupported']}")
        logger.info(f"总耗时: {elapsed:.2f}秒")
        logger.info(f"处理速度: {self.stats['total_lines']/elapsed:.0f}行/秒")

    def _github_output(self):
        """设置GitHub Actions输出变量"""
        if os.getenv('GITHUB_OUTPUT'):
            with open(os.getenv('GITHUB_OUTPUT'), 'a') as f:
                f.write(f"adblock_file={Config.OUTPUT_FILE}\n")
                f.write(f"allow_file={Config.ALLOW_FILE}\n")
                f.write(f"rule_count={self.stats['valid_rules']}\n")

    def _merge_results(self, results: Dict):
        """合并单文件结果到全局统计"""
        # 合并规则缓存
        self.rule_cache.update(results['rules'])
        self.allow_cache.update(results['allows'])
        # 合并统计
        for k, v in results['stats'].items():
            self.stats[k] += v


# ============== 主入口 ==============
if __name__ == '__main__':
    try:
        merger = AdGuardMerger()
        merger.run()
        sys.exit(0)
    except Exception as e:
        logger.critical(f"脚本执行失败: {str(e)}", exc_info=not os.getenv('GITHUB_ACTIONS'))
        sys.exit(1)
