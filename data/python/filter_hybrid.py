#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""通用Adblock规则合并工具（输出拦截+白名单规则，覆盖80%常用语法）"""

import os
import sys
import glob
import re
import logging
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple, List, Set, Dict


class Config:
    """配置：聚焦通用规则，输出拦截+白名单文件"""
    GITHUB_WORKSPACE = os.getenv('GITHUB_WORKSPACE', os.getcwd())
    BASE_DIR = Path(GITHUB_WORKSPACE)
    TEMP_DIR = BASE_DIR / os.getenv('TEMP_DIR', 'tmp')
    OUTPUT_DIR = BASE_DIR / os.getenv('OUTPUT_DIR', 'output')
    
    # 核心输出文件
    BLOCK_RULES_FILE = OUTPUT_DIR / "adblock_hybrid.txt"  # 拦截规则
    ALLOW_RULES_FILE = OUTPUT_DIR / "allow_hybrid.txt"    # 白名单规则
    
    MAX_WORKERS = min(os.cpu_count() or 4, 4)
    RULE_LEN_RANGE = (3, 2048)  # 限制合理长度，覆盖多数场景
    MAX_FILESIZE_MB = 50
    INPUT_PATTERNS = ["*.txt", "*.list"]


class RegexPatterns:
    """聚焦80%常用Adblock语法（通用型）"""
    # 核心拦截规则（所有工具兼容）
    BLOCK_DOMAIN = re.compile(r'^\|\|([\w.-]+)\^?$')  # ||domain.com^（基础域名拦截）
    BLOCK_WILDCARD = re.compile(r'^[\*a-z0-9\-\./]+$', re.IGNORECASE)  # *ad/*、adserver.*（通配符）
    BLOCK_PATH = re.compile(r'^/[\w\-\./\*]+$')  # /ads/*（路径拦截）

    # 核心白名单规则（所有工具兼容）
    ALLOW_DOMAIN = re.compile(r'^@@\|\|([\w.-]+)\^?$')  # @@||domain.com^（域名白名单）
    ALLOW_WILDCARD = re.compile(r'^@@[\*a-z0-9\-\./]+$', re.IGNORECASE)  # @@*ad/*（通配符白名单）

    # 可转换规则（提升通用性）
    HOSTS_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([\w.-]+)$')  # Hosts规则转域名拦截
    PLAIN_DOMAIN = re.compile(r'^[\w.-]+\.[a.[]{2,}$')  # 纯域名（domain.com）转||domain.com^

    # 过滤项（非规则内容）
    COMMENT = re.compile(r'^[!#]')  # 注释行（! 或 # 开头）
    EMPTY_LINE = re.compile(r'^\s*$')  # 空行
    # 排除过于特殊的扩展语法（确保通用性）
    SPECIAL_EXTENSIONS = re.compile(r'(##\+js|#@#|\$csp|\$redirect)', re.IGNORECASE)


def setup_logger():
    logger = logging.getLogger('SimpleAdblockMerger')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


def check_file_size(file_path: Path) -> bool:
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > Config.MAX_FILESIZE_MB:
            logger.warning(f"跳过大文件 {file_path.name}（{size_mb:.1f}MB）")
            return False
        return True
    except Exception as e:
        logger.error(f"获取文件大小失败 {file_path.name}: {str(e)}")
        return False


class SimpleAdblockMerger:
    def __init__(self):
        # 初始化目录
        Config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # 清理旧文件
        for file in [Config.BLOCK_RULES_FILE, Config.ALLOW_RULES_FILE]:
            if file.exists():
                file.unlink()
                
        self.regex = RegexPatterns()
        self.len_min, self.len_max = Config.RULE_LEN_RANGE

    def run(self):
        start_time = time.time()
        logger.info("===== 通用Adblock规则合并工具 =====")
        logger.info(f"输入目录: {Config.TEMP_DIR}")
        logger.info(f"拦截规则输出: {Config.BLOCK_RULES_FILE}")
        logger.info(f"白名单规则输出: {Config.ALLOW_RULES_FILE}")

        # 获取输入文件
        input_files = []
        for pattern in Config.INPUT_PATTERNS:
            input_files.extend([Path(p) for p in glob.glob(str(Config.TEMP_DIR / pattern))])
        if not input_files:
            logger.error("未找到输入文件，退出")
            return

        logger.info(f"发现{len(input_files)}个文件，开始处理...")

        # 全局去重缓存
        block_cache: Set[str] = set()
        allow_cache: Set[str] = set()
        # 结果存储
        block_rules: List[str] = []
        allow_rules: List[str] = []
        # 统计
        total_stats = {'total': 0, 'block': 0, 'allow': 0, 'filtered': 0}

        # 并行处理文件
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._process_file, file): file for file in input_files}

            for future in as_completed(futures):
                file = futures[future]
                try:
                    results, stats = future.result()
                    # 全局去重并合并
                    new_block = [r for r in results['block'] if r not in block_cache]
                    new_allow = [r for r in results['allow'] if r not in allow_cache]
                    
                    block_rules.extend(new_block)
                    allow_rules.extend(new_allow)
                    
                    block_cache.update(new_block)
                    allow_cache.update(new_allow)
                    
                    # 更新统计
                    for k, v in stats.items():
                        total_stats[k] += v
                    logger.info(f"处理完成 {file.name}：拦截{stats['block']}条，白名单{stats['allow']}条")
                except Exception as e:
                    logger.error(f"处理文件{file.name}失败: {str(e)}")

        # 写入输出文件
        self._write_rules(Config.BLOCK_RULES_FILE, block_rules, "拦截规则")
        self._write_rules(Config.ALLOW_RULES_FILE, allow_rules, "白名单规则")

        # 最终统计
        elapsed = time.time() - start_time
        logger.info("\n===== 处理完成 =====")
        logger.info(f"总处理文件: {len(input_files)}个")
        logger.info(f"总拦截规则（去重后）: {len(block_rules)}条")
        logger.info(f"总白名单规则（去重后）: {len(allow_rules)}条")
        logger.info(f"过滤无效规则: {total_stats['filtered']}条")
        logger.info(f"耗时: {elapsed:.2f}秒")

    def _process_file(self, file_path: Path) -> Tuple[Dict, Dict]:
        """处理单个文件，返回拦截/白名单规则和统计"""
        if not check_file_size(file_path):
            return {'block': [], 'allow': []}, {'total': 0, 'block': 0, 'allow': 0, 'filtered': 0}

        stats = {'total': 0, 'block': 0, 'allow': 0, 'filtered': 0}
        local_block: Set[str] = set()
        local_allow: Set[str] = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    self._process_line(line, local_block, local_allow, stats)
        except Exception as e:
            logger.error(f"读取文件{file_path.name}出错: {str(e)}")

        return {
            'block': list(local_block),
            'allow': list(local_allow)
        }, stats

    def _process_line(self, line: str, block_set: Set[str], allow_set: Set[str], stats: Dict):
        """处理单行，分类为拦截/白名单规则（仅保留通用语法）"""
        stats['total'] += 1

        # 过滤注释、空行、特殊扩展语法（确保通用性）
        if (self.regex.EMPTY_LINE.match(line) or 
            self.regex.COMMENT.match(line) or 
            self.regex.SPECIAL_EXTENSIONS.search(line)):
            stats['filtered'] += 1
            return

        # 过滤长度异常的规则
        if not (self.len_min <= len(line) <= self.len_max):
            stats['filtered'] += 1
            return

        # 转换为通用规则并分类
        rule_type, rule = self._classify_rule(line)
        if not rule:
            stats['filtered'] += 1
            return

        # 单文件内去重
        if rule_type == 'block' and rule not in block_set:
            block_set.add(rule)
            stats['block'] += 1
        elif rule_type == 'allow' and rule not in allow_set:
            allow_set.add(rule)
            stats['allow'] += 1
        else:
            stats['filtered'] += 1

    def _classify_rule(self, line: str) -> Tuple[str, str]:
        """判断规则类型（拦截/白名单）并转换为通用格式"""
        # 白名单规则（以@@开头）
        if line.startswith('@@'):
            # 纯白名单域名转换为@@||domain.com^
            if self.regex.PLAIN_DOMAIN.match(line[2:]):  # 去掉@@后检查是否为纯域名
                return 'allow', f"@@||{line[2:]}^"
            # 保留通用白名单格式（@@+域名/通配符）
            if self.regex.ALLOW_DOMAIN.match(line) or self.regex.ALLOW_WILDCARD.match(line):
                return 'allow', line
            return '', ''  # 非通用白名单格式

        # 拦截规则
        else:
            # Hosts规则转换为||domain.com^
            hosts_match = self.regex.HOSTS_RULE.match(line)
            if hosts_match:
                return 'block', f"||{hosts_match.group(2)}^"
            # 纯域名转换为||domain.com^
            if self.regex.PLAIN_DOMAIN.match(line):
                return 'block', f"||{line}^"
            # 保留通用拦截格式（域名/通配符/路径）
            if self.regex.BLOCK_DOMAIN.match(line) or self.regex.BLOCK_WILDCARD.match(line) or self.regex.BLOCK_PATH.match(line):
                return 'block', line
            return '', ''  # 非通用拦截格式

    def _write_rules(self, file_path: Path, rules: List[str], name: str):
        """写入规则文件"""
        if not rules:
            logger.warning(f"无{name}可写入")
            return
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules) + '\n')
        logger.info(f"已写入{len(rules)}条{name}到 {file_path}")


if __name__ == '__main__':
    try:
        merger = SimpleAdblockMerger()
        merger.run()
    except Exception as e:
        logger.critical(f"工具运行失败: {str(e)}", exc_info=True)
        sys.exit(1)
