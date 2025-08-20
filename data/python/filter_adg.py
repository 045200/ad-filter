#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
专属拦截器规则转换工具
- 保留拦截器已支持的Adblock原生语法
- 转换不支持的规则类型（Hosts、非标准格式等）
- 补充处理未涵盖的规则语法（通配符、路径规则等）
"""

import os
import sys
import re
import logging
import time
from pathlib import Path
from typing import Tuple, List, Set, Dict


# ============== 配置集中管理 ==============
class Config:
    # 输入输出配置
    INPUT_FILE = Path(os.getenv("INPUT_FILE", "adblock_merged.txt"))
    OUTPUT_FILE = Path(os.getenv("OUTPUT_FILE", "interceptor_rules.txt"))
    # 拦截器原生支持的规则类型（不转换）
    SUPPORTED_ADBLOCK_TYPES = {
        "domain_rule": re.compile(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}\^?(\$[a-z0-9_,=;]+)?$', re.IGNORECASE),
        "element_rule": re.compile(r'^([a-z0-9-]+\.)+[a-z]{2,}##.+$', re.IGNORECASE),
        "whitelist_rule": re.compile(r'^@@\|\|([a-z0-9-]+\.)+[a-z]{2,}\^?(\$[a-z0-9_,=;]+)?$', re.IGNORECASE),
        "adguard_extra": re.compile(r'^([a-z0-9-]+\.)+[a-z]{2,}\$(csp|redirect)=', re.IGNORECASE),
        "modifier_rule": re.compile(r'^\|\|([a-z0-9-]+\.)+[a-z]{2,}(/.*)?\$[a-z0-9_,=;]+$', re.IGNORECASE)
    }
    # 转换规则映射（键：规则类型，值：转换函数）
    CONVERSION_MAP = {
        "hosts": lambda d: f"||{d}^",
        "plain_domain": lambda d: f"||{d}^",
        "wildcard_simple": lambda d: f"||{d}^",  # 简单通配符（*domain.com → ||domain.com^）
        "invalid_format": lambda r: None  # 无效格式不转换
    }
    # 规则长度范围
    RULE_LEN_RANGE = (3, 4096)
    # 忽略的规则类型（注释、空行等）
    IGNORE_PATTERNS = [
        re.compile(r'^[!#]'),  # 注释
        re.compile(r'^\s*$')   # 空行
    ]


# ============== 日志配置 ==============
def setup_logger():
    logger = logging.getLogger('InterceptorConverter')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)
    return logger

logger = setup_logger()


# ============== 核心转换类 ==============
class InterceptorConverter:
    def __init__(self):
        # 初始化路径
        self.input_path = Config.INPUT_FILE
        self.output_path = Config.OUTPUT_FILE
        # 去重缓存
        self.rule_cache: Set[str] = set()
        # 统计信息
        self.stats = {
            "total": 0,
            "supported": 0,  # 拦截器原生支持，不转换
            "converted": 0,  # 已转换
            "ignored": 0,    # 忽略（注释、空行等）
            "invalid": 0     # 无效规则，无法转换
        }

    def run(self):
        """主运行函数"""
        start_time = time.time()
        logger.info("===== 专属拦截器规则转换开始 =====")
        logger.info(f"输入文件: {self.input_path}")
        logger.info(f"输出文件: {self.output_path}")

        if not self.input_path.exists():
            logger.error(f"输入文件不存在: {self.input_path}")
            return

        # 读取并处理规则
        processed_rules = self._process_rules()

        # 写入输出
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(processed_rules) + '\n')

        # 输出统计
        elapsed = time.time() - start_time
        logger.info("\n===== 转换统计 =====")
        logger.info(f"总规则数: {self.stats['total']}")
        logger.info(f"原生支持(不转换): {self.stats['supported']}")
        logger.info(f"成功转换: {self.stats['converted']}")
        logger.info(f"忽略规则(注释/空行): {self.stats['ignored']}")
        logger.info(f"无效规则: {self.stats['invalid']}")
        logger.info(f"耗时: {elapsed:.2f}秒")
        logger.info(f"输出规则数(去重后): {len(processed_rules)}")

    def _process_rules(self) -> List[str]:
        """处理所有规则并返回转换后列表"""
        processed = []
        with open(self.input_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                self.stats["total"] += 1
                # 处理单条规则
                result = self._process_line(line)
                if result and result not in self.rule_cache:
                    processed.append(result)
                    self.rule_cache.add(result)
        return processed

    def _process_line(self, line: str) -> str:
        """处理单条规则，返回转换后结果或原规则（支持的类型）"""
        # 检查是否为忽略类型（注释、空行）
        if any(pattern.match(line) for pattern in Config.IGNORE_PATTERNS):
            self.stats["ignored"] += 1
            return ""

        # 检查规则长度
        len_min, len_max = Config.RULE_LEN_RANGE
        if not (len_min <= len(line) <= len_max):
            self.stats["invalid"] += 1
            return ""

        # 检查是否为拦截器原生支持的规则类型（不转换）
        if self._is_supported_type(line):
            self.stats["supported"] += 1
            return line

        # 识别规则类型并转换
        rule_type, content = self._identify_rule_type(line)
        if rule_type in Config.CONVERSION_MAP:
            converted = Config.CONVERSION_MAP[rule_type](content)
            if converted:
                self.stats["converted"] += 1
                return converted

        # 无法识别的规则（无效）
        self.stats["invalid"] += 1
        return ""

    def _is_supported_type(self, line: str) -> bool:
        """判断是否为拦截器原生支持的规则类型"""
        for pattern in Config.SUPPORTED_ADBLOCK_TYPES.values():
            if pattern.match(line):
                return True
        return False

    def _identify_rule_type(self, line: str) -> Tuple[str, str]:
        """识别规则类型，返回类型和核心内容"""
        # Hosts规则（0.0.0.0/127.0.0.1/::1 域名）
        hosts_match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE)
        if hosts_match:
            return "hosts", hosts_match.group(2)

        # 纯域名（无任何前缀后缀）
        plain_match = re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', line, re.IGNORECASE)
        if plain_match and self._is_valid_domain(plain_match.group(0)):
            return "plain_domain", plain_match.group(0)

        # 简单通配符规则（*domain.com 或 domain.com* 或 *domain.com*）
        wildcard_match = re.match(r'^\*?([a-z0-9-]+\.)+[a-z]{2,}\*?$', line, re.IGNORECASE)
        if wildcard_match:
            # 提取纯域名部分（去除首尾*）
            domain = wildcard_match.group(1).strip('*')
            if self._is_valid_domain(domain):
                return "wildcard_simple", domain

        # 其他无法识别的类型（视为无效）
        return "invalid_format", line

    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名有效性（基础验证）"""
        if len(domain) > 253:
            return False
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            return False
        # 检查每个域名片段
        parts = domain.split('.')
        for part in parts:
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', part, re.IGNORECASE):
                return False
        return True


# ============== 主入口 ==============
if __name__ == '__main__':
    try:
        converter = InterceptorConverter()
        converter.run()
    except Exception as e:
        logger.critical(f"转换失败: {str(e)}", exc_info=True)
        sys.exit(1)
