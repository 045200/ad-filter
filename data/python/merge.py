#!/usr/bin/env python3
"""
通用广告规则处理器 - 中间格式输出
输出标准化规则供各拦截器专用脚本使用
"""

import os
import sys
import glob
import re
import logging
from pathlib import Path
import ipaddress

# === 配置参数 ===
CONFIG = {
    'input_dir': os.getenv('TEMP_DIR', 'tmp'),
    'block_pattern': 'adblock*.txt',
    'allow_pattern': 'allow*.txt',
    'output_block': 'adblock_intermediate.txt',
    'output_allow': 'allow_intermediate.txt',

    # 通用规则验证配置
    'max_rule_length': 4096,
    'min_rule_length': 3,
    'preserve_headers': True,
    'max_filesize_mb': 50
}

# === 日志配置 ===
def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if os.getenv('GITHUB_ACTIONS') == 'true':
        formatter = logging.Formatter('%(message)s')
    else:
        formatter = logging.Formatter('[%(levelname)s] %(message)s')

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# === GitHub Actions支持 ===
def gh_group(name):
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info(f"::group::{name}")

def gh_endgroup():
    if os.getenv('GITHUB_ACTIONS') == 'true':
        logger.info("::endgroup::")

# === 规则处理器 ===
class RuleProcessor:
    def __init__(self):
        self.github_workspace = os.getenv('GITHUB_WORKSPACE', os.getcwd())
        self.repo_root = Path(self.github_workspace)

        # 设置输入输出路径
        self.input_dir = self.repo_root / CONFIG['input_dir']
        self.block_path = self.repo_root / CONFIG['output_block']
        self.allow_path = self.repo_root / CONFIG['output_allow']

        self.rule_cache = {'block': set(), 'allow': set()}
        self.stats = {'block': 0, 'allow': 0, 'duplicates': 0}

    def run(self):
        gh_group("通用规则处理器")
        logger.info(f"仓库根目录: {self.repo_root}")
        logger.info(f"输入目录: {self.input_dir}")

        logger.info("[1] 处理白名单规则...")
        self._process_files(CONFIG['allow_pattern'], self.allow_path, 'allow')

        logger.info("[2] 处理黑名单规则...")
        self._process_files(CONFIG['block_pattern'], self.block_path, 'block')  # 已修正拼写错误

        logger.info(f"处理完成: 黑名单={self.stats['block']}条 | 白名单={self.stats['allow']}条 | 去重={self.stats['duplicates']}条")
        gh_endgroup()

    def _process_files(self, pattern: str, output: Path, rule_type: str):
        buffer = []
        cache = self.rule_cache[rule_type]

        if not self.input_dir.exists():
            logger.error(f"输入目录不存在: {self.input_dir}")
            return

        for file_path in glob.glob(str(self.input_dir / pattern)):
            if not self._check_file_size(file_path):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()

                        if self._is_comment(line):
                            if CONFIG['preserve_headers']:
                                buffer.append(line)
                            continue

                        if not self._is_valid_rule(line):
                            continue

                        if line in cache:
                            self.stats['duplicates'] += 1
                            continue

                        cache.add(line)
                        buffer.append(line)
                        self.stats[rule_type] += 1

            except Exception as e:
                logger.error(f"处理文件失败 {file_path}: {str(e)}")
                continue

        try:
            with output.open('w', encoding='utf-8') as f:
                f.write('\n'.join(buffer) + '\n')
        except Exception as e:
            logger.error(f"写入输出文件失败 {output}: {str(e)}")

    @staticmethod
    def _is_comment(line: str) -> bool:
        stripped = line.strip()
        return not stripped or stripped.startswith(('!', '#', '[Adblock'))

    @staticmethod
    def _is_valid_rule(line: str) -> bool:
        return CONFIG['min_rule_length'] <= len(line) <= CONFIG['max_rule_length']

    @staticmethod
    def _check_file_size(file_path: str) -> bool:
        try:
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if size_mb > CONFIG['max_filesize_mb']:
                logger.warning(f"跳过大文件: {Path(file_path).name} ({size_mb:.1f}MB)")
                return False
            return True
        except Exception:
            return False

if __name__ == '__main__':
    processor = RuleProcessor()
    processor.run()
