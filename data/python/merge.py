#!/usr/bin/env python3
"""
AdGuard规则合并去重脚本 - 专注于AdGuard语法处理
功能：合并多个AdGuard规则文件，去除重复规则，保持原有路径和文件名
作者：AI助手
日期：2025-09-01
版本：2.0
"""

import os
import re
import json
import requests
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional, Any, Union
from pybloom_live import ScalableBloomFilter
from dataclasses import dataclass, field
import logging
import sys
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AdGuardConfig:
    """配置类 - 保持原有路径和文件名"""
    # 基础路径配置（保持原样）
    INPUT_DIR: Path = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR: Path = Path(os.getenv('OUTPUT_DIR', './'))

    # GitHub Actions特定环境变量
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    GITHUB_REPOSITORY: str = os.getenv('GITHUB_REPOSITORY', 'unknown/repository')
    GITHUB_SHA: str = os.getenv('GITHUB_SHA', 'unknown')
    GITHUB_REF: str = os.getenv('GITHUB_REF', 'unknown')
    GITHUB_WORKFLOW: str = os.getenv('GITHUB_WORKFLOW', 'unknown')
    
    # 文件模式配置（保持原样）
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter'])
    OUTPUT_BLOCK: str = 'adblock_adg.txt'  # 保持原文件名
    OUTPUT_ALLOW: str = 'allow_adg.txt'    # 保持原文件名
    
    # 布隆过滤器配置（保持原样）
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.0001'))
    
    # 规则处理配置（保持原样）
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    
    # 语法数据库配置（保持原样）
    SYNTAX_DB_FILE: str = "adblock_syntax_db.json"
    
    # 性能配置
    MAX_RULES_PER_FILE: int = int(os.getenv('MAX_RULES_PER_FILE', '50000'))
    DOWNLOAD_TIMEOUT: int = int(os.getenv('DOWNLOAD_TIMEOUT', '30'))


class AdGuardSyntaxDatabase:
    """AdGuard语法数据库"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_patterns = {}
        self.rule_types = {}
        self.modifiers = {}
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载语法数据库"""
        # 首先尝试从脚本同目录加载语法数据库
        script_dir = Path(__file__).parent
        db_path = script_dir / self.config.SYNTAX_DB_FILE

        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    db_data = json.load(f)
                    self.syntax_patterns = db_data.get('syntax_patterns', {})
                    self.rule_types = db_data.get('rule_types', {})
                    self.modifiers = db_data.get('modifiers', {})
                logger.info(f"从脚本目录加载语法数据库: {len(self.syntax_patterns)} 个模式")
                return
            except Exception as e:
                logger.error(f"加载脚本目录语法数据库失败: {e}")

        # 然后尝试从输入目录加载语法数据库
        db_path = self.config.INPUT_DIR / self.config.SYNTAX_DB_FILE

        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    db_data = json.load(f)
                    self.syntax_patterns = db_data.get('syntax_patterns', {})
                    self.rule_types = db_data.get('rule_types', {})
                    self.modifiers = db_data.get('modifiers', {})
                logger.info(f"从输入目录加载语法数据库: {len(self.syntax_patterns)} 个模式")
                return
            except Exception as e:
                logger.error(f"加载输入目录语法数据库失败: {e}")

        # 如果都没有找到，使用内置的AdGuard语法规则
        logger.warning("未找到语法数据库文件，使用内置AdGuard语法规则")
        self.load_adguard_syntax()

        # 尝试保存基本语法数据库到脚本目录
        try:
            self.save_syntax_database(script_dir / self.config.SYNTAX_DB_FILE)
        except Exception as e:
            logger.error(f"保存AdGuard语法数据库失败: {e}")

    def save_syntax_database(self, db_path: Path):
        """保存语法数据库到文件"""
        db_data = {
            'syntax_patterns': self.syntax_patterns,
            'rule_types': self.rule_types,
            'modifiers': self.modifiers,
            'version': '2.0',
            'description': 'AdGuard语法数据库'
        }

        with open(db_path, 'w', encoding='utf-8') as f:
            json.dump(db_data, f, ensure_ascii=False, indent=2)

        logger.info(f"语法数据库已保存到: {db_path}")

    def load_adguard_syntax(self):
        """加载AdGuard语法规则"""
        # AdGuard特定规则模式
        self.syntax_patterns = {
            'domain_rule': r'^\|\|([^\^]+)\^',
            'url_rule': r'^\|([^\|]+)\|',
            'element_hiding': r'^([^#]+)##([^#]+)',
            'exception_rule': r'^@@',
            'regex_rule': r'^/(.+)/$',
            'comment': r'^!',
            'options': r'\$(.+)$',
            'adguard_specific': r'^#\$#',  # AdGuard特定规则
            'html_filtering': r'^#@?#',    # HTML过滤规则
            'scriptlet': r'^#%#',          # 脚本规则
            'extension': r'^#\?#',         # 扩展语法
        }

        # 规则类型定义
        self.rule_types = {
            'domain_rule': 'block',
            'url_rule': 'block',
            'element_hiding': 'block',
            'exception_rule': 'allow',
            'regex_rule': 'block',
            'comment': 'invalid',
            'options': 'modifier',
            'adguard_specific': 'block',
            'html_filtering': 'block',
            'scriptlet': 'block',
            'extension': 'block',
        }

        # AdGuard修饰符定义
        self.modifiers = {
            'domain': r'domain=([^\s,]+)',
            'script': r'script',
            'image': r'image',
            'stylesheet': r'stylesheet',
            'object': r'object',
            'xmlhttprequest': r'xmlhttprequest',
            'subdocument': r'subdocument',
            'document': r'document',
            'elemhide': r'elemhide',
            'other': r'other',
            'third-party': r'third-party',
            'match-case': r'match-case',
            'collapse': r'collapse',
            'donottrack': r'donottrack',
            'websocket': r'websocket',
            'webrtc': r'webrtc',
            'content': r'content',  # AdGuard特定
            'popup': r'popup',      # AdGuard特定
            'app': r'app',          # AdGuard特定
            'network': r'network',  # AdGuard特定
        }

        logger.info("使用内置AdGuard语法规则")


class AdGuardMerger:
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)

        # 为两组规则创建独立的去重容器（完全隔离）
        # adblock*.txt 处理后的数据（黑名单）
        self.block_data = {
            "bloom": ScalableBloomFilter(
                initial_capacity=config.BLOOM_INIT_CAP,
                error_rate=config.BLOOM_ERROR_RATE
            ),
            "seen": set(),          # 精确去重集合
            "rules": [],            # 最终有效规则列表
            "stats": {              # 独立统计
                "processed": 0,     # 总处理规则数
                "valid": 0,         # 有效规则数
                "duplicate": 0,     # 重复规则数
                "invalid": 0        # 无效规则数
            }
        }

        # allow*.txt 处理后的数据（白名单）
        self.allow_data = {
            "bloom": ScalableBloomFilter(
                initial_capacity=config.BLOOM_INIT_CAP,
                error_rate=config.BLOOM_ERROR_RATE
            ),
            "seen": set(),
            "rules": [],
            "stats": {
                "processed": 0,
                "valid": 0,
                "duplicate": 0,
                "invalid": 0
            }
        }

        # 全局文件统计（辅助日志）
        self.global_stats = {
            "total_files": 0,       # 总处理文件数
            "block_files": 0,       # adblock前缀文件数
            "allow_files": 0        # allow前缀文件数
        }

    def github_log(self, level: str, message: str):
        """GitHub Actions专用日志格式"""
        if self.config.GITHUB_ACTIONS:
            level_map = {
                'warning': 'warning',
                'error': 'error',
                'notice': 'notice',
                'debug': 'debug'
            }
            gh_level = level_map.get(level, 'notice')
            print(f"::{gh_level} ::{message}")
        else:
            getattr(logger, level)(message)

    def analyze_rule_syntax(self, rule: str) -> Dict[str, Any]:
        """使用语法数据库分析规则语法"""
        result = {
            'type': 'unknown',
            'pattern_type': 'unknown',
            'modifiers': [],
            'is_valid': False,
            'normalized': rule.strip()
        }

        # 检查注释
        if rule.startswith('!'):
            result['type'] = 'comment'
            return result

        # 移除前后空白
        rule = rule.strip()
        if not rule:
            result['type'] = 'empty'
            return result

        # 检查规则长度
        if len(rule) < self.config.MIN_RULE_LENGTH or len(rule) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            return result

        # 使用语法数据库匹配规则类型
        for pattern_name, pattern in self.syntax_db.syntax_patterns.items():
            try:
                match = re.match(pattern, rule)
                if match:
                    result['pattern_type'] = pattern_name
                    result['type'] = self.syntax_db.rule_types.get(pattern_name, 'unknown')
                    result['is_valid'] = result['type'] not in ['invalid', 'comment', 'empty']
                    break
            except re.error:
                self.github_log('warning', f"正则表达式模式错误: {pattern_name} - {pattern}")
                continue

        # 提取修饰符
        if '$' in rule:
            parts = rule.split('$', 1)
            result['normalized'] = parts[0].strip()
            modifiers_str = parts[1].strip()

            for mod_name, mod_pattern in self.syntax_db.modifiers.items():
                try:
                    if re.search(mod_pattern, modifiers_str):
                        result['modifiers'].append(mod_name)
                except re.error:
                    self.github_log('warning', f"修饰符正则表达式错误: {mod_name} - {mod_pattern}")
                    continue

            # 对修饰符进行排序以确保一致性
            result['modifiers'].sort()

        # 对异常规则进行特殊处理
        if rule.startswith('@@'):
            result['type'] = 'allow'
            result['is_valid'] = True

        return result

    def normalize_rule(self, rule: str) -> Optional[str]:
        """基于语法分析的规则标准化"""
        analysis = self.analyze_rule_syntax(rule)

        if not analysis['is_valid']:
            return None

        # 基础标准化
        normalized = analysis['normalized']

        # 根据规则类型进行特定标准化
        if analysis['pattern_type'] == 'domain_rule':
            # 域名规则标准化: ||example.com^ -> ||example.com^
            try:
                match = re.match(r'^\|\|([^\^]+)\^', normalized)
                if match:
                    domain = match.group(1).lower()  # 域名转换为小写
                    normalized = f'||{domain}^'
            except re.error:
                pass  # 保持原样

        elif analysis['pattern_type'] == 'url_rule':
            # URL规则标准化: |http://example.com| -> |http://example.com|
            try:
                match = re.match(r'^\|([^\|]+)\|', normalized)
                if match:
                    url = match.group(1)
                    # 对URL进行基本清理
                    url = re.sub(r'^https?://', '', url)  # 移除协议
                    url = re.sub(r'^www\.', '', url)      # 移除www前缀
                    normalized = f'|{url}|'
            except re.error:
                pass  # 保持原样

        elif analysis['pattern_type'] == 'element_hiding':
            # 元素隐藏规则标准化: example.com##.ad -> example.com##.ad
            try:
                match = re.match(r'^([^#]+)##([^#]+)', normalized)
                if match:
                    domain = match.group(1).lower()  # 域名转换为小写
                    selector = match.group(2).strip()
                    normalized = f'{domain}##{selector}'
            except re.error:
                pass  # 保持原样

        # 添加排序后的修饰符
        if analysis['modifiers']:
            modifiers_str = ','.join(analysis['modifiers'])
            normalized = f'{normalized}${modifiers_str}'

        return normalized

    def is_valid_rule(self, rule: str) -> bool:
        """使用语法数据库检查是否为有效规则"""
        analysis = self.analyze_rule_syntax(rule)
        return analysis['is_valid']

    def determine_rule_type(self, rule: str) -> str:
        """使用语法数据库确定规则类型"""
        analysis = self.analyze_rule_syntax(rule)
        return analysis['type']

    def get_files_by_prefix(self, directory: Path) -> Tuple[List[Path], List[Path]]:
        """按文件名前缀筛选文件，返回 (adblock前缀文件列表, allow前缀文件列表)"""
        block_files = []  # 存储 adblock*.txt 文件
        allow_files = []  # 存储 allow*.txt 文件

        # 检查输入目录是否存在，不存在则创建
        if not directory.exists():
            self.github_log('warning', f"输入目录 {directory} 不存在，已自动创建")
            directory.mkdir(parents=True, exist_ok=True)
            return block_files, allow_files

        # 递归遍历目录下所有 .txt 和 .filter 文件
        for pattern in self.config.ADBLOCK_PATTERNS:
            for file_path in directory.rglob(pattern):
                if not file_path.is_file():
                    continue  # 跳过目录，只处理文件

                # 按文件名前缀分类（不区分大小写）
                filename = file_path.name.lower()
                if filename.startswith("adblock"):
                    block_files.append(file_path)
                    self.global_stats["block_files"] += 1
                elif filename.startswith("allow"):
                    allow_files.append(file_path)
                    self.global_stats["allow_files"] += 1

        # 统计总文件数
        self.global_stats["total_files"] = len(block_files) + len(allow_files)
        return block_files, allow_files

    def process_single_group(self, files: List[Path], data_container: dict, group_name: str) -> None:
        """
        独立处理一组文件（adblock组或allow组），数据完全隔离
        :param files: 该组的文件列表
        :param data_container: 该组的去重容器+统计（block_data 或 allow_data）
        :param group_name: 组名（用于日志区分）
        """
        logger.info(f"\n=== 开始处理 {group_name} 组文件（共 {len(files)} 个）===")

        for file_path in files:
            try:
                # 读取当前文件的所有规则
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rules = f.read().splitlines()
                logger.info(f"成功读取 {file_path}，共 {len(rules)} 条规则")

                # 逐条处理当前文件的规则
                for rule in rules:
                    data_container["stats"]["processed"] += 1  # 累计总处理数
                    rule_stripped = rule.strip()

                    # 1. 跳过注释和空行（不统计为无效，仅跳过）
                    if not rule_stripped or rule_stripped.startswith("!"):
                        continue

                    # 2. 验证规则有效性（长度+语法）
                    if not self.is_valid_rule(rule_stripped):
                        data_container["stats"]["invalid"] += 1
                        continue
                    normalized_rule = self.normalize_rule(rule_stripped)
                    if not normalized_rule:
                        data_container["stats"]["invalid"] += 1
                        continue

                    # 3. 独立去重（仅与同组规则对比，不跨组）
                    # 先通过布隆过滤器快速判断，再通过精确集合验证
                    if normalized_rule in data_container["bloom"]:
                        if normalized_rule in data_container["seen"]:
                            data_container["stats"]["duplicate"] += 1
                            continue

                    # 4. 有效规则加入该组（更新去重容器和规则列表）
                    data_container["bloom"].add(normalized_rule)
                    data_container["seen"].add(normalized_rule)
                    data_container["rules"].append(normalized_rule)
                    data_container["stats"]["valid"] += 1

            except Exception as e:
                self.github_log('error', f"处理文件 {file_path} 时出错: {str(e)}")

        # 输出该组处理结果统计
        stats = data_container["stats"]
        logger.info(f"\n=== {group_name} 组处理完成 ===")
        logger.info(f"总处理规则数：{stats['processed']}")
        logger.info(f"有效规则数：{stats['valid']}")
        logger.info(f"重复规则数：{stats['duplicate']}")
        logger.info(f"无效规则数：{stats['invalid']}")

    def merge_and_deduplicate(self):
        """主流程：按前缀分类文件→独立处理两组规则→完全隔离"""
        logger.info("=== 开始整体规则处理流程 ===")

        # 1. 按前缀分类输入文件
        block_files, allow_files = self.get_files_by_prefix(self.config.INPUT_DIR)
        logger.info(f"\n文件分类结果：")
        logger.info(f"adblock前缀文件（黑名单源）：{self.global_stats['block_files']} 个")
        logger.info(f"allow前缀文件（白名单源）：{self.global_stats['allow_files']} 个")
        logger.info(f"总计处理文件：{self.global_stats['total_files']} 个")

        # 2. 独立处理 adblock 组（生成黑名单规则）
        if block_files:
            self.process_single_group(block_files, self.block_data, "adblock（黑名单）")
        else:
            self.github_log('warning', "未找到任何 adblock*.txt 文件，黑名单规则将为空")

        # 3. 独立处理 allow 组（生成白名单规则）
        if allow_files:
            self.process_single_group(allow_files, self.allow_data, "allow（白名单）")
        else:
            self.github_log('warning', "未找到任何 allow*.txt 文件，白名单规则将为空")

    def save_rules(self):
        """保存独立处理后的规则，保持原有输出路径和文件名"""
        # 确保输出目录存在
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 开始保存规则（输出目录：{self.config.OUTPUT_DIR}）===")

        # 1. 保存 adblock 组到原配置的黑名单输出文件
        block_output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_BLOCK
        with open(block_output_path, 'w', encoding='utf-8') as f:
            # 规则按字母排序，保持一致性
            f.write('\n'.join(sorted(self.block_data["rules"])))
        logger.info(f"黑名单规则已保存：{block_output_path}（共 {len(self.block_data['rules'])} 条）")

        # 2. 保存 allow 组到原配置的白名单输出文件
        allow_output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ALLOW
        with open(allow_output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.allow_data["rules"])))
        logger.info(f"白名单规则已保存：{allow_output_path}（共 {len(self.allow_data['rules'])} 条）")

        logger.info("\n=== 所有规则保存完成 ===")
        
        # 在GitHub Actions中输出摘要
        if self.config.GITHUB_ACTIONS:
            summary = f"""## AdGuard规则处理结果
            
**处理时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**仓库**: {self.config.GITHUB_REPOSITORY}
**提交**: {self.config.GITHUB_SHA[:7]}
**分支**: {self.config.GITHUB_REF}
            
### 处理统计
- 总文件数: {self.global_stats['total_files']}
- 黑名单文件: {self.global_stats['block_files']}
- 白名单文件: {self.global_stats['allow_files']}
            
### 黑名单规则
- 总处理规则: {self.block_data['stats']['processed']}
- 有效规则: {self.block_data['stats']['valid']}
- 重复规则: {self.block_data['stats']['duplicate']}
- 无效规则: {self.block_data['stats']['invalid']}
            
### 白名单规则
- 总处理规则: {self.allow_data['stats']['processed']}
- 有效规则: {self.allow_data['stats']['valid']}
- 重复规则: {self.allow_data['stats']['duplicate']}
- 无效规则: {self.allow_data['stats']['invalid']}
            
**输出文件**:
- 黑名单: {self.config.OUTPUT_BLOCK}
- 白名单: {self.config.OUTPUT_ALLOW}
            """
            
            # 在GitHub Actions中输出摘要
            with open(os.getenv('GITHUB_STEP_SUMMARY', ''), 'a') as f:
                f.write(summary)


def main():
    """主函数"""
    # 初始化配置（保持原有路径和文件名）
    config = AdGuardConfig()
    
    # 输出GitHub Actions信息
    if config.GITHUB_ACTIONS:
        logger.info(f"运行在GitHub Actions环境: {config.GITHUB_WORKFLOW}")
        logger.info(f"仓库: {config.GITHUB_REPOSITORY}")
        logger.info(f"提交: {config.GITHUB_SHA}")
        logger.info(f"分支: {config.GITHUB_REF}")

    # 创建合并器实例
    merger = AdGuardMerger(config)

    # 执行合并去重（按前缀独立处理）
    merger.merge_and_deduplicate()

    # 保存结果（保持原有输出路径和文件名）
    merger.save_rules()


if __name__ == "__main__":
    main()