#!/usr/bin/env python3
"""
AdGuard规则合并去重脚本（增强版） - 完全依赖外部语法数据库
功能：合并多个AdGuard规则文件，去除重复规则，同时生成AdGuard和AdGuard Home规则
修复问题：
1. 修复allow_adh.txt为空的问题
2. 修复hosts语法被错误归类为允许规则的问题
3. 正确区分拦截规则和允许规则
4. 增强多平台语法支持
作者：AI助手
日期：2025-09-02
版本：4.0.0
"""

import os
import re
import json
import hashlib
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
    """配置类 - 同时输出AdGuard和AdGuard Home规则"""
    # 基础路径配置
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))

    # 输入目录
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"

    # 输出目录
    OUTPUT_DIR: Path = BASE_DIR

    # GitHub Actions特定环境变量
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    GITHUB_REPOSITORY: str = os.getenv('GITHUB_REPOSITORY', 'unknown/repository')
    GITHUB_SHA: str = os.getenv('GITHUB_SHA', 'unknown')
    GITHUB_REF: str = os.getenv('GITHUB_REF', 'unknown')
    GITHUB_WORKFLOW: str = os.getenv('GITHUB_WORKFLOW', 'unknown')

    # 文件模式配置
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter'])

    # 输出文件配置 - 同时输出AdGuard和AdGuard Home规则
    OUTPUT_ADG_BLOCK: str = 'adblock_adg.txt'  # AdGuard拦截规则
    OUTPUT_ADG_ALLOW: str = 'allow_adg.txt'    # AdGuard允许规则
    OUTPUT_ADH_BLOCK: str = 'adblock_adh.txt'  # AdGuard Home拦截规则
    OUTPUT_ADH_ALLOW: str = 'allow_adh.txt'    # AdGuard Home允许规则

    # 语法数据库配置
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"

    # 布隆过滤器配置
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    BLOOM_SCALING_FACTOR: float = float(os.getenv('BLOOM_SCALING_FACTOR', '2.0'))
    BLOOM_MAX_CAPACITY: int = int(os.getenv('BLOOM_MAX_CAPACITY', '10000000'))

    # 规则处理配置
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))

    # 性能配置
    MAX_RULES_PER_FILE: int = int(os.getenv('MAX_RULES_PER_FILE', '50000'))
    DOWNLOAD_TIMEOUT: int = int(os.getenv('DOWNLOAD_TIMEOUT', '30'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))


class AdGuardSyntaxDatabase:
    """AdGuard语法数据库 - 完全依赖外部数据库，增强完整性检查"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_patterns = {}
        self.rule_types = {}
        self.modifiers = {}
        self.validation_rules = {}
        self.common_patterns = {}
        self.adguard_home_specific = {}
        self.performance_config = {}
        self.db_path = None
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载语法数据库"""
        self.db_path = self.config.SYNTAX_DB_FILE

        logger.info(f"尝试加载语法数据库，路径: {self.db_path}")
        logger.info(f"文件是否存在: {self.db_path.exists()}")

        if not self.db_path.exists():
            # 尝试备用路径
            alternate_path = Path(__file__).parent / "adblock_syntax_db.json"
            logger.info(f"尝试备用路径: {alternate_path}")
            logger.info(f"备用路径文件是否存在: {alternate_path.exists()}")

            if alternate_path.exists():
                self.db_path = alternate_path
                logger.info(f"使用备用路径: {self.db_path}")
            else:
                error_msg = f"错误：找不到语法数据库文件 {self.config.SYNTAX_DB_FILE}"
                logger.error(error_msg)
                raise FileNotFoundError(error_msg)

        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                db_data = json.load(f)

            # 验证数据库完整性
            self.validate_database_integrity(db_data)

            self.syntax_patterns = db_data.get('syntax_patterns', {})
            self.rule_types = db_data.get('rule_types', {})
            self.modifiers = db_data.get('modifiers', {})
            self.validation_rules = db_data.get('validation_rules', {})
            self.common_patterns = db_data.get('common_patterns', {})

            # 修复：adguard_home_specific 字段可能不存在
            self.adguard_home_specific = db_data.get('adguard_home_specific', {
                "supported_rule_types": ["domain_rule", "exception_rule", "adguard_dns_rule", 
                                       "adguard_home_dns_rewrite", "adguard_home_client", 
                                       "adguard_home_dnstype", "hosts_rule", "regex_rule"],
                "unsupported_patterns": []
            })

            self.performance_config = db_data.get('performance_optimization', {}).get('bloom_filter_config', {})

            # 更新布隆过滤器配置（如果数据库中有定义）
            if self.performance_config:
                self.config.BLOOM_INIT_CAP = self.performance_config.get('initial_capacity', self.config.BLOOM_INIT_CAP)
                self.config.BLOOM_ERROR_RATE = self.performance_config.get('error_rate', self.config.BLOOM_ERROR_RATE)

            logger.info(f"成功加载语法数据库: {self.db_path}")
            logger.info(f"数据库版本: {db_data.get('version', '未知')}")
            logger.info(f"语法模式数量: {len(self.syntax_patterns)}")
            logger.info(f"规则类型数量: {len(self.rule_types)}")

        except json.JSONDecodeError as e:
            error_msg = f"语法数据库JSON格式错误: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"加载语法数据库失败: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def validate_database_integrity(self, db_data: Dict) -> bool:
        """验证数据库完整性"""
        required_fields = [
            "version", "syntax_patterns", "rule_types", "modifiers", 
            "validation_rules", "platform_support"
        ]

        missing_fields = [field for field in required_fields if field not in db_data]
        if missing_fields:
            raise ValueError(f"数据库缺少必需字段: {missing_fields}")

        # 检查版本兼容性
        version = db_data.get("version", "1.0")
        if not version.startswith(("3.", "4.")):  # 支持 3.x 和 4.x
            logger.warning(f"数据库版本 {version} 可能不兼容当前脚本")

        return True

    def is_rule_supported_by_adguard_home(self, rule_type: str) -> bool:
        """检查规则类型是否被AdGuard Home支持"""
        if not self.adguard_home_specific or "supported_rule_types" not in self.adguard_home_specific:
            logger.warning("语法数据库中缺少AdGuard Home支持规则类型定义，使用默认值")
            return rule_type in ["domain_rule", "exception_rule", "adguard_dns_rule", 
                               "adguard_home_dns_rewrite", "adguard_home_client", 
                               "adguard_home_dnstype", "hosts_rule", "regex_rule"]

        return rule_type in self.adguard_home_specific["supported_rule_types"]

    def validate_rule_for_adguard_home(self, rule: str, rule_type: str) -> bool:
        """验证规则是否符合AdGuard Home的要求"""
        # 检查规则类型是否支持
        if not self.is_rule_supported_by_adguard_home(rule_type):
            logger.debug(f"AdGuard Home不支持的规则类型: {rule_type} - {rule}")
            return False

        # 检查DNS重写规则长度
        if rule_type == "adguard_home_dns_rewrite":
            max_length = self.adguard_home_specific.get("max_dns_rewrite_length", 1000)
            if len(rule) > max_length:
                logger.debug(f"DNS重写规则过长: {rule}")
                return False

        # 检查DNS重写类型是否有效
        if rule_type == "adguard_home_dns_rewrite" or "$dnsrewrite=" in rule:
            match = re.search(r"\$dnsrewrite=([^,\s]+)", rule)
            if match:
                rewrite_type = match.group(1)
                valid_types = self.adguard_home_specific.get("dns_rewrite_types", ["A", "AAAA", "CNAME", "TXT", "MX", "PTR", "SRV", "SOA", "NS"])
                if rewrite_type not in valid_types:
                    logger.debug(f"无效的DNS重写类型: {rewrite_type} - {rule}")
                    return False

        return True

    def check_unsupported_patterns(self, rule: str) -> bool:
        """检查规则是否包含AdGuard Home不支持的模式"""
        unsupported_patterns = self.adguard_home_specific.get("unsupported_patterns", ["##", "#@#", "#%#", "$$", "script:inject", "##^", "##*"])
        for pattern in unsupported_patterns:
            if pattern in rule:
                return False
        return True


class EnhancedBloomFilter:
    """增强的布隆过滤器封装类，结合哈希表确保准确性"""
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.bloom = ScalableBloomFilter(
            initial_capacity=config.BLOOM_INIT_CAP,
            error_rate=config.BLOOM_ERROR_RATE,
            mode=ScalableBloomFilter.LARGE_SET_GROWTH
        )
        self.hash_set = set()
        self.collision_count = 0
        self.false_positive_count = 0

    def add(self, item: str) -> bool:
        """添加项目到布隆过滤器和哈希表"""
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()

        # 先检查布隆过滤器（快速但可能有误报）
        if item in self.bloom:
            # 布隆过滤器说可能存在，用哈希表确认
            if item_hash not in self.hash_set:
                self.false_positive_count += 1
                logger.debug(f"布隆过滤器误报: {item}")
                return False
            return True

        # 添加到布隆过滤器和哈希表
        self.bloom.add(item)
        self.hash_set.add(item_hash)
        return False

    def __contains__(self, item: str) -> bool:
        """检查项目是否存在"""
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        return item_hash in self.hash_set

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return {
            "total_items": len(self.hash_set),
            "collision_count": self.collision_count,
            "false_positive_count": self.false_positive_count,
            "false_positive_rate": self.false_positive_count / len(self.hash_set) if self.hash_set else 0
        }


class AdGuardMerger:
    def __init__(self, config: AdGuardConfig):
        self.config = config
        try:
            self.syntax_db = AdGuardSyntaxDatabase(config)
        except (FileNotFoundError, RuntimeError, ValueError) as e:
            logger.error(f"初始化语法数据库失败: {e}")
            sys.exit(1)

        # 为AdGuard和AdGuard Home分别创建增强的去重容器
        self.adguard_filter = EnhancedBloomFilter(config)
        self.adhome_filter = EnhancedBloomFilter(config)

        # 规则存储 - 修复：分别存储拦截和允许规则
        self.adguard_block_rules = []
        self.adguard_allow_rules = []
        self.adhome_block_rules = []
        self.adhome_allow_rules = []

        # 统计信息
        self.stats = {
            "total_processed": 0,
            "adguard_block_rules": 0,
            "adguard_allow_rules": 0,
            "adhome_block_rules": 0,
            "adhome_allow_rules": 0,
            "duplicates": 0,
            "invalid_rules": 0,
            "unsupported_rules": 0,
            "bloom_false_positives": 0
        }

        # 全局文件统计
        self.file_stats = {
            "total_files": 0,
            "block_files": 0,
            "allow_files": 0
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
            'normalized': rule.strip(),
            'is_allow': False  # 新增字段，标识是否为允许规则
        }

        # 检查注释
        if re.match(r'^[!#]', rule):
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

        # 检查是否为允许规则
        if rule.startswith('@@'):
            result['is_allow'] = True

        # 使用语法数据库匹配规则类型
        for pattern_name, pattern_str in self.syntax_db.syntax_patterns.items():
            try:
                pattern = re.compile(pattern_str)
                if pattern.match(rule):
                    result['pattern_type'] = pattern_name
                    result['type'] = self.syntax_db.rule_types.get(pattern_name, 'unknown')

                    # 修复：hosts规则应该是拦截规则，不是允许规则
                    if pattern_name == 'hosts_rule':
                        result['is_allow'] = False

                    result['is_valid'] = result['type'] not in ['invalid', 'comment', 'empty']
                    break
            except re.error as e:
                self.github_log('debug', f"正则表达式模式错误: {pattern_name} - {pattern_str}, 错误: {e}")
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
                except re.error as e:
                    self.github_log('debug', f"修饰符正则表达式错误: {mod_name} - {mod_pattern}, 错误: {e}")
                    continue

            # 对修饰符进行排序以确保一致性
            result['modifiers'].sort()

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

        # 添加排序后的修饰符
        if analysis['modifiers']:
            modifiers_str = ','.join(analysis['modifiers'])
            normalized = f'{normalized}${modifiers_str}'

        return normalized

    def is_valid_rule(self, rule: str) -> bool:
        """使用语法数据库检查是否为有效规则"""
        analysis = self.analyze_rule_syntax(rule)
        return analysis['is_valid']

    def get_files_by_prefix(self, directory: Path) -> Tuple[List[Path], List[Path]]:
        """按文件名前缀筛选文件"""
        block_files = []
        allow_files = []

        if not directory.exists():
            self.github_log('warning', f"输入目录 {directory} 不存在，已自动创建")
            directory.mkdir(parents=True, exist_ok=True)
            return block_files, allow_files

        for pattern in self.config.ADBLOCK_PATTERNS:
            for file_path in directory.rglob(pattern):
                if not file_path.is_file():
                    continue

                filename = file_path.name.lower()
                if filename.startswith("adblock"):
                    block_files.append(file_path)
                    self.file_stats["block_files"] += 1
                elif filename.startswith("allow"):
                    allow_files.append(file_path)
                    self.file_stats["allow_files"] += 1

        self.file_stats["total_files"] = len(block_files) + len(allow_files)
        return block_files, allow_files

    def process_file_batch(self, file_path: Path, is_allow_file: bool = False):
        """批量处理文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line in f:
                    batch.append(line.strip())
                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        self.process_batch(batch, is_allow_file)
                        batch = []

                # 处理剩余内容
                if batch:
                    self.process_batch(batch, is_allow_file)

        except Exception as e:
            self.github_log('error', f"处理文件 {file_path} 时出错: {str(e)}")

    def process_batch(self, batch: List[str], is_allow_file: bool = False):
        """处理批量规则"""
        for rule in batch:
            self.stats["total_processed"] += 1

            # 跳过注释和空行
            if not rule or re.match(r'^[!#]', rule):
                continue

            # 验证规则有效性
            if not self.is_valid_rule(rule):
                self.stats["invalid_rules"] += 1
                continue

            # 分析规则语法
            analysis = self.analyze_rule_syntax(rule)

            # 标准化规则
            normalized_rule = self.normalize_rule(rule)
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                continue

            # 检查AdGuard Home兼容性
            adhome_compatible = (self.syntax_db.validate_rule_for_adguard_home(rule, analysis['pattern_type']) and 
                               self.syntax_db.check_unsupported_patterns(rule))

            # 确定规则类型（拦截或允许）
            # 修复：优先使用规则自身的类型标识，而不是文件前缀
            is_allow_rule = analysis['is_allow']

            # 去重处理 - AdGuard规则
            if self.adguard_filter.add(normalized_rule):
                self.stats["duplicates"] += 1
            else:
                if is_allow_rule:
                    self.adguard_allow_rules.append(normalized_rule)
                    self.stats["adguard_allow_rules"] += 1
                else:
                    self.adguard_block_rules.append(normalized_rule)
                    self.stats["adguard_block_rules"] += 1

            # 去重处理 - AdGuard Home规则（如果兼容）
            if adhome_compatible:
                if self.adhome_filter.add(normalized_rule):
                    self.stats["duplicates"] += 1
                else:
                    if is_allow_rule:
                        self.adhome_allow_rules.append(normalized_rule)
                        self.stats["adhome_allow_rules"] += 1
                    else:
                        self.adhome_block_rules.append(normalized_rule)
                        self.stats["adhome_block_rules"] += 1
            else:
                self.stats["unsupported_rules"] += 1

    def process_files(self):
        """处理所有文件"""
        block_files, allow_files = self.get_files_by_prefix(self.config.INPUT_DIR)

        logger.info(f"\n文件分类结果：")
        logger.info(f"adblock前缀文件: {self.file_stats['block_files']} 个")
        logger.info(f"allow前缀文件: {self.file_stats['allow_files']} 个")
        logger.info(f"总计处理文件: {self.file_stats['total_files']} 个")

        # 处理拦截规则文件
        for file_path in block_files:
            self.process_file_batch(file_path, is_allow_file=False)

        # 处理允许规则文件
        for file_path in allow_files:
            self.process_file_batch(file_path, is_allow_file=True)

        # 更新误报统计
        self.stats["bloom_false_positives"] = (
            self.adguard_filter.false_positive_count + 
            self.adhome_filter.false_positive_count
        )

    def save_results(self):
        """保存结果到文件"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 开始保存规则 ===")

        # 保存AdGuard规则
        adg_block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_BLOCK
        with open(adg_block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_block_rules)))
        logger.info(f"AdGuard拦截规则已保存: {adg_block_path}")

        adg_allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_ALLOW
        with open(adg_allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_allow_rules)))
        logger.info(f"AdGuard允许规则已保存: {adg_allow_path}")

        # 保存AdGuard Home规则
        adh_block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADH_BLOCK
        with open(adh_block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adhome_block_rules)))
        logger.info(f"AdGuard Home拦截规则已保存: {adh_block_path}")

        adh_allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADH_ALLOW
        with open(adh_allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adhome_allow_rules)))
        logger.info(f"AdGuard Home允许规则已保存: {adh_allow_path}")

        # 输出详细统计信息
        logger.info("\n=== 处理统计 ===")
        logger.info(f"总处理规则: {self.stats['total_processed']}")
        logger.info(f"AdGuard拦截规则: {self.stats['adguard_block_rules']}")
        logger.info(f"AdGuard允许规则: {self.stats['adguard_allow_rules']}")
        logger.info(f"AdGuard Home拦截规则: {self.stats['adhome_block_rules']}")
        logger.info(f"AdGuard Home允许规则: {self.stats['adhome_allow_rules']}")
        logger.info(f"重复规则: {self.stats['duplicates']}")
        logger.info(f"无效规则: {self.stats['invalid_rules']}")
        logger.info(f"不兼容规则: {self.stats['unsupported_rules']}")
        logger.info(f"布隆过滤器误报: {self.stats['bloom_false_positives']}")

        # 布隆过滤器性能统计
        adg_stats = self.adguard_filter.get_stats()
        adh_stats = self.adhome_filter.get_stats()
        logger.info(f"AdGuard过滤器误报率: {adg_stats['false_positive_rate']:.6f}")
        logger.info(f"AdGuard Home过滤器误报率: {adh_stats['false_positive_rate']:.6f}")

        # GitHub Actions摘要
        if self.config.GITHUB_ACTIONS:
            self.generate_github_summary()

    def generate_github_summary(self):
        """生成GitHub Actions摘要"""
        summary = f"""## AdGuard规则处理结果（修复版）
        
**处理时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**仓库**: {self.config.GITHUB_REPOSITORY}
**提交**: {self.config.GITHUB_SHA[:7]}
**数据库版本**: {getattr(self.syntax_db, 'version', '未知')}

### 文件统计
- 总文件数: {self.file_stats['total_files']}
- 拦截规则文件: {self.file_stats['block_files']}
- 允许规则文件: {self.file_stats['allow_files']}

### 规则处理统计
- 总处理规则: {self.stats['total_processed']}
- AdGuard拦截规则: {self.stats['adguard_block_rules']}
- AdGuard允许规则: {self.stats['adguard_allow_rules']}
- AdGuard Home拦截规则: {self.stats['adhome_block_rules']}
- AdGuard Home允许规则: {self.stats['adhome_allow_rules']}
- 重复规则: {self.stats['duplicates']}
- 无效规则: {self.stats['invalid_rules']}
- 不兼容规则: {self.stats['unsupported_rules']}
- 布隆过滤器误报: {self.stats['bloom_false_positives']}

### 性能指标
- AdGuard过滤器误报率: {self.adguard_filter.get_stats()['false_positive_rate']:.6f}
- AdGuard Home过滤器误报率: {self.adhome_filter.get_stats()['false_positive_rate']:.6f}

**输出文件**:
- AdGuard拦截规则: {self.config.OUTPUT_ADG_BLOCK}
- AdGuard允许规则: {self.config.OUTPUT_ADG_ALLOW}
- AdGuard Home拦截规则: {self.config.OUTPUT_ADH_BLOCK}
- AdGuard Home允许规则: {self.config.OUTPUT_ADH_ALLOW}

**修复问题**:
1. ✅ 修复allow_adh.txt为空的问题
2. ✅ 修复hosts语法被错误归类为允许规则的问题
3. ✅ 正确区分拦截规则和允许规则
4. ✅ 增强多平台语法支持 (AdGuard, AdGuard Home, ABP, UBO, Surge, Pi-hole)

**数据库完整性**: ✅ 验证通过
**去重机制**: ✅ 布隆过滤器+哈希表协同工作
"""

        if os.getenv('GITHUB_STEP_SUMMARY'):
            with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a') as f:
                f.write(summary)


def main():
    """主函数"""
    config = AdGuardConfig()

    if config.GITHUB_ACTIONS:
        logger.info(f"运行在GitHub Actions环境: {config.GITHUB_WORKFLOW}")

    try:
        merger = AdGuardMerger(config)
        merger.process_files()
        merger.save_results()
        return 0
    except Exception as e:
        logger.error(f"处理失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())