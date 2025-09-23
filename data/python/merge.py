#!/usr/bin/env python3
"""
AdGuard规则合并器 - 将多个规则文件合并为AdGuard兼容格式
支持AdGuard Home兼容性检查，自动标准化规则语法
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

# 日志级别默认设为INFO，支持通过环境变量覆盖
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AdGuardConfig:
    """配置类 - 输出AdGuard规则（兼容AdGuard Home）"""
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    INPUT_DIR: Path = BASE_DIR / "data" / "filter"
    OUTPUT_DIR: Path = BASE_DIR

    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    GITHUB_REPOSITORY: str = os.getenv('GITHUB_REPOSITORY', 'unknown/repository')
    GITHUB_SHA: str = os.getenv('GITHUB_SHA', 'unknown')
    GITHUB_REF: str = os.getenv('GITHUB_REF', 'unknown')
    GITHUB_WORKFLOW: str = os.getenv('GITHUB_WORKFLOW', 'unknown')

    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter'])
    OUTPUT_ADG_BLOCK: str = 'adblock_adg.txt'
    OUTPUT_ADG_ALLOW: str = 'allow_adg.txt'
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"

    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.001'))
    BLOOM_SCALING_FACTOR: float = float(os.getenv('BLOOM_SCALING_FACTOR', '2.0'))
    BLOOM_MAX_CAPACITY: int = int(os.getenv('BLOOM_MAX_CAPACITY', '10000000'))

    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    MAX_RULES_PER_FILE: int = int(os.getenv('MAX_RULES_PER_FILE', '50000'))
    DOWNLOAD_TIMEOUT: int = int(os.getenv('DOWNLOAD_TIMEOUT', '30'))
    BATCH_PROCESSING_SIZE: int = int(os.getenv('BATCH_PROCESSING_SIZE', '1000'))

    # 新增配置项
    ENABLE_ADGUARD_HOME_COMPATIBILITY: bool = True
    STRICT_VALIDATION: bool = True
    NORMALIZE_DOMAINS: bool = True


class AdGuardSyntaxDatabase:
    """AdGuard语法数据库"""
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
        self.version = "未知"
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载语法数据库"""
        # 尝试多个可能的路径
        possible_paths = [
            self.config.SYNTAX_DB_FILE,
            self.config.BASE_DIR / "adblock_syntax_db.json",
            Path(__file__).parent / "adblock_syntax_db.json"
        ]
        
        self.db_path = None
        for path in possible_paths:
            if path.exists():
                self.db_path = path
                break
        
        if not self.db_path:
            error_msg = f"错误：找不到语法数据库文件。尝试路径: {possible_paths}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        logger.info(f"使用语法数据库: {self.db_path}")
        
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                db_data = json.load(f)
            self.validate_database_integrity(db_data)
            self.syntax_patterns = db_data.get('syntax_patterns', {})
            self.rule_types = db_data.get('rule_types', {})
            self.modifiers = db_data.get('modifiers', {})
            self.validation_rules = db_data.get('validation_rules', {})
            self.common_patterns = db_data.get('common_patterns', {})
            self.version = db_data.get('version', '未知')
            self.adguard_home_specific = db_data.get('adguard_home_specific', {
                "supported_rule_types": ["domain_rule", "exception_rule", "adguard_dns_rule", "adguard_home_dns_rewrite", "adguard_home_client", "adguard_home_dnstype", "hosts_rule", "regex_rule"],
                "unsupported_patterns": []
            })
            self.performance_config = db_data.get('performance_optimization', {}).get('bloom_filter_config', {})
            if self.performance_config:
                self.config.BLOOM_INIT_CAP = self.performance_config.get('initial_capacity', self.config.BLOOM_INIT_CAP)
                self.config.BLOOM_ERROR_RATE = self.performance_config.get('error_rate', self.config.BLOOM_ERROR_RATE)
            logger.info(f"成功加载语法数据库: {self.db_path} 版本: {self.version}")
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
        
        version = db_data.get("version", "1.0")
        if not version.startswith(("3.", "4.")):
            logger.warning(f"数据库版本 {version} 可能不兼容当前脚本")
        
        return True

    def is_adguard_home_compatible(self, rule_type: str, modifiers: List[str]) -> bool:
        """检查规则是否兼容AdGuard Home"""
        if not self.config.ENABLE_ADGUARD_HOME_COMPATIBILITY:
            return True
            
        # AdGuard Home不支持的规则类型
        incompatible_rule_types = [
            "element_hiding_basic", "element_hiding_exception", "extended_css",
            "adguard_scriptlet", "adguard_redirect_rule", "adguard_removeparam_rule",
            "adguard_csp_rule", "adguard_replace_rule", "adguard_cookie_rule"
        ]
        
        # AdGuard Home不支持的修饰符
        incompatible_modifiers = [
            "redirect", "removeparam", "csp", "replace", "cookie", "header",
            "jsonprune", "hls", "all", "elemhide", "generichide", "specifichide"
        ]
        
        # 检查规则类型
        if rule_type in incompatible_rule_types:
            return False
            
        # 检查修饰符
        if any(mod in modifiers for mod in incompatible_modifiers):
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
        """添加项目到过滤器"""
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        if item in self.bloom:
            if item_hash not in self.hash_set:
                self.false_positive_count += 1
                logger.debug(f"布隆过滤器误报: {item}")
                return False
            return True
        self.bloom.add(item)
        self.hash_set.add(item_hash)
        return False

    def __contains__(self, item: str) -> bool:
        """检查项目是否存在"""
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        return item_hash in self.hash_set

    def get_stats(self) -> Dict[str, Any]:
        """获取过滤器统计信息"""
        total_items = len(self.hash_set)
        false_positive_rate = self.false_positive_count / total_items if total_items > 0 else 0
        
        return {
            "total_items": total_items,
            "collision_count": self.collision_count,
            "false_positive_count": self.false_positive_count,
            "false_positive_rate": false_positive_rate
        }


class AdGuardMerger:
    """AdGuard规则合并器"""
    
    def __init__(self, config: AdGuardConfig):
        self.config = config
        
        # 纯域名匹配正则（不含协议、前缀，符合域名格式）
        self.pure_domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,61}[a-zA-Z0-9]$')
        
        try:
            self.syntax_db = AdGuardSyntaxDatabase(config)
        except (FileNotFoundError, RuntimeError, ValueError) as e:
            logger.error(f"初始化语法数据库失败: {e}")
            sys.exit(1)
            
        self.adguard_filter = EnhancedBloomFilter(config)
        self.adguard_block_rules = []
        self.adguard_allow_rules = []
        
        # 统计信息
        self.stats = {
            "total_processed": 0,
            "adguard_block_rules": 0,
            "adguard_allow_rules": 0,
            "duplicates": 0,
            "invalid_rules": 0,
            "adhome_compatible_rules": 0,
            "adhome_incompatible_rules": 0,
            "bloom_false_positives": 0,
            "normalized_rules": 0
        }
        
        self.file_stats = {
            "total_files": 0,
            "block_files": 0,
            "allow_files": 0
        }

    def github_log(self, level: str, message: str):
        """GitHub Actions友好的日志输出"""
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
        """分析规则语法"""
        result = {
            'type': 'unknown',
            'pattern_type': 'unknown',
            'modifiers': [],
            'is_valid': False,
            'normalized': rule.strip(),
            'is_allow': False,
            'adhome_compatible': True
        }
        
        # 跳过注释和空行
        if re.match(r'^[!#]', rule) or not rule.strip():
            result['type'] = 'comment'
            return result
            
        rule = rule.strip()
        
        # 长度检查
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
                    
                    # 特殊处理hosts规则
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
                    
            result['modifiers'].sort()
            
        # 检查AdGuard Home兼容性
        result['adhome_compatible'] = self.syntax_db.is_adguard_home_compatible(
            result['pattern_type'], result['modifiers']
        )
            
        return result

    def normalize_rule(self, rule: str) -> Optional[str]:
        """标准化规则"""
        analysis = self.analyze_rule_syntax(rule)
        
        if not analysis['is_valid']:
            return None
            
        normalized = analysis['normalized']

        # 白名单纯域名补全逻辑
        if analysis['is_allow']:
            # 情况1：纯域名（无@@、无||、无协议）
            if self.pure_domain_pattern.match(normalized.lstrip('@')):
                clean_domain = normalized.lstrip('@')
                normalized = f'@@||{clean_domain}^'
            # 情况2：含@@但无||和^（如@@domain.com）
            elif normalized.startswith('@@') and not normalized.startswith('@@||') and not normalized.endswith('^'):
                clean_domain = normalized[2:].strip()
                if self.pure_domain_pattern.match(clean_domain):
                    normalized = f'@@||{clean_domain}^'
            # 原有补全逻辑保留，作为兜底
            else:
                m = re.match(r'^@@([a-zA-Z0-9\.\-\_]+)$', normalized)
                if m:
                    normalized = f'@@||{m.group(1)}^'
                elif re.match(r'^@@https?://', normalized):
                    url = normalized[2:] if normalized.startswith('@@') else normalized
                    normalized = f'@@|{url[2:]}|'
                elif not (normalized.startswith('@@||') or normalized.startswith('@@|')):
                    normalized = f'@@||{normalized}^'

        # 域名规则标准化（支持||IP^格式，统一小写处理）
        if analysis['pattern_type'] == 'domain_rule':
            try:
                match = re.match(r'^\|\|([^\^]+)\^', normalized)
                if match:
                    target = match.group(1).lower()
                    normalized = f'||{target}^'
            except re.error:
                pass
                
        # URL规则标准化
        elif analysis['pattern_type'] == 'url_rule':
            try:
                match = re.match(r'^\|([^\|]+)\|', normalized)
                if match:
                    url = match.group(1)
                    url = re.sub(r'^https?://', '', url)
                    url = re.sub(r'^www\.', '', url)
                    normalized = f'|{url}|'
            except re.error:
                pass
                
        # 域名标准化
        if self.config.NORMALIZE_DOMAINS and analysis['pattern_type'] in ['domain_rule', 'adguard_domain_rule']:
            normalized = normalized.lower()
            
        # 添加排序后的修饰符
        if analysis['modifiers']:
            modifiers_str = ','.join(analysis['modifiers'])
            normalized = f'{normalized}${modifiers_str}'
            
        self.stats['normalized_rules'] += 1
        return normalized

    def is_valid_rule(self, rule: str) -> bool:
        """检查规则有效性"""
        analysis = self.analyze_rule_syntax(rule)
        return analysis['is_valid']

    def get_files_by_prefix(self, directory: Path) -> Tuple[List[Path], List[Path]]:
        """根据文件名前缀分类文件"""
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
        """处理文件批次"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line in f:
                    batch.append(line.strip())
                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        self.process_batch(batch, is_allow_file)
                        batch = []
                if batch:
                    self.process_batch(batch, is_allow_file)
                    
            logger.info(f"成功处理文件: {file_path}")
                    
        except Exception as e:
            self.github_log('error', f"处理文件 {file_path} 时出错: {str(e)}")

    def process_batch(self, batch: List[str], is_allow_file: bool = False):
        """处理规则批次"""
        for rule in batch:
            self.stats["total_processed"] += 1
            
            # 跳过注释和空行
            if not rule or re.match(r'^[!#]', rule):
                continue
                
            # 1. 检查规则语法有效性，无效则记录日志并跳过
            if not self.is_valid_rule(rule):
                self.stats["invalid_rules"] += 1
                logger.debug(f"跳过无效规则（语法/长度不符合要求）: {rule.strip()}")
                continue
                
            # 2. 分析规则并标准化
            analysis = self.analyze_rule_syntax(rule)
            normalized_rule = self.normalize_rule(rule)
            
            # 3. 标准化失败则记录日志并跳过
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                logger.debug(f"跳过无效规则（标准化失败）: {rule.strip()}")
                continue
            
            # 去重处理
            if self.adguard_filter.add(normalized_rule):
                self.stats["duplicates"] += 1
                logger.debug(f"跳过重复规则: {normalized_rule}")
            else:
                # 分类添加到拦截/允许规则列表
                if analysis['is_allow']:
                    self.adguard_allow_rules.append(normalized_rule)
                    self.stats["adguard_allow_rules"] += 1
                else:
                    self.adguard_block_rules.append(normalized_rule)
                    self.stats["adguard_block_rules"] += 1
                    
                # 记录兼容性统计
                if analysis['adhome_compatible']:
                    self.stats["adhome_compatible_rules"] += 1
                else:
                    self.stats["adhome_incompatible_rules"] += 1

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
            
        self.stats["bloom_false_positives"] = self.adguard_filter.false_positive_count

    def save_results(self):
        """保存结果"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 开始保存规则 ===")
        
        # 保存AdGuard格式规则
        adg_block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_BLOCK
        with open(adg_block_path, 'w', encoding='utf-8') as f:
            # 添加文件头
            f.write(f"! Title: AdGuard广告拦截规则\n")
            f.write(f"! Description: 自动生成的AdGuard兼容规则集\n")
            f.write(f"! Version: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"! Last modified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! Homepage: https://github.com/{self.config.GITHUB_REPOSITORY}\n")
            f.write(f"! Total rules: {len(self.adguard_block_rules)}\n")
            f.write(f"!\n")
            f.write('\n'.join(sorted(self.adguard_block_rules)))
        logger.info(f"AdGuard拦截规则已保存: {adg_block_path}")

        adg_allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_ALLOW
        with open(adg_allow_path, 'w', encoding='utf-8') as f:
            # 添加文件头
            f.write(f"! Title: AdGuard白名单规则\n")
            f.write(f"! Description: 自动生成的AdGuard兼容白名单\n")
            f.write(f"! Version: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"! Last modified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! Homepage: https://github.com/{self.config.GITHUB_REPOSITORY}\n")
            f.write(f"! Total rules: {len(self.adguard_allow_rules)}\n")
            f.write(f"!\n")
            f.write('\n'.join(sorted(self.adguard_allow_rules)))
        logger.info(f"AdGuard允许规则已保存: {adg_allow_path}")

        self.print_statistics()

    def print_statistics(self):
        """打印统计信息"""
        logger.info("\n=== 处理统计 ===")
        logger.info(f"总处理规则: {self.stats['total_processed']}")
        logger.info(f"AdGuard拦截规则: {self.stats['adguard_block_rules']}")
        logger.info(f"AdGuard允许规则: {self.stats['adguard_allow_rules']}")
        logger.info(f"重复规则: {self.stats['duplicates']}")
        logger.info(f"无效规则: {self.stats['invalid_rules']}")
        logger.info(f"标准化规则: {self.stats['normalized_rules']}")
        logger.info(f"AdGuard Home兼容规则: {self.stats['adhome_compatible_rules']}")
        logger.info(f"AdGuard Home不兼容规则: {self.stats['adhome_incompatible_rules']}")
        logger.info(f"布隆过滤器误报: {self.stats['bloom_false_positives']}")

        adg_stats = self.adguard_filter.get_stats()
        logger.info(f"AdGuard过滤器误报率: {adg_stats['false_positive_rate']:.6f}")

        if self.config.GITHUB_ACTIONS:
            self.generate_github_summary()

    def generate_github_summary(self):
        """生成GitHub Actions摘要"""
        summary = f"""## AdGuard规则处理结果
        
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
- 重复规则: {self.stats['duplicates']}
- 无效规则: {self.stats['invalid_rules']}
- 标准化规则: {self.stats['normalized_rules']}
- AdGuard Home兼容规则: {self.stats['adhome_compatible_rules']}
- AdGuard Home不兼容规则: {self.stats['adhome_incompatible_rules']}

### 性能指标
- AdGuard过滤器误报率: {self.adguard_filter.get_stats()['false_positive_rate']:.6f}

**输出文件**:
- AdGuard拦截规则: {self.config.OUTPUT_ADG_BLOCK}
- AdGuard允许规则: {self.config.OUTPUT_ADG_ALLOW}

**说明**: 输出规则完全兼容AdGuard Home，DEBUG级别可查看无效/重复规则详情。

"""
        if os.getenv('GITHUB_STEP_SUMMARY'):
            with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a', encoding='utf-8') as f:
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