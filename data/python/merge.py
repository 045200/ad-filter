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

# 日志级别可通过LOG_LEVEL环境变量控制
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
    """配置类 - 同时输出AdGuard和AdGuard Home规则"""
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
    OUTPUT_ADH_BLOCK: str = 'adblock_adh.txt'
    OUTPUT_ADH_ALLOW: str = 'allow_adh.txt'
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
        self.version = "未知"
        self.load_syntax_database()

    def load_syntax_database(self):
        """加载语法数据库"""
        self.db_path = self.config.SYNTAX_DB_FILE
        logger.info(f"尝试加载语法数据库，路径: {self.db_path}")
        if not self.db_path.exists():
            alternate_path = Path(__file__).parent / "adblock_syntax_db.json"
            logger.info(f"尝试备用路径: {alternate_path}")
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

    def is_rule_supported_by_adguard_home(self, rule_type: str) -> bool:
        if not self.adguard_home_specific or "supported_rule_types" not in self.adguard_home_specific:
            logger.warning("语法数据库中缺少AdGuard Home支持规则类型定义，使用默认值")
            return rule_type in ["domain_rule", "exception_rule", "adguard_dns_rule", "adguard_home_dns_rewrite", "adguard_home_client", "adguard_home_dnstype", "hosts_rule", "regex_rule"]
        return rule_type in self.adguard_home_specific["supported_rule_types"]

    def validate_rule_for_adguard_home(self, rule: str, rule_type: str) -> bool:
        if not self.is_rule_supported_by_adguard_home(rule_type):
            logger.debug(f"AdGuard Home不支持的规则类型: {rule_type} - {rule}")
            return False
        if rule_type == "adguard_home_dns_rewrite":
            max_length = self.adguard_home_specific.get("max_dns_rewrite_length", 1000)
            if len(rule) > max_length:
                logger.debug(f"DNS重写规则过长: {rule}")
                return False
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
        item_hash = hashlib.md5(item.encode('utf-8')).hexdigest()
        return item_hash in self.hash_set

    def get_stats(self) -> Dict[str, int]:
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
        self.adguard_filter = EnhancedBloomFilter(config)
        self.adhome_filter = EnhancedBloomFilter(config)
        self.adguard_block_rules = []
        self.adguard_allow_rules = []
        self.adhome_block_rules = []
        self.adhome_allow_rules = []
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
        self.file_stats = {
            "total_files": 0,
            "block_files": 0,
            "allow_files": 0
        }

    def github_log(self, level: str, message: str):
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
        result = {
            'type': 'unknown',
            'pattern_type': 'unknown',
            'modifiers': [],
            'is_valid': False,
            'normalized': rule.strip(),
            'is_allow': False
        }
        if re.match(r'^[!#]', rule):
            result['type'] = 'comment'
            return result
        rule = rule.strip()
        if not rule:
            result['type'] = 'empty'
            return result
        if len(rule) < self.config.MIN_RULE_LENGTH or len(rule) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            return result
        if rule.startswith('@@'):
            result['is_allow'] = True
        for pattern_name, pattern_str in self.syntax_db.syntax_patterns.items():
            try:
                pattern = re.compile(pattern_str)
                if pattern.match(rule):
                    result['pattern_type'] = pattern_name
                    result['type'] = self.syntax_db.rule_types.get(pattern_name, 'unknown')
                    if pattern_name == 'hosts_rule':
                        result['is_allow'] = False
                    result['is_valid'] = result['type'] not in ['invalid', 'comment', 'empty']
                    break
            except re.error as e:
                self.github_log('debug', f"正则表达式模式错误: {pattern_name} - {pattern_str}, 错误: {e}")
                continue
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
        return result

    def normalize_rule(self, rule: str) -> Optional[str]:
        analysis = self.analyze_rule_syntax(rule)
        if not analysis['is_valid']:
            return None
        normalized = analysis['normalized']

        # 白名单自动补全
        if analysis['is_allow']:
            # 只含@@domain.com自动补全为@@||domain.com^
            m = re.match(r'^@@([a-zA-Z0-9\.\-\_]+)$', normalized)
            if m:
                normalized = f'@@||{m.group(1)}^'
            # 只含@@http(s)://xxx自动补全为@@|url|
            elif re.match(r'^@@https?://', normalized):
                url = normalized[2:] if normalized.startswith('@@') else normalized
                normalized = f'@@|{url[2:]}|'
            elif not (normalized.startswith('@@||') or normalized.startswith('@@|')):
                # 兜底全部加@@||xxx^
                normalized = f'@@||{normalized}^'

        # 域名规则标准化
        if analysis['pattern_type'] == 'domain_rule':
            try:
                match = re.match(r'^\|\|([^\^]+)\^', normalized)
                if match:
                    domain = match.group(1).lower()
                    normalized = f'||{domain}^'
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
        # 添加排序后的修饰符
        if analysis['modifiers']:
            modifiers_str = ','.join(analysis['modifiers'])
            normalized = f'{normalized}${modifiers_str}'
        return normalized

    def is_valid_rule(self, rule: str) -> bool:
        analysis = self.analyze_rule_syntax(rule)
        return analysis['is_valid']

    def get_files_by_prefix(self, directory: Path) -> Tuple[List[Path], List[Path]]:
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
        except Exception as e:
            self.github_log('error', f"处理文件 {file_path} 时出错: {str(e)}")

    def process_batch(self, batch: List[str], is_allow_file: bool = False):
        for rule in batch:
            self.stats["total_processed"] += 1
            if not rule or re.match(r'^[!#]', rule):
                continue
            if not self.is_valid_rule(rule):
                self.stats["invalid_rules"] += 1
                continue
            analysis = self.analyze_rule_syntax(rule)
            normalized_rule = self.normalize_rule(rule)
            if not normalized_rule:
                self.stats["invalid_rules"] += 1
                continue
            adhome_compatible = (self.syntax_db.validate_rule_for_adguard_home(rule, analysis['pattern_type']) and self.syntax_db.check_unsupported_patterns(rule))
            is_allow_rule = analysis['is_allow']
            if self.adguard_filter.add(normalized_rule):
                self.stats["duplicates"] += 1
            else:
                if is_allow_rule:
                    self.adguard_allow_rules.append(normalized_rule)
                    self.stats["adguard_allow_rules"] += 1
                else:
                    self.adguard_block_rules.append(normalized_rule)
                    self.stats["adguard_block_rules"] += 1
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
        block_files, allow_files = self.get_files_by_prefix(self.config.INPUT_DIR)
        logger.info(f"\n文件分类结果：")
        logger.info(f"adblock前缀文件: {self.file_stats['block_files']} 个")
        logger.info(f"allow前缀文件: {self.file_stats['allow_files']} 个")
        logger.info(f"总计处理文件: {self.file_stats['total_files']} 个")
        for file_path in block_files:
            self.process_file_batch(file_path, is_allow_file=False)
        for file_path in allow_files:
            self.process_file_batch(file_path, is_allow_file=True)
        self.stats["bloom_false_positives"] = (
            self.adguard_filter.false_positive_count + 
            self.adhome_filter.false_positive_count
        )

    def save_results(self):
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 开始保存规则 ===")
        adg_block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_BLOCK
        with open(adg_block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_block_rules)))
        logger.info(f"AdGuard拦截规则已保存: {adg_block_path}")

        adg_allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADG_ALLOW
        with open(adg_allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adguard_allow_rules)))
        logger.info(f"AdGuard允许规则已保存: {adg_allow_path}")

        adh_block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADH_BLOCK
        with open(adh_block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adhome_block_rules)))
        logger.info(f"AdGuard Home拦截规则已保存: {adh_block_path}")

        adh_allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ADH_ALLOW
        with open(adh_allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.adhome_allow_rules)))
        logger.info(f"AdGuard Home允许规则已保存: {adh_allow_path}")

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

        adg_stats = self.adguard_filter.get_stats()
        adh_stats = self.adhome_filter.get_stats()
        logger.info(f"AdGuard过滤器误报率: {adg_stats['false_positive_rate']:.6f}")
        logger.info(f"AdGuard Home过滤器误报率: {adh_stats['false_positive_rate']:.6f}")

        if self.config.GITHUB_ACTIONS:
            self.generate_github_summary()

    def generate_github_summary(self):
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

"""
        if os.getenv('GITHUB_STEP_SUMMARY'):
            with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a') as f:
                f.write(summary)

def main():
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