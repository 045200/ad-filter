import os
import re
import json
import hashlib
import logging
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pybloom_live import ScalableBloomFilter

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class RuleType(Enum):
    """规则类型枚举"""
    DOMAIN = "domain_rule"
    EXCEPTION = "exception_rule"
    HOSTS = "hosts_rule"
    ELEMENT_HIDING = "element_hiding_basic"
    SCRIPTLET = "adguard_scriptlet"
    DNS = "adguard_dns_rule"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"

@dataclass
class AppConfig:
    """应用程序配置"""
    input_dir: Path = Path("data/filter")
    output_dir: Path = Path(".")
    bloom_init_cap: int = 1000000
    bloom_error_rate: float = 0.001
    max_rule_length: int = 2000
    min_rule_length: int = 3
    batch_size: int = 1000
    
    # 输出文件名（保持与原始脚本兼容）
    output_adg_block: str = "adblock_adg.txt"
    output_adg_allow: str = "allow_adg.txt"
    output_adh_block: str = "adblock_adh.txt"
    output_adh_allow: str = "allow_adh.txt"

    def __post_init__(self):
        """从环境变量初始化配置"""
        self.input_dir = Path(os.getenv("INPUT_DIR", str(self.input_dir)))
        self.output_dir = Path(os.getenv("OUTPUT_DIR", str(self.output_dir)))
        self.bloom_init_cap = int(os.getenv("BLOOM_INIT_CAP", self.bloom_init_cap))
        self.bloom_error_rate = float(os.getenv("BLOOM_ERROR_RATE", self.bloom_error_rate))
        self.max_rule_length = int(os.getenv("MAX_RULE_LENGTH", self.max_rule_length))
        self.min_rule_length = int(os.getenv("MIN_RULE_LENGTH", self.min_rule_length))
        self.batch_size = int(os.getenv("BATCH_SIZE", self.batch_size))

class EnhancedBloomFilter:
    """增强版布隆过滤器"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.bloom = ScalableBloomFilter(
            initial_capacity=config.bloom_init_cap,
            error_rate=config.bloom_error_rate,
            mode=ScalableBloomFilter.LARGE_SET_GROWTH
        )
        self.hash_set = set()
        self.false_positives = 0

    def add(self, item: str) -> bool:
        """添加元素到过滤器，返回是否已存在"""
        item_hash = hashlib.sha256(item.encode('utf-8')).hexdigest()
        
        if item in self.bloom:
            if item_hash not in self.hash_set:
                self.false_positives += 1
                return False
            return True
        
        self.bloom.add(item)
        self.hash_set.add(item_hash)
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取过滤器统计信息"""
        total = len(self.hash_set)
        fp_rate = self.false_positives / total if total > 0 else 0
        
        return {
            "total_items": total,
            "false_positives": self.false_positives,
            "false_positive_rate": f"{fp_rate:.6f}"
        }

class SyntaxDatabase:
    """语法数据库管理器"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.syntax_patterns = {}
        self.rule_types = {}
        self.platform_support = {}
        self.load_database()

    def load_database(self) -> bool:
        """加载语法数据库"""
        if not self.db_path.exists():
            logger.error(f"语法数据库文件不存在: {self.db_path}")
            return False

        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.syntax_patterns = data.get('syntax_patterns', {})
            self.rule_types = data.get('rule_types', {})
            self.platform_support = data.get('platform_support', {})
            
            logger.info(f"语法数据库加载成功: {len(self.syntax_patterns)} 个模式")
            return True
            
        except Exception as e:
            logger.error(f"加载语法数据库失败: {e}")
            return False

    def identify_rule_type(self, rule: str) -> RuleType:
        """识别规则类型"""
        rule = rule.strip()
        
        if not rule or len(rule) < 3:
            return RuleType.INVALID
            
        if rule.startswith(('!', '#')):
            return RuleType.INVALID
            
        for pattern_name, pattern in self.syntax_patterns.items():
            try:
                if re.match(pattern, rule):
                    return RuleType(self.rule_types.get(pattern_name, "invalid"))
            except re.error:
                continue
                
        return RuleType.UNSUPPORTED

    def is_supported_by_platform(self, rule: str, platform: str) -> bool:
        """检查规则是否被指定平台支持"""
        if platform not in self.platform_support:
            return False
            
        platform_info = self.platform_support[platform]
        rule_type = self.identify_rule_type(rule)
        
        return rule_type.value in platform_info.get("supported_rule_types", [])

class RuleProcessor:
    """规则处理器（保持文件分离）"""
    
    def __init__(self, config: AppConfig, syntax_db: SyntaxDatabase):
        self.config = config
        self.syntax_db = syntax_db
        
        # 为AdGuard和AdGuard Home分别创建过滤器
        self.adguard_filter = EnhancedBloomFilter(config)
        self.adhome_filter = EnhancedBloomFilter(config)
        
        # 分离存储不同类型的规则
        self.adguard_block_rules = []
        self.adguard_allow_rules = []
        self.adhome_block_rules = []
        self.adhome_allow_rules = []
        
        self.stats = {
            'processed': 0, 'duplicates': 0, 'invalid': 0,
            'unsupported': 0, 'by_type': {}
        }

    def process_files(self) -> None:
        """处理所有规则文件，保持adblock/allow分离"""
        if not self.config.input_dir.exists():
            logger.error(f"输入目录不存在: {self.config.input_dir}")
            return

        try:
            # 处理adblock文件（拦截规则）
            for file_path in self.config.input_dir.rglob("adblock*.txt"):
                logger.info(f"处理拦截规则文件: {file_path.name}")
                self._process_file(file_path, is_allow_file=False)
            
            # 处理allow文件（允许规则）
            for file_path in self.config.input_dir.rglob("allow*.txt"):
                logger.info(f"处理允许规则文件: {file_path.name}")
                self._process_file(file_path, is_allow_file=True)
                
        except Exception as e:
            logger.error(f"处理文件时发生错误: {e}")

    def _process_file(self, file_path: Path, is_allow_file: bool) -> None:
        """处理单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    rule = line.strip()
                    if not rule or rule.startswith(('!', '#')):
                        continue
                        
                    self._process_rule(rule, is_allow_file)
                        
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")

    def _process_rule(self, rule: str, is_allow_rule: bool) -> None:
        """处理单个规则"""
        self.stats['processed'] += 1
        
        rule_type = self.syntax_db.identify_rule_type(rule)
        if rule_type == RuleType.INVALID:
            self.stats['invalid'] += 1
            return
            
        # 更新类型统计
        self.stats['by_type'][rule_type.value] = self.stats['by_type'].get(rule_type.value, 0) + 1
        
        # 检查AdGuard支持
        adguard_supported = self.syntax_db.is_supported_by_platform(rule, "adguard")
        adhome_supported = self.syntax_db.is_supported_by_platform(rule, "adguard_home")
        
        if not adguard_supported and not adhome_supported:
            self.stats['unsupported'] += 1
            return
        
        # 处理AdGuard规则
        if adguard_supported:
            if self.adguard_filter.add(rule):
                self.stats['duplicates'] += 1
            else:
                if is_allow_rule:
                    self.adguard_allow_rules.append(rule)
                else:
                    self.adguard_block_rules.append(rule)
        
        # 处理AdGuard Home规则
        if adhome_supported:
            if self.adhome_filter.add(rule):
                self.stats['duplicates'] += 1
            else:
                if is_allow_rule:
                    self.adhome_allow_rules.append(rule)
                else:
                    self.adhome_block_rules.append(rule)

    def save_results(self) -> None:
        """保存处理结果"""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存AdGuard规则
        if self.adguard_block_rules:
            output_file = self.config.output_dir / self.config.output_adg_block
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.adguard_block_rules))))
            logger.info(f"AdGuard拦截规则已保存: {output_file}")
        
        if self.adguard_allow_rules:
            output_file = self.config.output_dir / self.config.output_adg_allow
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.adguard_allow_rules))))
            logger.info(f"AdGuard允许规则已保存: {output_file}")
        
        # 保存AdGuard Home规则
        if self.adhome_block_rules:
            output_file = self.config.output_dir / self.config.output_adh_block
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.adhome_block_rules))))
            logger.info(f"AdGuard Home拦截规则已保存: {output_file}")
        
        if self.adhome_allow_rules:
            output_file = self.config.output_dir / self.config.output_adh_allow
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(set(self.adhome_allow_rules))))
            logger.info(f"AdGuard Home允许规则已保存: {output_file}")

    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        adguard_stats = self.adguard_filter.get_stats()
        adhome_stats = self.adhome_filter.get_stats()
        
        return {
            **self.stats,
            "adguard_rules": len(self.adguard_block_rules) + len(self.adguard_allow_rules),
            "adhome_rules": len(self.adhome_block_rules) + len(self.adhome_allow_rules),
            "adguard_false_positives": adguard_stats["false_positives"],
            "adhome_false_positives": adhome_stats["false_positives"],
            "adguard_false_positive_rate": adguard_stats["false_positive_rate"],
            "adhome_false_positive_rate": adhome_stats["false_positive_rate"]
        }

def main():
    """主函数"""
    config = AppConfig()
    db_path = Path("data/python/adblock_syntax_db.json")
    
    # 确保输出目录存在
    config.output_dir.mkdir(parents=True, exist_ok=True)
    
    # 初始化语法数据库
    syntax_db = SyntaxDatabase(db_path)
    if not syntax_db.load_database():
        logger.error("无法加载语法数据库，使用基本规则处理")
        # 即使数据库加载失败，也继续处理，但只处理基本规则类型
    
    # 处理规则
    processor = RuleProcessor(config, syntax_db)
    processor.process_files()
    processor.save_results()
    
    # 输出统计信息
    stats = processor.get_stats()
    logger.info("=== 处理统计 ===")
    logger.info(f"总处理规则: {stats['processed']}")
    logger.info(f"AdGuard规则: {stats['adguard_rules']}")
    logger.info(f"AdGuard Home规则: {stats['adhome_rules']}")
    logger.info(f"重复规则: {stats['duplicates']}")
    logger.info(f"无效规则: {stats['invalid']}")
    logger.info(f"不支持规则: {stats['unsupported']}")
    logger.info(f"AdGuard误报率: {stats['adguard_false_positive_rate']}")
    logger.info(f"AdGuard Home误报率: {stats['adhome_false_positive_rate']}")
    
    # 输出规则类型统计
    if stats['by_type']:
        logger.info("=== 规则类型分布 ===")
        for rule_type, count in stats['by_type'].items():
            logger.info(f"{rule_type}: {count}")

if __name__ == "__main__":
    main()