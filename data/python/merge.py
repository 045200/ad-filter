import os
import re
import json
import requests
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional, Any
from pybloom_live import ScalableBloomFilter
from dataclasses import dataclass
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class AdBlockConfig:
    """配置类 - 白名单规则优化"""
    # 基础路径配置
    INPUT_DIR: Path = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR: Path = Path(os.getenv('OUTPUT_DIR', './data/filter'))
    
    # 文件模式配置
    ADBLOCK_PATTERNS: List[str] = None
    OUTPUT_BLOCK: str = 'adblock_merged.txt'
    OUTPUT_ALLOW: str = 'allow_merged.txt'
    
    # 布隆过滤器配置
    BLOOM_INIT_CAP: int = 1000000
    BLOOM_ERROR_RATE: float = 0.0001
    
    # 规则处理配置
    MAX_RULE_LENGTH: int = 2000  # 规则最大长度限制
    MIN_RULE_LENGTH: int = 3     # 规则最小长度限制
    
    # 语法数据库配置
    SYNTAX_DB_FILE: str = "adblock_syntax_db.json"
    
    def __post_init__(self):
        if self.ADBLOCK_PATTERNS is None:
            self.ADBLOCK_PATTERNS = ['*.txt', '*.filter']

class AdBlockSyntaxDatabase:
    """AdBlock和AdGuard语法数据库"""
    def __init__(self, config: AdBlockConfig):
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
        
        # 如果都没有找到，使用内置的基本语法规则
        logger.warning("未找到语法数据库文件，使用内置基本语法规则")
        self.load_basic_syntax()
        
        # 尝试保存基本语法数据库到脚本目录
        try:
            self.save_syntax_database(script_dir / self.config.SYNTAX_DB_FILE)
        except Exception as e:
            logger.error(f"保存基本语法数据库失败: {e}")
    
    def save_syntax_database(self, db_path: Path):
        """保存语法数据库到文件"""
        db_data = {
            'syntax_patterns': self.syntax_patterns,
            'rule_types': self.rule_types,
            'modifiers': self.modifiers,
            'version': '1.0',
            'description': 'AdBlock/AdGuard 语法数据库'
        }
        
        with open(db_path, 'w', encoding='utf-8') as f:
            json.dump(db_data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"语法数据库已保存到: {db_path}")
    
    def load_basic_syntax(self):
        """加载基本语法规则（备用）"""
        # 基本规则模式
        self.syntax_patterns = {
            'domain_rule': r'^\|\|([^\^]+)\^',
            'url_rule': r'^\|([^\|]+)\|',
            'element_hiding': r'^([^#]+)##([^#]+)',
            'exception_rule': r'^@@',
            'regex_rule': r'^/(.+)/$',
            'comment': r'^!',
            'options': r'\$(.+)$'
        }
        
        # 规则类型定义
        self.rule_types = {
            'domain_rule': 'block',
            'url_rule': 'block',
            'element_hiding': 'block',
            'exception_rule': 'allow',
            'regex_rule': 'block',
            'comment': 'invalid',
            'options': 'modifier'
        }
        
        # 修饰符定义
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
            'webrtc': r'webrtc'
        }
        
        logger.info("使用内置基本语法规则")

class AdBlockMerger:
    def __init__(self, config: AdBlockConfig):
        self.config = config
        self.bloom_filter = ScalableBloomFilter(
            initial_capacity=config.BLOOM_INIT_CAP, 
            error_rate=config.BLOOM_ERROR_RATE
        )
        self.syntax_db = AdBlockSyntaxDatabase(config)
        self.rule_dict: Dict[str, str] = {}  # 存储规则和其类型的映射
        self.seen_rules: Set[str] = set()     # 精确去重集合
        self.rule_stats = {
            'total_processed': 0,
            'valid_rules': 0,
            'duplicate_rules': 0,
            'invalid_rules': 0,
            'block_rules': 0,
            'allow_rules': 0,
            'unknown_rules': 0
        }
        
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
                logger.warning(f"正则表达式模式错误: {pattern_name} - {pattern}")
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
                    logger.warning(f"修饰符正则表达式错误: {mod_name} - {mod_pattern}")
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

    def process_rules(self, rules: List[str], source: str = "unknown") -> Tuple[int, int]:
        """处理规则列表并去重"""
        added_count = 0
        skipped_count = 0
        
        for rule in rules:
            self.rule_stats['total_processed'] += 1
            
            if not self.is_valid_rule(rule):
                self.rule_stats['invalid_rules'] += 1
                continue
                
            normalized_rule = self.normalize_rule(rule)
            if not normalized_rule:
                self.rule_stats['invalid_rules'] += 1
                continue
                
            # 使用布隆过滤器进行初步去重
            if normalized_rule in self.bloom_filter:
                # 使用精确集合进行二次验证
                if normalized_rule in self.seen_rules:
                    skipped_count += 1
                    self.rule_stats['duplicate_rules'] += 1
                    continue
            
            # 添加到过滤器和集合中
            self.bloom_filter.add(normalized_rule)
            self.seen_rules.add(normalized_rule)
            
            # 确定规则类型并统计
            rule_type = self.determine_rule_type(normalized_rule)
            self.rule_dict[normalized_rule] = rule_type
            
            if rule_type == 'allow':
                self.rule_stats['allow_rules'] += 1
            elif rule_type == 'block':
                self.rule_stats['block_rules'] += 1
            else:
                self.rule_stats['unknown_rules'] += 1
                
            added_count += 1
            self.rule_stats['valid_rules'] += 1
            
        return added_count, skipped_count

    def recursive_read_files(self, directory: Path, patterns: List[str]) -> List[str]:
        """递归读取目录下匹配模式的所有文件"""
        all_rules = []
        
        if not directory.exists():
            logger.warning(f"目录 {directory} 不存在，正在创建...")
            directory.mkdir(parents=True, exist_ok=True)
            return all_rules
            
        for pattern in patterns:
            for file_path in directory.rglob(pattern):
                if file_path.is_file() and file_path.name != self.config.SYNTAX_DB_FILE:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            rules = f.read().splitlines()
                            all_rules.extend(rules)
                            logger.info(f"从 {file_path} 读取了 {len(rules)} 条规则")
                    except Exception as e:
                        logger.error(f"读取文件 {file_path} 失败: {e}")
                    
        return all_rules

    def merge_and_deduplicate(self):
        """主函数：合并和去重所有规则"""
        logger.info("开始处理本地规则...")
        
        # 读取本地所有规则文件
        local_rules = self.recursive_read_files(
            self.config.INPUT_DIR, 
            self.config.ADBLOCK_PATTERNS
        )
        
        # 处理本地规则
        added, skipped = self.process_rules(local_rules, "local")
        
        logger.info(f"本地规则处理完成:")
        logger.info(f"  总处理规则: {self.rule_stats['total_processed']}")
        logger.info(f"  有效规则: {self.rule_stats['valid_rules']}")
        logger.info(f"  重复规则: {self.rule_stats['duplicate_rules']}")
        logger.info(f"  无效规则: {self.rule_stats['invalid_rules']}")
        logger.info(f"  黑名单规则: {self.rule_stats['block_rules']}")
        logger.info(f"  白名单规则: {self.rule_stats['allow_rules']}")
        logger.info(f"  未知类型规则: {self.rule_stats['unknown_rules']}")

    def save_rules(self):
        """保存去重后的规则到文件"""
        # 确保输出目录存在
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # 分离黑名单和白名单规则
        block_rules = []
        allow_rules = []
        
        for rule, rule_type in self.rule_dict.items():
            if rule_type == 'allow':
                allow_rules.append(rule)
            else:
                block_rules.append(rule)
        
        # 按字母顺序排序规则
        block_rules.sort()
        allow_rules.sort()
        
        # 保存黑名单规则
        block_output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_BLOCK
        with open(block_output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(block_rules))
        
        # 保存白名单规则
        allow_output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ALLOW
        with open(allow_output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(allow_rules))
        
        logger.info(f"\n规则保存完成:")
        logger.info(f"  {len(block_rules)} 条黑名单规则保存到 {block_output_path}")
        logger.info(f"  {len(allow_rules)} 条白名单规则保存到 {allow_output_path}")


def main():
    """主函数"""
    # 初始化配置
    config = AdBlockConfig()
    
    # 创建合并器实例
    merger = AdBlockMerger(config)
    
    # 执行合并和去重
    merger.merge_and_deduplicate()
    
    # 保存结果
    merger.save_rules()


if __name__ == "__main__":
    main()