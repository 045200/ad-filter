#!/usr/bin/env python3
"""
AdGuard全平台规则转换脚本 - 增强修复版
修复平台支持问题，增强规则识别
"""

import json
import hashlib
import re
from typing import List, Dict, Tuple, Set, Optional
from pathlib import Path

try:
    from adblockparser import AdblockRule
    HAS_ADBLOCK_PARSER = True
except ImportError:
    HAS_ADBLOCK_PARSER = False
    print("错误: adblockparser 未安装，这是必需依赖")
    exit(1)

class Logger:
    """简化日志管理器"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def info(self, message: str):
        """信息日志"""
        print(f"[INFO] {message}")
    
    def warning(self, message: str):
        """警告日志"""
        print(f"[WARNING] {message}")
    
    def error(self, message: str):
        """错误日志"""
        print(f"[ERROR] {message}")
    
    def progress(self, current: int, total: int, stage: str = ""):
        """进度日志"""
        if current % 10000 == 0 or current == total:
            percentage = (current / total) * 100
            stage_info = f" [{stage}]" if stage else ""
            print(f"[PROGRESS] 已处理 {current}/{total} 行 ({percentage:.1f}%){stage_info}")

class EnhancedAdBlockClassifier:
    """增强型AdBlock分类器 - 修复平台支持问题"""
    
    def __init__(self, syntax_db: Dict, logger: Logger):
        self.syntax_db = syntax_db
        self.logger = logger
        self.compiled_patterns = self._compile_patterns()
        self.common_patterns = self._compile_common_patterns()
        
        # 基础规则到平台支持的映射
        self.basic_rule_support = self._init_basic_rule_support()
        
        self.logger.info("增强型分类器已初始化")
        self.logger.info(f"已编译 {len(self.compiled_patterns)} 个高级语法模式")
        self.logger.info(f"已配置 {len(self.basic_rule_support)} 个基础规则支持")
    
    def _init_basic_rule_support(self) -> Dict[str, List[str]]:
        """初始化基础规则平台支持映射"""
        return {
            'adblock_basic_domain_rule': ['adg', 'abp', 'ubo'],
            'adblock_basic_exception_rule': ['adg', 'abp', 'ubo'],
            'adblock_basic_element_hiding': ['adg', 'abp', 'ubo'],
            'adblock_basic_element_hiding_exception': ['adg', 'abp', 'ubo'],
            'adblock_basic_url_rule': ['adg', 'abp', 'ubo'],
            'adblock_basic_generic_hide': ['adg', 'abp', 'ubo'],
            'adblock_basic_generic_hide_exception': ['adg', 'abp', 'ubo'],
            'hosts_rule': ['adg', 'abp', 'ubo'],
            'pihole_domain': ['adg', 'abp', 'ubo'],
            'pihole_regex': ['adg', 'ubo'],
            'regex_rule': ['adg', 'ubo'],
            'adblock_basic_regex_rule': ['adg', 'ubo'],
        }
    
    def _compile_patterns(self) -> Dict[str, any]:
        """编译语法数据库中的正则模式"""
        compiled = {}
        patterns = self.syntax_db.get('advanced_syntax_patterns', {})
        
        for rule_type, pattern_str in patterns.items():
            try:
                compiled[rule_type] = re.compile(pattern_str)
            except re.error as e:
                self.logger.warning(f"正则模式编译失败 {rule_type}: {e}")
                continue
        
        return compiled
    
    def _compile_common_patterns(self) -> Dict[str, any]:
        """编译常用规则模式"""
        patterns = {
            'hosts_rule': re.compile(r'^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+'),
            'pihole_domain': re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'pihole_regex': re.compile(r'^/(?:[^/\\\\]|\\\\.)*/$'),
            'basic_domain': re.compile(r'^\|\|([a-zA-Z0-9.-]+[a-zA-Z0-9])\^$'),
            'basic_exception': re.compile(r'^@@\|\|([a-zA-Z0-9.-]+[a-zA-Z0-9])\^$'),
            'element_hiding': re.compile(r'^##[^#]'),
            'element_hiding_exception': re.compile(r'^#@#|^@@##'),
            'url_rule': re.compile(r'^\|https?://[^|]+\|$'),
            'regex_rule': re.compile(r'^/(?:[^\\n]|\\([^)]*\\))+/$'),
            'comment': re.compile(r'^!'),
        }
        return patterns
    
    def classify_rule(self, rule: str) -> Tuple[str, List[str]]:
        """分类单条规则 - 增强版本"""
        rule = rule.strip()
        
        if not rule:
            return 'empty', []
        
        # 快速基础分类
        basic_type = self._quick_classify(rule)
        if basic_type and basic_type != 'unknown':
            platforms = self._get_platform_support(basic_type)
            return basic_type, platforms
        
        # 使用 adblockparser 进行详细分类
        if HAS_ADBLOCK_PARSER:
            detailed_type = self._classify_with_adblockparser(rule)
            if detailed_type and detailed_type != 'unknown':
                platforms = self._get_platform_support(detailed_type)
                return detailed_type, platforms
        
        # 使用语法数据库进行高级分类
        advanced_type = self._classify_with_syntax_db(rule)
        if advanced_type:
            platforms = self._get_platform_support(advanced_type)
            return advanced_type, platforms
        
        # 最后尝试通用分类
        generic_type = self._generic_classify(rule)
        if generic_type:
            platforms = self._get_platform_support(generic_type)
            return generic_type, platforms
        
        return 'unknown', []
    
    def _quick_classify(self, rule: str) -> Optional[str]:
        """快速基础分类"""
        if not rule:
            return 'empty'
        
        if rule.startswith('!'):
            return 'comment'
        
        # 使用预编译模式快速匹配
        for pattern_name, pattern in self.common_patterns.items():
            if pattern.match(rule):
                return pattern_name
        
        return None
    
    def _classify_with_adblockparser(self, rule: str) -> str:
        """使用 adblockparser 进行详细分类"""
        try:
            adblock_rule = AdblockRule(rule)
            
            if adblock_rule.is_comment:
                return 'comment'
            
            # 详细的规则类型映射
            if adblock_rule.is_exception:
                if adblock_rule.is_elemhide:
                    return 'adblock_basic_element_hiding_exception'
                elif adblock_rule.is_generic_hide:
                    return 'adblock_basic_generic_hide_exception'
                else:
                    return 'adblock_basic_exception_rule'
            elif adblock_rule.is_elemhide:
                return 'adblock_basic_element_hiding'
            elif adblock_rule.is_generic_hide:
                return 'adblock_basic_generic_hide'
            else:
                # 进一步细分基础规则
                if rule.startswith('||') and rule.endswith('^'):
                    return 'adblock_basic_domain_rule'
                elif '^' in rule and ('|' in rule or '$' in rule):
                    return 'adblock_basic_url_rule'
                else:
                    return 'adblock_basic_domain_rule'
                    
        except Exception as e:
            return 'unknown'
    
    def _classify_with_syntax_db(self, rule: str) -> Optional[str]:
        """使用语法数据库进行高级分类"""
        for rule_type, pattern in self.compiled_patterns.items():
            if pattern.search(rule):
                return rule_type
        return None
    
    def _generic_classify(self, rule: str) -> Optional[str]:
        """通用分类 - 处理无法识别的规则"""
        # 尝试基于内容特征进行分类
        if rule.startswith('@@'):
            return 'adblock_basic_exception_rule'
        elif rule.startswith('##'):
            return 'adblock_basic_element_hiding'
        elif rule.startswith('||') and rule.endswith('^'):
            return 'adblock_basic_domain_rule'
        elif rule.startswith('|') and rule.endswith('|'):
            return 'adblock_basic_url_rule'
        elif '/' in rule and rule.startswith('/') and rule.endswith('/'):
            return 'regex_rule'
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return 'pihole_domain'
        
        return None
    
    def _get_platform_support(self, rule_type: str) -> List[str]:
        """获取规则平台支持 - 修复版本"""
        # 首先检查基础规则支持
        if rule_type in self.basic_rule_support:
            return self.basic_rule_support[rule_type]
        
        # 然后检查语法数据库支持
        platforms = []
        platform_support = self.syntax_db.get('platform_support', {})
        
        # 平台映射
        platform_mapping = {
            'adguard_browser_extension': 'adg',
            'adblock_plus': 'abp',
            'ublock_origin': 'ubo'
        }
        
        for platform_key, platform_code in platform_mapping.items():
            if self._is_platform_supported(platform_support, platform_key, rule_type):
                platforms.append(platform_code)
        
        # 如果语法数据库中没有找到支持，使用默认支持
        if not platforms:
            # 对于未知规则，默认支持所有平台
            if rule_type == 'unknown':
                return ['adg', 'abp', 'ubo']
            # 对于其他规则，默认支持AdGuard
            else:
                return ['adg']
        
        return platforms
    
    def _is_platform_supported(self, platform_support: Dict, platform: str, rule_type: str) -> bool:
        """检查特定平台是否支持该规则类型"""
        if platform in platform_support:
            supported_types = platform_support[platform].get('supported_rule_types', [])
            return rule_type in supported_types
        return False
    
    def is_allow_rule(self, rule_type: str, rule_content: str) -> bool:
        """判断是否为允许规则（白名单）"""
        allow_indicators = ['@@', '#@#', '@@##']
        allow_types = [
            'adblock_basic_exception_rule',
            'adblock_basic_element_hiding_exception',
            'adblock_basic_generic_hide_exception'
        ]
        
        return (rule_type in allow_types or 
                any(rule_content.startswith(indicator) for indicator in allow_indicators))

class RuleStatistics:
    """详细规则统计器"""
    
    def __init__(self):
        self.counts = {
            'total_lines': 0, 'comments': 0, 'empty_lines': 0,
            'valid_rules': 0, 'duplicates': 0, 'errors': 0,
            'unknown_rules': 0
        }
        self.platform_counts = {'adg': 0, 'abp': 0, 'ubo': 0}
        self.rule_types = {}
        self.classification_sources = {'quick': 0, 'adblockparser': 0, 'syntax_db': 0, 'generic': 0}
    
    def count(self, category: str):
        """计数"""
        if category in self.counts:
            self.counts[category] += 1
    
    def add_rule(self, rule_type: str, platforms: List[str], source: str = 'unknown'):
        """添加规则统计"""
        self.count('valid_rules')
        
        # 规则类型统计
        if rule_type not in self.rule_types:
            self.rule_types[rule_type] = 0
        self.rule_types[rule_type] += 1
        
        # 分类来源统计
        if source in self.classification_sources:
            self.classification_sources[source] += 1
        
        # 平台统计
        for platform in platforms:
            if platform in self.platform_counts:
                self.platform_counts[platform] += 1
    
    def print_summary(self):
        """打印详细统计摘要"""
        print("\n" + "="*60)
        print("详细规则处理统计")
        print("="*60)
        
        # 基础统计
        print(f"\n📊 文件处理统计:")
        stats_data = [
            ("总行数", self.counts['total_lines']),
            ("有效规则", self.counts['valid_rules']),
            ("重复规则", self.counts['duplicates']),
            ("未知规则", self.counts['unknown_rules']),
            ("注释/空行", self.counts['comments'] + self.counts['empty_lines']),
            ("处理错误", self.counts['errors'])
        ]
        
        for name, count in stats_data:
            print(f"  {name:<12}: {count:>8} 行")
        
        # 平台统计
        print(f"\n🏷️  平台规则分布:")
        platform_names = {'adg': 'AdGuard', 'abp': 'AdBlock Plus', 'ubo': 'uBlock Origin'}
        for platform, count in self.platform_counts.items():
            percentage = (count / self.counts['valid_rules']) * 100 if self.counts['valid_rules'] > 0 else 0
            print(f"  {platform_names[platform]:<15}: {count:>8} 条 ({percentage:>5.1f}%)")
        
        # 分类来源统计
        print(f"\n🔍 分类来源统计:")
        total_classified = sum(self.classification_sources.values())
        for source, count in self.classification_sources.items():
            if count > 0:
                percentage = (count / total_classified) * 100 if total_classified > 0 else 0
                source_name = {
                    'quick': '快速分类',
                    'adblockparser': 'adblockparser', 
                    'syntax_db': '语法数据库',
                    'generic': '通用分类'
                }.get(source, source)
                print(f"  {source_name:<12}: {count:>8} 条 ({percentage:>5.1f}%)")
        
        # 规则类型统计
        if self.rule_types:
            print(f"\n📋 主要规则类型分布 (前10):")
            sorted_types = sorted(self.rule_types.items(), key=lambda x: x[1], reverse=True)[:10]
            for rule_type, count in sorted_types:
                percentage = (count / self.counts['valid_rules']) * 100 if self.counts['valid_rules'] > 0 else 0
                display_name = rule_type.replace('adblock_basic_', '').replace('_', ' ').title()
                print(f"  {display_name:<30}: {count:>6} 条 ({percentage:>5.1f}%)")

class RuleProcessor:
    """高效规则处理器"""
    
    def __init__(self, syntax_db_path: str):
        # 先初始化logger
        self.logger = Logger()
        
        # 然后加载语法数据库（现在可以使用logger了）
        self.syntax_db = self._load_syntax_db(syntax_db_path)
        
        # 初始化其他组件
        self.classifier = EnhancedAdBlockClassifier(self.syntax_db, self.logger)
        self.statistics = RuleStatistics()
        
        # 高效去重
        self.seen_rules = set()
        
        # 平台规则存储
        self.platform_rules = {
            'adg': {'block': set(), 'allow': set()},
            'abp': {'block': set(), 'allow': set()},
            'ubo': {'block': set(), 'allow': set()}
        }
    
    def _load_syntax_db(self, db_path: str) -> Dict:
        """加载语法数据库"""
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                db = json.load(f)
                version = db.get('version', '未知')
                desc = db.get('description', '')
                self.logger.info(f"语法数据库加载成功 - 版本: {version}")
                if desc:
                    self.logger.info(f"数据库描述: {desc}")
                return db
        except Exception as e:
            self.logger.error(f"无法加载语法数据库: {e}")
            return {}
    
    def _is_duplicate(self, rule: str) -> bool:
        """高效去重检查"""
        # 使用规则内容本身进行去重（比MD5更快）
        if rule in self.seen_rules:
            return True
        self.seen_rules.add(rule)
        return False
    
    def process_file(self, input_path: str):
        """处理输入文件"""
        self.logger.info(f"开始处理文件: {input_path}")
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.error(f"无法读取输入文件: {e}")
            return
        
        total_lines = len(lines)
        self.statistics.counts['total_lines'] = total_lines
        
        self.logger.info(f"读取到 {total_lines} 行规则")
        
        for line_num, line in enumerate(lines, 1):
            try:
                self._process_single_rule(line.rstrip('\n'))
                
                # 进度显示
                if line_num % 10000 == 0:
                    self.logger.progress(line_num, total_lines, "分类处理")
                    
            except Exception as e:
                self.statistics.count('errors')
                # 只在开始时显示错误以便调试
                if line_num <= 100 and line_num % 10 == 0:
                    self.logger.warning(f"第 {line_num} 行处理错误: {e}")
        
        self.logger.info("文件处理完成")
    
    def _process_single_rule(self, rule: str):
        """处理单条规则"""
        rule_type, platforms = self.classifier.classify_rule(rule)
        
        # 跟踪分类来源
        source = 'unknown'
        if rule_type in ['empty', 'comment']:
            source = 'quick'
        elif rule_type != 'unknown':
            if rule_type in self.classifier.common_patterns:
                source = 'quick'
            elif rule_type in self.classifier.compiled_patterns:
                source = 'syntax_db'
            elif hasattr(self.classifier, '_generic_classify') and rule_type in [
                'adblock_basic_exception_rule', 'adblock_basic_element_hiding', 
                'adblock_basic_domain_rule', 'adblock_basic_url_rule', 'regex_rule'
            ]:
                source = 'generic'
            else:
                source = 'adblockparser'
        
        # 统计分类
        if rule_type in ['empty', 'comment']:
            self.statistics.count('comments' if rule_type == 'comment' else 'empty_lines')
            return
        
        if rule_type == 'unknown':
            self.statistics.count('unknown_rules')
            return
        
        # 去重检查
        if self._is_duplicate(rule):
            self.statistics.count('duplicates')
            return
        
        # 添加到对应平台
        is_allow = self.classifier.is_allow_rule(rule_type, rule)
        self.statistics.add_rule(rule_type, platforms, source)
        
        for platform in platforms:
            if platform in self.platform_rules:
                rule_set = 'allow' if is_allow else 'block'
                self.platform_rules[platform][rule_set].add(rule)
    
    def save_results(self, output_dir: str):
        """保存结果到文件"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"保存结果到: {output_path}")
        
        # 文件映射
        file_mapping = {
            'adg': {
                'block': 'adblock_adg.txt',
                'allow': 'allow_adg.txt'
            },
            'abp': {
                'block': 'adblock_abp.txt', 
                'allow': 'allow_abp.txt'
            },
            'ubo': {
                'block': 'adblock_ubo.txt',
                'allow': 'allow_ubo.txt'
            }
        }
        
        saved_files = []
        total_rules = 0
        
        for platform, files in file_mapping.items():
            for rule_type, filename in files.items():
                rules = self.platform_rules[platform][rule_type]
                if rules:
                    filepath = output_path / filename
                    rule_count = len(rules)
                    self._write_rules_to_file(filepath, sorted(rules), platform, rule_type)
                    saved_files.append((filepath.name, rule_count, rule_type))
                    total_rules += rule_count
        
        # 输出保存结果
        print("\n" + "="*50)
        print("📁 生成的文件清单")
        print("="*50)
        for filename, count, rule_type in saved_files:
            rule_type_name = '允许规则' if rule_type == 'allow' else '拦截规则'
            rule_icon = '✅' if rule_type == 'allow' else '🚫'
            print(f"{rule_icon} {filename}: {count} 条{rule_type_name}")
        
        print(f"\n📦 总计生成: {total_rules} 条规则")
    
    def _write_rules_to_file(self, filepath: Path, rules: List[str], platform: str, rule_type: str):
        """写入规则到文件"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # 文件头信息
                platform_names = {
                    'adg': 'AdGuard全平台',
                    'abp': 'AdBlock Plus',
                    'ubo': 'uBlock Origin'
                }
                rule_type_names = {
                    'block': '拦截规则',
                    'allow': '允许规则'
                }
                
                f.write(f"! {platform_names[platform]} {rule_type_names[rule_type]}\n")
                f.write(f"! 生成时间: {self._get_current_time()}\n")
                f.write(f"! 规则数量: {len(rules)}\n")
                f.write(f"! 分类方式: 增强型adblockparser + 语法数据库\n")
                f.write(f"! 来源文件: {Path(__file__).name}\n")
                f.write(f"! 语法数据库版本: {self.syntax_db.get('version', '未知')}\n\n")
                
                # 写入规则
                for i, rule in enumerate(rules):
                    f.write(f"{rule}\n")
                    
            self.logger.info(f"已写入: {filepath.name} ({len(rules)} 条规则)")
                    
        except Exception as e:
            self.logger.error(f"无法写入文件 {filepath}: {e}")
    
    def _get_current_time(self) -> str:
        """获取当前时间字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def print_statistics(self):
        """打印统计信息"""
        self.statistics.print_summary()

def check_dependencies():
    """检查依赖"""
    if not HAS_ADBLOCK_PARSER:
        print("❌ 错误: adblockparser 库未安装")
        print("请安装: pip install adblockparser")
        return False
    return True

def main():
    """主函数"""
    # 检查依赖
    if not check_dependencies():
        return
    
    # 文件路径配置
    base_dir = Path(__file__).parent.parent.parent
    input_file = base_dir / "data" / "filter" / "rule.txt"
    syntax_db_file = base_dir / "data" / "python" / "syntax_db.json"
    output_dir = base_dir
    
    # 检查文件存在
    if not input_file.exists():
        print(f"❌ 错误: 输入文件不存在: {input_file}")
        return
    
    if not syntax_db_file.exists():
        print(f"❌ 错误: 语法数据库不存在: {syntax_db_file}")
        return
    
    print("🚀 AdGuard全平台规则转换器 - 增强修复版")
    print(f"📂 输入文件: {input_file}")
    print(f"🗃️  语法数据库: {syntax_db_file}")
    print(f"📁 输出目录: {output_dir}")
    print("-" * 50)
    
    # 初始化处理器
    processor = RuleProcessor(str(syntax_db_file))
    
    # 处理文件
    processor.process_file(str(input_file))
    
    # 保存结果
    processor.save_results(str(output_dir))
    
    # 打印统计
    processor.print_statistics()
    
    print("\n🎉 处理完成！")

if __name__ == "__main__":
    main()