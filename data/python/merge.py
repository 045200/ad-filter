#!/usr/bin/env python3
"""
AdGuard全平台规则转换脚本 - 精准修复版
专注AdGuard全平台语法，无文件头输出，预编译正则全覆盖
"""

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

class AdGuardRuleClassifier:
    """AdGuard规则分类器 - 全平台语法覆盖"""

    def __init__(self, logger: Logger):
        self.logger = logger
        
        # 预编译所有AdGuard全平台正则表达式模式
        self.patterns = self._compile_adguard_patterns()
        
        # 规则类型到平台支持的映射
        self.rule_support = self._init_rule_support()
        
        self.logger.info("AdGuard全平台分类器已初始化")
        self.logger.info(f"已预编译 {len(self.patterns)} 个AdGuard正则表达式模式")

    def _compile_adguard_patterns(self) -> Dict[str, any]:
        """预编译AdGuard全平台正则表达式模式[citation:1][citation:5][citation:8]"""
        patterns = {
            # AdGuard基础域名规则[citation:8]
            'adguard_domain_rule': re.compile(r'^\|\|([a-zA-Z0-9.-]+[a-zA-Z0-9])\^(\$[^,\s]+)?$'),
            
            # AdGuard例外规则[citation:5]
            'adguard_exception_rule': re.compile(r'^@@\|\|([a-zA-Z0-9.-]+[a-zA-Z0-9])\^(\$[^,\s]+)?$'),
            
            # AdGuard元素隐藏规则[citation:8]
            'adguard_element_hiding': re.compile(r'^##[^#@\s]'),
            'adguard_element_hiding_exception': re.compile(r'^#@#[^#\s]|^@@##[^#\s]'),
            
            # AdGuard URL规则[citation:8]
            'adguard_url_rule': re.compile(r'^\|(https?://|http://)?[^|]+\|$'),
            
            # AdGuard修饰符规则[citation:1][citation:2]
            'adguard_csp_rule': re.compile(r'^[^$]*\$[^$,]+csp=[^,$\s]+'),
            'adguard_scriptlet_rule': re.compile(r'^[^$]*\$[^$,]+script(?:let)?=[^,$\s]+'),
            'adguard_removeparam_rule': re.compile(r'^[^$]*\$[^$,]+removeparam=[^,$\s]+'),
            'adguard_extension_rule': re.compile(r'^[^$]*\$[^$,]+extension[^,$\s]*'),
            'adguard_domain_modifier': re.compile(r'^[^$]*\$[^$,]+domain=[^,$\s]+'),
            'adguard_important_rule': re.compile(r'^[^$]*\$[^$,]+important'),
            'adguard_generic_modifier': re.compile(r'^[^$]*\$[a-zA-Z_,-]+(?:=[^,$\s]+)?$'),
            
            # AdGuard正则表达式规则[citation:8]
            'adguard_regex_rule': re.compile(r'^/(?:[^/\\]|\\.)+/[ims]*$'),
            
            # AdGuard Home特定规则[citation:7]
            'adguard_hosts_rule': re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            
            # 注释和空行
            'comment': re.compile(r'^!'),
            'empty': re.compile(r'^\s*$'),
            
            # 通用AdGuard规则模式
            'adguard_basic_exception': re.compile(r'^@@'),
            'adguard_basic_hide': re.compile(r'^##'),
            'adguard_basic_domain': re.compile(r'^\|\|'),
            'adguard_basic_url': re.compile(r'^\|http'),
            'adguard_contains_modifier': re.compile(r'\$[a-zA-Z]'),
        }
        return patterns

    def _init_rule_support(self) -> Dict[str, List[str]]:
        """初始化AdGuard全平台规则支持映射[citation:1][citation:5][citation:7]"""
        return {
            # 基础AdGuard规则 - 全平台支持[citation:5]
            'adguard_domain_rule': ['adg', 'abp', 'ubo'],
            'adguard_exception_rule': ['adg', 'abp', 'ubo'],
            'adguard_element_hiding': ['adg', 'abp', 'ubo'],
            'adguard_element_hiding_exception': ['adg', 'abp', 'ubo'],
            'adguard_url_rule': ['adg', 'abp', 'ubo'],
            
            # AdGuard修饰符规则 - AdGuard和uBlock Origin支持[citation:1][citation:2]
            'adguard_csp_rule': ['adg', 'ubo'],
            'adguard_scriptlet_rule': ['adg', 'ubo'],
            'adguard_removeparam_rule': ['adg', 'ubo'],
            'adguard_extension_rule': ['adg', 'ubo'],
            'adguard_domain_modifier': ['adg', 'ubo'],
            'adguard_important_rule': ['adg', 'abp', 'ubo'],
            'adguard_generic_modifier': ['adg', 'ubo'],
            
            # 正则表达式规则
            'adguard_regex_rule': ['adg', 'ubo'],
            
            # AdGuard Home特定规则[citation:7]
            'adguard_hosts_rule': ['adg'],
            
            # 注释和空行
            'comment': [],
            'empty': []
        }

    def classify_rule(self, rule: str) -> Tuple[str, List[str]]:
        """分类单条规则 - AdGuard全平台覆盖"""
        rule = rule.strip()

        if not rule:
            return 'empty', []

        # 使用预编译正则表达式快速分类[citation:6][citation:9]
        for rule_type, pattern in self.patterns.items():
            if pattern.match(rule):
                platforms = self._get_platform_support(rule_type)
                return rule_type, platforms

        # 如果正则匹配失败，使用adblockparser作为后备
        if HAS_ADBLOCK_PARSER:
            rule_type = self._classify_with_adblockparser(rule)
            if rule_type != 'unknown':
                platforms = self._get_platform_support(rule_type)
                return rule_type, platforms

        return 'unknown', ['adg']  # 未知规则默认支持AdGuard

    def _classify_with_adblockparser(self, rule: str) -> str:
        """使用adblockparser进行后备分类"""
        try:
            adblock_rule = AdblockRule(rule)

            if adblock_rule.is_comment:
                return 'comment'

            # 基于adblockparser的结果映射到AdGuard规则类型
            if adblock_rule.is_exception:
                if adblock_rule.is_elemhide:
                    return 'adguard_element_hiding_exception'
                else:
                    return 'adguard_exception_rule'
            elif adblock_rule.is_elemhide:
                return 'adguard_element_hiding'
            else:
                # 进一步分类为AdGuard规则类型
                if rule.startswith('||') and rule.endswith('^'):
                    return 'adguard_domain_rule'
                elif rule.startswith('|') and rule.endswith('|'):
                    return 'adguard_url_rule'
                elif '$' in rule:
                    if 'csp=' in rule:
                        return 'adguard_csp_rule'
                    elif 'script' in rule:
                        return 'adguard_scriptlet_rule'
                    elif 'removeparam=' in rule:
                        return 'adguard_removeparam_rule'
                    else:
                        return 'adguard_generic_modifier'
                else:
                    return 'adguard_domain_rule'

        except Exception:
            return 'unknown'

    def _get_platform_support(self, rule_type: str) -> List[str]:
        """获取规则平台支持"""
        return self.rule_support.get(rule_type, ['adg'])

    def is_allow_rule(self, rule_type: str, rule_content: str) -> bool:
        """判断是否为允许规则（白名单）[citation:5]"""
        allow_indicators = ['@@', '#@#', '@@##']
        allow_types = [
            'adguard_exception_rule',
            'adguard_element_hiding_exception'
        ]

        return (rule_type in allow_types or 
                any(rule_content.startswith(indicator) for indicator in allow_indicators))

class RuleStatistics:
    """规则统计器"""

    def __init__(self):
        self.counts = {
            'total_lines': 0, 'comments': 0, 'empty_lines': 0,
            'valid_rules': 0, 'duplicates': 0, 'errors': 0,
            'unknown_rules': 0
        }
        self.platform_counts = {'adg': 0, 'abp': 0, 'ubo': 0}
        self.rule_types = {}

    def count(self, category: str):
        """计数"""
        if category in self.counts:
            self.counts[category] += 1

    def add_rule(self, rule_type: str, platforms: List[str]):
        """添加规则统计"""
        self.count('valid_rules')

        # 规则类型统计
        if rule_type not in self.rule_types:
            self.rule_types[rule_type] = 0
        self.rule_types[rule_type] += 1

        # 平台统计
        for platform in platforms:
            if platform in self.platform_counts:
                self.platform_counts[platform] += 1

    def print_summary(self):
        """打印统计摘要"""
        print("\n" + "="*50)
        print("规则处理统计")
        print("="*50)

        # 基础统计
        print(f"\n📊 处理统计:")
        print(f"  总行数: {self.counts['total_lines']}")
        print(f"  有效规则: {self.counts['valid_rules']}")
        print(f"  重复规则: {self.counts['duplicates']}")
        print(f"  未知规则: {self.counts['unknown_rules']}")
        print(f"  注释/空行: {self.counts['comments'] + self.counts['empty_lines']}")

        # 平台统计
        print(f"\n🏷️ 平台分布:")
        platform_names = {'adg': 'AdGuard', 'abp': 'AdBlock Plus', 'ubo': 'uBlock Origin'}
        for platform, count in self.platform_counts.items():
            percentage = (count / self.counts['valid_rules']) * 100 if self.counts['valid_rules'] > 0 else 0
            print(f"  {platform_names[platform]}: {count} 条 ({percentage:.1f}%)")

        # 主要规则类型
        if self.rule_types:
            print(f"\n📋 主要规则类型:")
            sorted_types = sorted(self.rule_types.items(), key=lambda x: x[1], reverse=True)[:8]
            for rule_type, count in sorted_types:
                percentage = (count / self.counts['valid_rules']) * 100 if self.counts['valid_rules'] > 0 else 0
                display_name = rule_type.replace('adguard_', '').replace('_', ' ').title()
                print(f"  {display_name}: {count} 条 ({percentage:.1f}%)")

class RuleProcessor:
    """高效规则处理器"""

    def __init__(self):
        self.logger = Logger()
        self.classifier = AdGuardRuleClassifier(self.logger)
        self.statistics = RuleStatistics()
        self.seen_rules = set()

        # 平台规则存储 - 保持原有输出文件名
        self.platform_rules = {
            'adg': {'block': set(), 'allow': set()},
            'abp': {'block': set(), 'allow': set()},
            'ubo': {'block': set(), 'allow': set()}
        }

    def _is_duplicate(self, rule: str) -> bool:
        """高效去重检查"""
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
                if line_num % 10000 == 0 or line_num == total_lines:
                    self.logger.progress(line_num, total_lines, "处理中")

            except Exception as e:
                self.statistics.count('errors')
                if line_num <= 50:
                    self.logger.warning(f"第 {line_num} 行处理错误: {e}")

        self.logger.info("文件处理完成")

    def _process_single_rule(self, rule: str):
        """处理单条规则"""
        rule_type, platforms = self.classifier.classify_rule(rule)

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
        self.statistics.add_rule(rule_type, platforms)

        for platform in platforms:
            if platform in self.platform_rules:
                rule_set = 'allow' if is_allow else 'block'
                self.platform_rules[platform][rule_set].add(rule)

    def save_results(self, output_dir: str):
        """保存结果到文件 - 无文件头版本"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"保存结果到: {output_path}")

        # 保持原有输出文件名
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
                    self._write_rules_to_file(filepath, sorted(rules))
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

    def _write_rules_to_file(self, filepath: Path, rules: List[str]):
        """写入规则到文件 - 无文件头"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # 直接写入规则，无任何文件头
                for rule in rules:
                    f.write(f"{rule}\n")

            self.logger.info(f"已写入: {filepath.name} ({len(rules)} 条规则)")

        except Exception as e:
            self.logger.error(f"无法写入文件 {filepath}: {e}")

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
    base_dir = Path(__file__).parent
    input_file = base_dir / "rule.txt"
    output_dir = base_dir

    # 检查文件存在
    if not input_file.exists():
        print(f"❌ 错误: 输入文件不存在: {input_file}")
        print(f"请将AdGuard规则文件放置为: {input_file}")
        return

    print("🚀 AdGuard规则转换器 - 全平台语法版")
    print(f"📂 输入文件: {input_file}")
    print(f"📁 输出目录: {output_dir}")
    print("-" * 50)

    # 初始化处理器
    processor = RuleProcessor()

    # 处理文件
    processor.process_file(str(input_file))

    # 保存结果
    processor.save_results(str(output_dir))

    # 打印统计
    processor.print_statistics()

    print("\n🎉 处理完成！")

if __name__ == "__main__":
    main()