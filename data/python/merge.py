#!/usr/bin/env python3
"""
AdGuard三平台规则转换脚本 - 修复版
修复：分别处理黑白名单、去除汉字注释、保留白名单原始语法
输入: /data/filter/adblock*.txt 和 /data/filter/allow*.txt
输出: 根目录下的各平台黑白名单文件
"""

import re
import hashlib
import glob
from pathlib import Path
from typing import List, Dict, Tuple, Set

class Logger:
    """高效日志管理器"""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def info(self, message: str):
        if self.verbose:
            print(f"[INFO] {message}")

    def warning(self, message: str):
        print(f"[WARNING] {message}")

    def error(self, message: str):
        print(f"[ERROR] {message}")

    def progress(self, current: int, total: int, stage: str = ""):
        if current % 50000 == 0 or current == total:
            percentage = (current / total) * 100
            stage_info = f" [{stage}]" if stage else ""
            print(f"[PROGRESS] 已处理 {current}/{total} 行 ({percentage:.1f}%){stage_info}")

class AdGuardRuleClassifier:
    """
    AdGuard全平台规则分类器
    支持AdGuard、AdBlock Plus、uBlock Origin三平台
    """
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.patterns = self._compile_comprehensive_patterns()
        self.platform_support = self._init_platform_support()
        # 中文注释正则
        self.chinese_comment_pattern = re.compile(r'#.*[\u4e00-\u9fff]+.*$')

    def _compile_comprehensive_patterns(self) -> Dict[str, any]:
        """编译全平台正则表达式模式"""
        return {
            # === 基础规则类型 - 三平台通用 ===
            'domain_block_rule': re.compile(r'^\|\|([a-zA-Z0-9.*-]+[a-zA-Z0-9*])\^'),
            'domain_allow_rule': re.compile(r'^@@\|\|([a-zA-Z0-9.*-]+[a-zA-Z0-9*])\^'),
            'url_block_rule': re.compile(r'^\|([^|]+)\|$'),
            'url_allow_rule': re.compile(r'^@@\|([^|]+)\|$'),
            
            # === 元素隐藏规则 - 三平台通用 ===
            'element_hiding': re.compile(r'^##[^#]'),
            'element_hiding_exception': re.compile(r'^#@#|^@@##'),
            
            # === AdGuard扩展元素隐藏 - AdGuard/UBO支持 ===
            'extended_element_hiding': re.compile(r'^#\$?#[^{]'),
            'extended_element_hiding_exception': re.compile(r'^#@\$#|^@@#\$#'),
            
            # === HTML过滤规则 - AdGuard/UBO支持 ===
            'html_filtering': re.compile(r'^#\$?#.*\{.*\}'),
            'html_filtering_exception': re.compile(r'^#@\$#.*\{.*\}'),
            
            # === 脚本注入规则 - AdGuard/UBO支持 ===
            'scriptlet_injection': re.compile(r'#\$?#.*scriptlet'),
            'scriptlet_exception': re.compile(r'#@\$?#.*scriptlet'),
            
            # === DNS级别规则 - AdGuard专用 ===
            'dns_block_rule': re.compile(r'^\|\$[^|]'),
            'dns_allow_rule': re.compile(r'^@@\|\$[^|]'),
            'dns_regex_rule': re.compile(r'^/.*/\$[^|]'),
            
            # === 修饰符规则 - 平台差异 ===
            'csp_rule': re.compile(r'\$csp=[^,\s]+'),
            'scriptlet_modifier': re.compile(r'\$(?:script(?:let)?|rewrite)=[^,\s]+'),
            'removeparam_rule': re.compile(r'\$removeparam(?:=|,)[^,\s]+'),
            'important_rule': re.compile(r'\$important'),
            'badfilter_rule': re.compile(r'\$badfilter'),
            'denyallow_rule': re.compile(r'\$denyallow=[^,\s]+'),
            'redirect_rule': re.compile(r'\$redirect(?:-rule)?=[^,\s]+'),
            'redirect_exception': re.compile(r'\$~redirect(?:-rule)?=[^,\s]+'),
            
            # === 通用修饰符 ===
            'domain_modifier': re.compile(r'\$domain=[^,\s]+'),
            'third_party_modifier': re.compile(r'\$third-party'),
            'first_party_modifier': re.compile(r'\$~third-party'),
            'method_modifier': re.compile(r'\$method=[^,\s]+'),
            
            # === 内容类型修饰符 ===
            'content_type_modifiers': re.compile(
                r'\$(?:~?(?:script|stylesheet|image|xmlhttprequest|object|object-subrequest|'
                r'font|media|subdocument|ping|websocket|webrtc|other))'
            ),
            
            # === AdGuard特定功能 ===
            'adguard_specific': re.compile(
                r'\$(?:urlblock|document|content|jsinject|extension|'
                r'elemhide|generichide|genericblock|specifichide)'
            ),
            
            # === 注释和空行 ===
            'comment_line': re.compile(r'^[![]|^[ \t]*#[^#]|^//|^;;'),
            'empty_line': re.compile(r'^\s*$'),
            
            # === 正则表达式规则 ===
            'regex_rule': re.compile(r'^/.*/[$^]?'),
        }

    def _init_platform_support(self) -> Dict[str, List[str]]:
        """初始化各平台支持映射"""
        return {
            # 基础规则 - 三平台通用
            'domain_block_rule': ['adg', 'abp', 'ubo'],
            'domain_allow_rule': ['adg', 'abp', 'ubo'],
            'url_block_rule': ['adg', 'abp', 'ubo'],
            'url_allow_rule': ['adg', 'abp', 'ubo'],
            'element_hiding': ['adg', 'abp', 'ubo'],
            'element_hiding_exception': ['adg', 'abp', 'ubo'],
            
            # 扩展功能 - AdGuard和UBO支持
            'extended_element_hiding': ['adg', 'ubo'],
            'extended_element_hiding_exception': ['adg', 'ubo'],
            'html_filtering': ['adg', 'ubo'],
            'html_filtering_exception': ['adg', 'ubo'],
            'scriptlet_injection': ['adg', 'ubo'],
            'scriptlet_exception': ['adg', 'ubo'],
            
            # DNS规则 - 仅AdGuard支持
            'dns_block_rule': ['adg'],
            'dns_allow_rule': ['adg'],
            'dns_regex_rule': ['adg'],
            
            # 修饰符规则 - AdGuard和UBO支持
            'csp_rule': ['adg', 'ubo'],
            'scriptlet_modifier': ['adg', 'ubo'],
            'removeparam_rule': ['adg', 'ubo'],
            'important_rule': ['adg', 'abp', 'ubo'],
            'badfilter_rule': ['adg', 'ubo'],
            'denyallow_rule': ['adg', 'ubo'],
            'redirect_rule': ['adg', 'ubo'],
            'redirect_exception': ['adg', 'ubo'],
            
            # 通用修饰符
            'domain_modifier': ['adg', 'ubo'],
            'third_party_modifier': ['adg', 'abp', 'ubo'],
            'first_party_modifier': ['adg', 'abp', 'ubo'],
            'method_modifier': ['adg', 'ubo'],
            'content_type_modifiers': ['adg', 'ubo'],
            
            # AdGuard特定功能
            'adguard_specific': ['adg'],
            
            # 正则表达式规则
            'regex_rule': ['adg', 'ubo'],
            
            # 注释和空行
            'comment_line': [],
            'empty_line': []
        }

    def _remove_chinese_comments(self, rule: str) -> str:
        """去除规则中的中文注释"""
        # 保留原始规则用于检查
        original_rule = rule
        
        # 去除行内的中文注释
        rule = self.chinese_comment_pattern.sub('', rule).strip()
        
        # 如果去除注释后规则为空，返回空字符串
        if not rule:
            return ""
            
        # 特别处理：如果原始规则是@@|开头的白名单规则，确保保留完整语法
        if original_rule.startswith('@@|') and not rule.startswith('@@|'):
            # 如果误删了@@|前缀，恢复它
            if rule.startswith('|'):
                rule = '@@' + rule
        
        return rule

    def classify_rule(self, rule: str) -> Tuple[str, bool, List[str]]:
        """
        分类单条规则并返回规则类型、是否允许、支持的平台
        
        Returns:
            Tuple[规则类型, 是否允许规则, 支持的平台列表]
        """
        # 先去除中文注释
        original_rule = rule
        rule = self._remove_chinese_comments(rule)
        
        if not rule:
            return 'empty', False, []

        # 快速检查注释
        if self.patterns['comment_line'].match(rule):
            return 'comment', False, []
            
        if self.patterns['empty_line'].match(rule):
            return 'empty', False, []

        # === 允许规则检测 ===
        # 特别注意：保留原始的@@|语法
        allow_indicators = [
            rule.startswith('@@'),  # 基础异常规则（包括@@|）
            rule.startswith('#@#'),  # 元素隐藏异常
            rule.startswith('#@$#'),  # 扩展元素隐藏异常
            rule.startswith('@@##'),  # 元素隐藏异常变体
            '##@' in rule[:10],  # 元素隐藏异常
            self.patterns['domain_allow_rule'].match(rule),
            self.patterns['url_allow_rule'].match(rule),
            self.patterns['dns_allow_rule'].match(rule),
            self.patterns['element_hiding_exception'].match(rule),
            self.patterns['extended_element_hiding_exception'].match(rule),
            self.patterns['html_filtering_exception'].match(rule),
            self.patterns['scriptlet_exception'].match(rule),
            self.patterns['redirect_exception'].search(rule),
        ]
        
        is_allow_rule = any(allow_indicators)

        # === 规则类型检测 ===
        rule_types = [
            # 优先级从高到低
            ('dns_block_rule', self.patterns['dns_block_rule']),
            ('dns_allow_rule', self.patterns['dns_allow_rule']),
            ('dns_regex_rule', self.patterns['dns_regex_rule']),
            ('domain_allow_rule', self.patterns['domain_allow_rule']),
            ('domain_block_rule', self.patterns['domain_block_rule']),
            ('url_allow_rule', self.patterns['url_allow_rule']),
            ('url_block_rule', self.patterns['url_block_rule']),
            ('element_hiding_exception', self.patterns['element_hiding_exception']),
            ('element_hiding', self.patterns['element_hiding']),
            ('extended_element_hiding_exception', self.patterns['extended_element_hiding_exception']),
            ('extended_element_hiding', self.patterns['extended_element_hiding']),
            ('html_filtering_exception', self.patterns['html_filtering_exception']),
            ('html_filtering', self.patterns['html_filtering']),
            ('scriptlet_exception', self.patterns['scriptlet_exception']),
            ('scriptlet_injection', self.patterns['scriptlet_injection']),
            ('csp_rule', self.patterns['csp_rule']),
            ('removeparam_rule', self.patterns['removeparam_rule']),
            ('scriptlet_modifier', self.patterns['scriptlet_modifier']),
            ('important_rule', self.patterns['important_rule']),
            ('badfilter_rule', self.patterns['badfilter_rule']),
            ('denyallow_rule', self.patterns['denyallow_rule']),
            ('redirect_rule', self.patterns['redirect_rule']),
            ('domain_modifier', self.patterns['domain_modifier']),
            ('third_party_modifier', self.patterns['third_party_modifier']),
            ('content_type_modifiers', self.patterns['content_type_modifiers']),
            ('adguard_specific', self.patterns['adguard_specific']),
            ('regex_rule', self.patterns['regex_rule']),
        ]

        for rule_type, pattern in rule_types:
            if pattern.search(rule):
                platforms = self.platform_support.get(rule_type, ['adg'])
                return rule_type, is_allow_rule, platforms

        # 默认归类为通用域名规则，三平台都支持
        return 'domain_block_rule', is_allow_rule, ['adg', 'abp', 'ubo']

class RuleStatistics:
    """规则统计器"""
    
    def __init__(self):
        self.counts = {
            'total': 0, 'valid': 0, 'duplicates': 0, 
            'comments': 0, 'errors': 0, 'chinese_comments': 0
        }
        self.platform_counts = {'adg': 0, 'abp': 0, 'ubo': 0}
        self.rule_types = {}
        self.platform_rule_counts = {
            'adg': {'block': 0, 'allow': 0},
            'abp': {'block': 0, 'allow': 0},
            'ubo': {'block': 0, 'allow': 0}
        }

    def add_rule(self, rule_type: str, platforms: List[str], is_allow: bool):
        """添加规则统计"""
        self.counts['valid'] += 1
            
        # 规则类型统计
        self.rule_types[rule_type] = self.rule_types.get(rule_type, 0) + 1
        
        # 平台统计
        for platform in platforms:
            self.platform_counts[platform] = self.platform_counts.get(platform, 0) + 1
            rule_type_key = 'allow' if is_allow else 'block'
            self.platform_rule_counts[platform][rule_type_key] += 1

    def add_chinese_comment(self):
        """统计中文注释"""
        self.counts['chinese_comments'] += 1

    def print_summary(self):
        """打印统计摘要"""
        print("\n" + "="*60)
        print("📊 三平台规则处理统计摘要")
        print("="*60)
        
        print(f"总处理行数: {self.counts['total']}")
        print(f"有效规则数: {self.counts['valid']}")
        print(f"重复规则数: {self.counts['duplicates']}")
        print(f"注释/空行数: {self.counts['comments']}")
        print(f"中文注释数: {self.counts['chinese_comments']}")
        print(f"处理错误数: {self.counts['errors']}")

        # 平台分布
        print(f"\n🏷️ 平台规则分布:")
        platform_names = {'adg': 'AdGuard', 'abp': 'AdBlock Plus', 'ubo': 'uBlock Origin'}
        for platform in ['adg', 'abp', 'ubo']:
            total_platform_rules = self.platform_counts.get(platform, 0)
            block_count = self.platform_rule_counts[platform]['block']
            allow_count = self.platform_rule_counts[platform]['allow']
            percentage = (total_platform_rules / self.counts['valid']) * 100 if self.counts['valid'] > 0 else 0
            
            print(f"  {platform_names[platform]}: {total_platform_rules} 条 ({percentage:.1f}%)")
            print(f"    └─ 拦截规则: {block_count} 条, 允许规则: {allow_count} 条")

        if self.rule_types:
            print(f"\n📋 主要规则类型:")
            for rule_type, count in sorted(self.rule_types.items(), key=lambda x: x[1], reverse=True)[:8]:
                percentage = (count / self.counts['valid']) * 100 if self.counts['valid'] > 0 else 0
                display_name = rule_type.replace('_', ' ').title()
                print(f"  {display_name}: {count} 条 ({percentage:.1f}%)")

class RuleProcessor:
    """三平台规则处理器 - 修复版"""
    
    def __init__(self, verbose: bool = True):
        self.logger = Logger(verbose)
        self.classifier = AdGuardRuleClassifier(self.logger)
        self.statistics = RuleStatistics()
        self.seen_hashes = set()
        
        # 三平台规则存储
        self.platform_rules = {
            'adg': {'block': set(), 'allow': set()},
            'abp': {'block': set(), 'allow': set()},
            'ubo': {'block': set(), 'allow': set()}
        }

    def _rule_hash(self, rule: str) -> str:
        """生成规则哈希用于去重"""
        return hashlib.md5(rule.encode('utf-8')).hexdigest()

    def _is_duplicate(self, rule: str) -> bool:
        """去重检查"""
        rule_hash = self._rule_hash(rule)
        if rule_hash in self.seen_hashes:
            return True
        self.seen_hashes.add(rule_hash)
        return False

    def _clean_rule(self, rule: str) -> str:
        """清理规则：去除前后空白"""
        return rule.strip()

    def find_input_files(self) -> Tuple[List[str], List[str]]:
        """查找输入文件"""
        input_dir = Path("./data/filter")
        
        if not input_dir.exists():
            self.logger.error(f"输入目录不存在: {input_dir}")
            return [], []

        # 查找拦截规则文件
        adblock_files = glob.glob(str(input_dir / "adblock*.txt"))
        # 查找允许规则文件  
        allow_files = glob.glob(str(input_dir / "allow*.txt"))
        
        self.logger.info(f"找到拦截规则文件: {len(adblock_files)} 个")
        for file in adblock_files:
            self.logger.info(f"  - {file}")
            
        self.logger.info(f"找到允许规则文件: {len(allow_files)} 个")
        for file in allow_files:
            self.logger.info(f"  - {file}")
        
        return adblock_files, allow_files

    def process_files(self):
        """处理所有输入文件 - 优先处理白名单"""
        adblock_files, allow_files = self.find_input_files()
        
        if not adblock_files and not allow_files:
            self.logger.error("未找到输入文件 (adblock*.txt 或 allow*.txt)")
            return False

        self.logger.info("🔄 优先处理白名单文件...")
        
        # 第一阶段：优先处理白名单文件
        if allow_files:
            for file_index, file_path in enumerate(allow_files, 1):
                self._process_single_file(file_path, file_index, len(allow_files), "白名单")
        
        # 第二阶段：处理黑名单文件
        self.logger.info("🔄 处理黑名单文件...")
        if adblock_files:
            for file_index, file_path in enumerate(adblock_files, 1):
                self._process_single_file(file_path, file_index, len(adblock_files), "黑名单")

        self.logger.info(f"文件处理完成，总计处理 {self.statistics.counts['total']} 行")
        return True

    def _process_single_file(self, file_path: str, file_index: int, total_files: int, file_type: str):
        """处理单个文件"""
        self.logger.info(f"处理{file_type}文件 ({file_index}/{total_files}): {Path(file_path).name}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.error(f"无法读取文件 {file_path}: {e}")
            return 0

        total_lines = len(lines)
        self.statistics.counts['total'] += total_lines
        self.logger.info(f"读取到 {total_lines} 行规则")

        valid_count = 0
        chinese_comment_count = 0
        
        for line_num, line in enumerate(lines, 1):
            try:
                cleaned_line = self._clean_rule(line)
                
                # 检查是否为中文注释
                if self.classifier.chinese_comment_pattern.search(cleaned_line):
                    chinese_comment_count += 1
                    self.statistics.add_chinese_comment()
                    # 中文注释不处理，直接跳过
                    continue
                    
                if self._process_single_rule(cleaned_line):
                    valid_count += 1
                if line_num % 10000 == 0:
                    self.logger.progress(line_num, total_lines, f"处理 {Path(file_path).name}")
            except Exception as e:
                self.statistics.counts['errors'] += 1
                if self.statistics.counts['errors'] <= 5:  # 只显示前5个错误
                    self.logger.warning(f"文件 {Path(file_path).name} 第 {line_num} 行错误: {e}")

        self.logger.info(f"文件 {Path(file_path).name} 处理完成: {valid_count} 条有效规则, {chinese_comment_count} 条中文注释已过滤")
        return valid_count

    def _process_single_rule(self, rule: str) -> bool:
        """处理单条规则，返回是否成功添加"""
        if not rule:
            return False

        rule_type, is_allow, platforms = self.classifier.classify_rule(rule)

        # 过滤注释和空行
        if rule_type in ['empty', 'comment']:
            self.statistics.counts['comments'] += 1
            return False

        # 去重检查
        if self._is_duplicate(rule):
            self.statistics.counts['duplicates'] += 1
            return False

        # 添加到对应平台
        self.statistics.add_rule(rule_type, platforms, is_allow)
        
        rule_set = 'allow' if is_allow else 'block'
        for platform in platforms:
            if platform in self.platform_rules:
                self.platform_rules[platform][rule_set].add(rule)
        
        return True

    def save_results(self):
        """保存结果到文件 - 三平台纯净规则输出"""
        output_dir = Path("./")
        
        self.logger.info(f"保存三平台结果到根目录: {output_dir}")

        # 文件映射
        file_mapping = {
            'adg': {'block': 'adblock_adg.txt', 'allow': 'allow_adg.txt'},
            'abp': {'block': 'adblock_abp.txt', 'allow': 'allow_abp.txt'},
            'ubo': {'block': 'adblock_ubo.txt', 'allow': 'allow_ubo.txt'}
        }

        saved_files = []
        total_rules = 0

        for platform, files in file_mapping.items():
            for rule_type, filename in files.items():
                rules = self.platform_rules[platform][rule_type]
                if rules:
                    filepath = output_dir / filename
                    rule_count = len(rules)
                    self._write_rules_to_file(filepath, sorted(rules))
                    saved_files.append((filename, rule_count, rule_type, platform))
                    total_rules += rule_count

        # 输出保存结果
        print("\n" + "="*60)
        print("📁 三平台规则文件生成清单")
        print("="*60)
        
        platform_names = {'adg': 'AdGuard', 'abp': 'AdBlock Plus', 'ubo': 'uBlock Origin'}
        for filename, count, rule_type, platform in saved_files:
            rule_type_name = '允许规则' if rule_type == 'allow' else '拦截规则'
            rule_icon = '✅' if rule_type == 'allow' else '🚫'
            platform_name = platform_names.get(platform, platform)
            print(f"{rule_icon} {filename}: {count} 条{rule_type_name} ({platform_name})")

        print(f"\n📦 总计生成: {total_rules} 条纯净规则")
        
        # 平台特性说明
        print(f"\n🏷️ 各平台特性说明:")
        print("  • AdGuard: 支持全功能，包括DNS规则、HTML过滤、脚本注入等")
        print("  • AdBlock Plus: 支持基础规则和元素隐藏，语法兼容性最好")
        print("  • uBlock Origin: 支持大部分高级功能，除AdGuard特定语法外")

        # 修复特性说明
        print(f"\n🔧 修复特性:")
        print("  • 优先处理白名单规则，确保优先级")
        print("  • 自动过滤中文注释，保持规则纯净")
        print("  • 完整保留@@|等白名单原始语法")

    def _write_rules_to_file(self, filepath: Path, rules: List[str]):
        """写入规则到文件 - 纯净输出，无空行注释"""
        try:
            with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
                f.writelines(f"{rule}\n" for rule in rules)
            self.logger.info(f"已写入: {filepath.name} ({len(rules)} 条纯净规则)")
        except Exception as e:
            self.logger.error(f"无法写入文件 {filepath}: {e}")

    def print_statistics(self):
        """打印统计信息"""
        self.statistics.print_summary()

def main():
    """主函数"""
    print("🚀 AdGuard三平台规则转换器 - 修复增强版")
    print("📂 输入目录: /data/filter/")
    print("📁 输出目录: / (根目录)")
    print("🎯 目标平台: AdGuard, AdBlock Plus, uBlock Origin")
    print("🔧 修复特性: 优先白名单、过滤中文注释、保留原始语法")
    print("-" * 60)

    # 初始化处理器
    processor = RuleProcessor(verbose=True)

    # 处理文件
    success = processor.process_files()
    
    if not success:
        print("❌ 处理失败，请检查输入文件和目录权限")
        return

    # 保存结果
    processor.save_results()

    # 打印统计
    processor.print_statistics()

    print("\n🎉 三平台规则处理完成！")
    print("💡 提示: 各平台会自动解析其支持的语法规则")

if __name__ == "__main__":
    main()