import os
import re
import hashlib
import json
from typing import Set, List, Dict, Tuple, Optional

# ------------------------------ 依赖加载 ------------------------------
try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False

try:
    import adblockparser
    ADBLOCK_PARSER_AVAILABLE = True
except ImportError:
    ADBLOCK_PARSER_AVAILABLE = False
    print("错误: adblockparser 未安装，请运行: pip install adblockparser")
    exit(1)

try:
    import json5 as json
    JSON5_AVAILABLE = True
except ImportError:
    import json
    JSON5_AVAILABLE = False

# ------------------------------ 核心处理类 ------------------------------
class AdBlockMultiConverter:
    def __init__(self, syntax_db_path: str, output_dir: str):
        # 加载语法数据库
        self.syntax_db = self._load_syntax_db(syntax_db_path)
        self.output_dir = output_dir

        # 编译所有语法模式
        self.compiled_patterns = self._compile_all_patterns()

        # 获取平台支持信息
        self.adp_supported_types = set(self.syntax_db['platform_support']['adblock_plus']['supported_rule_types'])
        self.ubo_supported_types = set(self.syntax_db['platform_support']['ublock_origin']['supported_rule_types'])
        self.ag_supported_types = set(self.syntax_db['platform_support']['adguard_browser_extension']['supported_rule_types'])

        # 初始化规则解析器
        self.rule_parser = None
        self._init_adblock_parser()

        # 流程变量 - 分别存储黑白名单规则
        self.raw_rules = []
        self.converted_block_rules = []  # 黑名单规则
        self.converted_allow_rules = []  # 白名单规则
        self.final_block_rules = set()
        self.final_allow_rules = set()

        # 为黑白名单分别配置布隆过滤器
        bloom_cfg = self.syntax_db['performance_optimization']['bloom_filter_config']
        if BLOOM_AVAILABLE:
            self.dedup_bloom_block = BloomFilter(
                capacity=bloom_cfg['initial_capacity'], 
                error_rate=bloom_cfg['error_rate']
            )
            self.dedup_bloom_allow = BloomFilter(
                capacity=bloom_cfg['initial_capacity'], 
                error_rate=bloom_cfg['error_rate']
            )
        else:
            self.dedup_bloom_block = None
            self.dedup_bloom_allow = None

    def _init_adblock_parser(self):
        """初始化adblockparser规则解析器"""
        if not ADBLOCK_PARSER_AVAILABLE:
            self.rule_parser = None
            return

        try:
            self.rule_parser = adblockparser.AdblockRules([], use_re2=True, max_mem=512*1024*1024)
        except Exception as e:
            print(f"警告: adblockparser初始化失败: {e}")
            self.rule_parser = None

    # ------------------------------ 步骤1：加载规则 ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载规则】从 {input_dir} 读取rule.txt...")
        
        rule_file_path = os.path.join(input_dir, "rule.txt")
        if not os.path.exists(rule_file_path):
            print(f"错误：未找到rule.txt文件")
            return

        self._load_rules(rule_file_path)
        print(f"【步骤1完成】加载 {len(self.raw_rules)} 条规则")

    def _load_rules(self, file_path: str) -> None:
        """从rule.txt加载规则"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                raw_rule = line.strip()
                if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                    continue
                self.raw_rules.append((raw_rule, "rule.txt", line_num))

    # ------------------------------ 步骤2：智能规则识别与转换 ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：智能规则识别与转换】")
        print("  处理流程: 语法数据库高级分类 → 黑白名单分离 → 规则转换")

        stats = {
            'total': len(self.raw_rules),
            'block_success': 0,
            'allow_success': 0,
            'failed': 0,
            'rule_types': {}
        }

        for raw_rule, file_name, line_num in self.raw_rules:
            try:
                # 使用语法数据库进行高级分类
                rule_type = self._classify_with_syntax_db(raw_rule)
                
                # 确定规则分类（黑名单/白名单）
                category = self._determine_rule_category(raw_rule, rule_type)
                
                # 转换规则
                converted_rule = self._convert_rule_based_on_type(raw_rule, rule_type, category)
                
                if converted_rule:
                    # 根据分类添加到不同的列表
                    if category == "block":
                        self.converted_block_rules.append((converted_rule, rule_type))
                        stats['block_success'] += 1
                    else:
                        self.converted_allow_rules.append((converted_rule, rule_type))
                        stats['allow_success'] += 1
                    
                    # 统计规则类型
                    if rule_type not in stats['rule_types']:
                        stats['rule_types'][rule_type] = 0
                    stats['rule_types'][rule_type] += 1
                else:
                    stats['failed'] += 1
                    print(f"  转换失败（{file_name}:{line_num}）：{raw_rule}")

            except Exception as e:
                stats['failed'] += 1
                print(f"  处理失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        print(f"【步骤2完成】转换统计：")
        print(f"  总计: {stats['total']}条")
        print(f"  黑名单: {stats['block_success']}条")
        print(f"  白名单: {stats['allow_success']}条")
        print(f"  失败: {stats['failed']}条")
        print(f"  主要规则类型分布:")
        for rule_type, count in sorted(stats['rule_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"    {rule_type}: {count}条")

    def _classify_with_syntax_db(self, rule: str) -> str:
        """使用语法数据库进行高级分类"""
        # 优先匹配AdGuard高级语法
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                rule_type_info = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                if rule_type_info in ['metadata', 'meta', 'comment']:
                    continue
                return pattern_name

        # AdGuard特定语法检测
        if self._is_adguard_advanced_rule(rule):
            return self._identify_adguard_specific_type(rule)
            
        # 基础语法分类
        return self._classify_basic_rule(rule)

    def _is_adguard_advanced_rule(self, rule: str) -> bool:
        """检测AdGuard高级规则"""
        adguard_indicators = [
            '#%#', '$dnsrewrite', '$removeparam', '$redirect', 
            '$csp', '$removeheader', '$jsonprune', '$client=',
            '$dnstype=', '#@#', '#@$#', '#@%#', '#?#'
        ]
        return any(indicator in rule for indicator in adguard_indicators)

    def _identify_adguard_specific_type(self, rule: str) -> str:
        """识别AdGuard特定规则类型"""
        if '#%#' in rule:
            return "adguard_scriptlet"
        elif '$dnsrewrite' in rule:
            return "adguard_dns_rewrite"
        elif '$removeparam' in rule:
            return "adguard_removeparam"
        elif any(x in rule for x in ['$redirect', '$redirect-rule']):
            return "adguard_redirect"
        elif '$csp' in rule:
            return "adguard_csp"
        elif '$removeheader' in rule:
            return "adguard_removeheader"
        elif '$client=' in rule:
            return "adguard_home_client"
        elif '$dnstype=' in rule:
            return "adguard_home_dnstype"
        elif '#@#' in rule:
            return "adblock_basic_element_hiding_exception"
        else:
            return "adguard_advanced_generic"

    def _classify_basic_rule(self, rule: str) -> str:
        """基础规则分类"""
        if self._is_hosts_rule(rule):
            return "hosts_rule"
        elif rule.startswith('@@'):
            return "adblock_basic_exception_rule"
        elif rule.startswith('##'):
            return "adblock_basic_element_hiding"
        elif rule.startswith('||') and rule.endswith('^'):
            return "adblock_basic_domain_rule"
        elif rule.startswith('|') and rule.endswith('|'):
            return "adblock_basic_url_rule"
        elif '$' in rule:
            return "adblock_basic_precise_domain"
        else:
            return "unknown"

    def _is_hosts_rule(self, rule: str) -> bool:
        """判断是否为hosts规则"""
        return re.match(r'^\s*(\d+\.\d+\.\d+\.\d+|\:\:[\d\w\:]+)\s+', rule) is not None

    def _determine_rule_category(self, rule: str, rule_type: str) -> str:
        """确定规则分类（黑名单/白名单）"""
        if rule.startswith('@@'):
            return "allow"
        elif '#@#' in rule:
            return "allow"
        elif "exception" in rule_type.lower():
            return "allow"
        else:
            return "block"

    def _convert_rule_based_on_type(self, rule: str, rule_type: str, category: str) -> Optional[str]:
        """根据规则类型进行转换"""
        try:
            # AdGuard高级规则保持原样
            if "adguard" in rule_type:
                return rule
                
            # 已经是标准格式的规则直接返回
            if self._is_standard_adblock_rule(rule):
                return rule
                
            # 特定类型转换
            if rule_type == "hosts_rule":
                return self._convert_hosts_rule(rule)
            elif "element_hiding" in rule_type:
                return self._normalize_element_hiding_rule(rule)
            elif "domain" in rule_type:
                return self._normalize_domain_rule(rule, category)
            else:
                return rule
                
        except Exception as e:
            print(f"  规则转换失败: {rule} → {str(e)}")
            return None

    def _is_standard_adblock_rule(self, rule: str) -> bool:
        """判断是否为标准Adblock规则"""
        standard_patterns = [
            r'^@@?[^#]', r'^##[^#]', r'^#@#', 
            r'^\|\|[^\|]+\^', r'^\|[^\|]+\|'
        ]
        return any(re.search(pattern, rule) for pattern in standard_patterns)

    def _convert_hosts_rule(self, rule: str) -> Optional[str]:
        """转换hosts规则"""
        parts = rule.split()
        if len(parts) >= 2:
            domain = parts[1].strip()
            if domain and not domain.startswith('#'):
                return f"||{domain}^"
        return None

    def _normalize_element_hiding_rule(self, rule: str) -> str:
        """标准化元素隐藏规则"""
        if rule.startswith('##'):
            return rule
        elif '#@#' in rule:
            return rule
        elif '##' in rule:
            return f"##{rule.split('##')[1]}"
        return rule

    def _normalize_domain_rule(self, rule: str, category: str) -> str:
        """标准化域名规则"""
        domain_match = re.search(r'([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)', rule)
        if domain_match:
            domain = domain_match.group(1)
            if category == "allow":
                return f"@@||{domain}^"
            else:
                return f"||{domain}^"
        return rule

    # ------------------------------ 步骤3：分别去重 ------------------------------
    def step3_dedup(self) -> None:
        print(f"\n【步骤3：去重规则】分别对黑白名单去重...")

        # 黑名单去重
        block_duplicate_count = 0
        for rule, rule_type in self.converted_block_rules:
            try:
                rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()
                rule_exists = rule in self.final_block_rules

                if (self.dedup_bloom_block and rule_hash in self.dedup_bloom_block) or rule_exists:
                    block_duplicate_count += 1
                    continue

                self.final_block_rules.add(rule)
                if self.dedup_bloom_block:
                    self.dedup_bloom_block.add(rule_hash)

            except Exception as e:
                print(f"  黑名单去重失败：{rule} → {str(e)}")

        # 白名单去重
        allow_duplicate_count = 0
        for rule, rule_type in self.converted_allow_rules:
            try:
                rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()
                rule_exists = rule in self.final_allow_rules

                if (self.dedup_bloom_allow and rule_hash in self.dedup_bloom_allow) or rule_exists:
                    allow_duplicate_count += 1
                    continue

                self.final_allow_rules.add(rule)
                if self.dedup_bloom_allow:
                    self.dedup_bloom_allow.add(rule_hash)

            except Exception as e:
                print(f"  白名单去重失败：{rule} → {str(e)}")

        print(f"  黑名单：去重前 {len(self.converted_block_rules)} 条 → 去重后 {len(self.final_block_rules)} 条，重复 {block_duplicate_count} 条")
        print(f"  白名单：去重前 {len(self.converted_allow_rules)} 条 → 去重后 {len(self.final_allow_rules)} 条，重复 {allow_duplicate_count} 条")

    # ------------------------------ 步骤4：多平台输出 ------------------------------
    def step4_output(self) -> None:
        print(f"\n【步骤4：保存结果】输出多平台规则到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        # 调试信息
        self._debug_platform_support()
        
        self._generate_platform_rules()
        print(f"【步骤4完成】多平台规则文件已保存！")

    def _debug_platform_support(self):
        """调试平台支持信息"""
        print(f"  总规则数: 黑名单 {len(self.final_block_rules)} 条, 白名单 {len(self.final_allow_rules)} 条")
        
        # 统计各平台支持的规则数量
        platforms = ['adguard_browser_extension', 'ublock_origin', 'adblock_plus']
        platform_stats = {}
        
        for platform in platforms:
            platform_stats[platform] = {
                'block': 0,
                'allow': 0
            }
            
            # 黑名单规则
            for rule in self.final_block_rules:
                rule_type = self._classify_with_syntax_db(rule)
                if self._is_rule_supported(rule_type, platform):
                    platform_stats[platform]['block'] += 1
            
            # 白名单规则
            for rule in self.final_allow_rules:
                rule_type = self._classify_with_syntax_db(rule)
                if self._is_rule_supported(rule_type, platform):
                    platform_stats[platform]['allow'] += 1
        
        print(f"  平台支持统计:")
        print(f"    AdGuard: 黑名单 {platform_stats['adguard_browser_extension']['block']}条, 白名单 {platform_stats['adguard_browser_extension']['allow']}条")
        print(f"    uBlock Origin: 黑名单 {platform_stats['ublock_origin']['block']}条, 白名单 {platform_stats['ublock_origin']['allow']}条")
        print(f"    Adblock Plus: 黑名单 {platform_stats['adblock_plus']['block']}条, 白名单 {platform_stats['adblock_plus']['allow']}条")

    def _is_rule_supported(self, rule_type: str, platform: str) -> bool:
        """检查规则是否被平台支持"""
        if platform == 'adblock_plus':
            return rule_type in self.adp_supported_types
        elif platform == 'ublock_origin':
            return rule_type in self.ubo_supported_types
        elif platform == 'adguard_browser_extension':
            return rule_type in self.ag_supported_types
        return False

    def _generate_platform_rules(self):
        """生成各平台规则文件"""
        # AdGuard/AdGuard Home 输出
        self._generate_adguard_rules()
        
        # uBlock Origin 输出
        self._generate_ubo_rules()
        
        # Adblock Plus 输出
        self._generate_adblock_plus_rules()

    def _generate_adguard_rules(self):
        """生成AdGuard格式规则"""
        # AdGuard 黑名单
        ag_block_rules = []
        for rule in self.final_block_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ag_supported_types:
                ag_block_rules.append(rule)

        if ag_block_rules:
            ag_block_path = os.path.join(self.output_dir, "adblock_adg.txt")
            with open(ag_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(ag_block_rules)))
            print(f"  AdGuard黑名单：{ag_block_path}（{len(ag_block_rules)} 条规则）")

        # AdGuard 白名单
        ag_allow_rules = []
        for rule in self.final_allow_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ag_supported_types:
                ag_allow_rules.append(rule)

        if ag_allow_rules:
            ag_allow_path = os.path.join(self.output_dir, "allow_adg.txt")
            with open(ag_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(ag_allow_rules)))
            print(f"  AdGuard白名单：{ag_allow_path}（{len(ag_allow_rules)} 条规则）")

    def _generate_ubo_rules(self):
        """生成uBlock Origin格式规则"""
        # uBlock Origin 黑名单
        ubo_block_rules = []
        for rule in self.final_block_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ubo_supported_types:
                ubo_block_rules.append(rule)

        if ubo_block_rules:
            ubo_block_path = os.path.join(self.output_dir, "adblock_ubo.txt")
            with open(ubo_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(ubo_block_rules)))
            print(f"  uBlock Origin黑名单：{ubo_block_path}（{len(ubo_block_rules)} 条规则）")

        # uBlock Origin 白名单
        ubo_allow_rules = []
        for rule in self.final_allow_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ubo_supported_types:
                ubo_allow_rules.append(rule)

        if ubo_allow_rules:
            ubo_allow_path = os.path.join(self.output_dir, "allow_ubo.txt")
            with open(ubo_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(ubo_allow_rules)))
            print(f"  uBlock Origin白名单：{ubo_allow_path}（{len(ubo_allow_rules)} 条规则）")

    def _generate_adblock_plus_rules(self):
        """生成Adblock Plus格式规则"""
        # Adblock Plus 黑名单
        abp_block_rules = []
        for rule in self.final_block_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.adp_supported_types:
                abp_block_rules.append(rule)

        if abp_block_rules:
            abp_block_path = os.path.join(self.output_dir, "adblock_abp.txt")
            with open(abp_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(abp_block_rules)))
            print(f"  Adblock Plus黑名单：{abp_block_path}（{len(abp_block_rules)} 条规则）")

        # Adblock Plus 白名单
        abp_allow_rules = []
        for rule in self.final_allow_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.adp_supported_types:
                abp_allow_rules.append(rule)

        if abp_allow_rules:
            abp_allow_path = os.path.join(self.output_dir, "allow_abp.txt")
            with open(abp_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(abp_allow_rules)))
            print(f"  Adblock Plus白名单：{abp_allow_path}（{len(abp_allow_rules)} 条规则）")

    # ------------------------------ 工具函数 ------------------------------
    def _is_comment_line_enhanced(self, rule: str) -> bool:
        """注释检测"""
        if not rule.strip():
            return True
        if rule.startswith(("!", "# ", "[", "//")):
            return True
        if any(header in rule for header in ["Title:", "Description:", "Version:"]):
            return True
        return False

    def _load_syntax_db(self, path: str) -> Dict:
        """加载语法数据库"""
        search_paths = [path, os.path.join(os.path.dirname(__file__), os.path.basename(path))]
        for p in search_paths:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f:
                    if JSON5_AVAILABLE:
                        return json.load(f)
                    else:
                        return json.loads(self._clean_json_comments(f.read()))
        raise FileNotFoundError(f"语法数据库未找到")

    def _clean_json_comments(self, content: str) -> str:
        """清理JSON注释"""
        lines = []
        for line in content.split('\n'):
            clean_line = []
            in_string = False
            escaped = False

            i = 0
            while i < len(line):
                char = line[i]
                if escaped:
                    clean_line.append(char)
                    escaped = False
                elif char == '\\':
                    clean_line.append(char)
                    escaped = True
                elif char == '"':
                    in_string = not in_string
                    clean_line.append(char)
                elif not in_string and char == '/' and i + 1 < len(line) and line[i+1] == '/':
                    break
                elif not in_string and char == '/' and i + 1 < len(line) and line[i+1] == '*':
                    break
                else:
                    clean_line.append(char)
                i += 1

            if clean_line:
                lines.append(''.join(clean_line))

        return '\n'.join(lines)

    def _compile_all_patterns(self) -> Dict[str, re.Pattern]:
        """编译所有语法模式"""
        compiled = {}
        for pat_name, pat_str in self.syntax_db['advanced_syntax_patterns'].items():
            if isinstance(pat_str, str):
                try:
                    compiled[pat_name] = re.compile(pat_str, re.UNICODE)
                except re.error as e:
                    print(f"  警告：模式编译失败 {pat_name}: {e}")
                    continue
        return compiled

    # ------------------------------ 启动流程 ------------------------------
    def run_full_flow(self, input_dir: str) -> None:
        print("="*60)
        print("AdBlock多平台规则处理流程")
        print(f"语法数据库版本: {self.syntax_db['version']}")
        print("输入: AdGuard/AdGuard Home/hosts语法")
        print("输出: 6个文件（3个平台 × 黑白名单）")
        print("  - adblock_adg.txt, allow_adg.txt (AdGuard/AdGuard Home)")
        print("  - adblock_ubo.txt, allow_ubo.txt (uBlock Origin)")
        print("  - adblock_abp.txt, allow_abp.txt (Adblock Plus)")
        print("="*60)
        
        try:
            self.step1_input(input_dir)
            if not self.raw_rules:
                print("\n流程终止：未加载到有效规则")
                return

            self.step2_convert()
            self.step3_dedup()
            self.step4_output()

            print("\n" + "="*60)
            print("流程完成！")
            print(f"  输出规则: 黑名单 {len(self.final_block_rules)} 条, 白名单 {len(self.final_allow_rules)} 条")
            print("  输出文件:")
            print("    AdGuard/AdGuard Home: adblock_adg.txt, allow_adg.txt")
            print("    uBlock Origin: adblock_ubo.txt, allow_ubo.txt")
            print("    Adblock Plus: adblock_abp.txt, allow_abp.txt")
            print("="*60)
            
        except Exception as e:
            print(f"\n流程失败：{str(e)}")
            import traceback
            traceback.print_exc()


# ------------------------------ 主函数 ------------------------------
if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
    SYNTAX_DB_PATH = os.path.join(SCRIPT_DIR, "syntax_db.json")

    INPUT_DIR = os.path.join(PROJECT_ROOT, "data", "filter")
    OUTPUT_DIR = PROJECT_ROOT

    converter = AdBlockMultiConverter(
        syntax_db_path=SYNTAX_DB_PATH,
        output_dir=OUTPUT_DIR
    )
    converter.run_full_flow(input_dir=INPUT_DIR)