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

        # 初始化规则解析器 - 使用空规则列表
        self.rule_parser = None
        self._init_adblock_parser()

        # 流程变量
        self.raw_rules = []
        self.converted_rules = []
        self.final_rules = set()

        # 布隆过滤器
        bloom_cfg = self.syntax_db['performance_optimization']['bloom_filter_config']
        if BLOOM_AVAILABLE:
            self.dedup_bloom = BloomFilter(
                capacity=bloom_cfg['initial_capacity'], 
                error_rate=bloom_cfg['error_rate']
            )
        else:
            self.dedup_bloom = None

    def _init_adblock_parser(self):
        """初始化adblockparser规则解析器"""
        if not ADBLOCK_PARSER_AVAILABLE:
            self.rule_parser = None
            return

        try:
            # 使用空规则列表初始化解析器用于规则验证[citation:4][citation:7]
            self.rule_parser = adblockparser.AdblockRules([], use_re2=True, max_mem=512*1024*1024)
        except Exception as e:
            print(f"警告: adblockparser初始化失败: {e}，将使用基础模式匹配")
            self.rule_parser = None

    # ------------------------------ 步骤1：加载规则 ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载规则】从 {input_dir} 读取rule.txt...")
        
        rule_file_path = os.path.join(input_dir, "rule.txt")
        if not os.path.exists(rule_file_path):
            print(f"错误：未找到rule.txt文件在路径 {rule_file_path}")
            return

        self._load_rules(rule_file_path)
        print(f"【步骤1完成】加载 {len(self.raw_rules)} 条规则")

    def _load_rules(self, file_path: str) -> None:
        """从rule.txt加载规则"""
        print(f"  处理规则文件：rule.txt")

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                raw_rule = line.strip()
                
                # 跳过注释和空行
                if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                    continue

                self.raw_rules.append((raw_rule, "rule.txt", line_num))

    # ------------------------------ 步骤2：智能规则识别与转换 ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：智能规则识别与转换】")
        print("  处理流程: adblockparser基础验证 → 语法数据库高级分类 → 规则转换")

        stats = {
            'total': len(self.raw_rules),
            'success': 0,
            'failed': 0,
            'adblock_basic': 0,
            'adguard_advanced': 0,
            'hosts_rules': 0,
            'unknown': 0
        }

        for raw_rule, file_name, line_num in self.raw_rules:
            try:
                # 第一步：使用adblockparser进行基础语法验证和分类[citation:4][citation:7]
                basic_type = self._classify_with_adblockparser(raw_rule)
                
                # 第二步：使用语法数据库进行高级AdGuard语法识别[citation:2][citation:6]
                advanced_type = self._classify_with_syntax_db(raw_rule)
                
                # 第三步：确定最终规则类型（优先使用高级分类）
                final_type = self._determine_final_rule_type(raw_rule, basic_type, advanced_type)
                
                # 统计规则类型
                if "adguard" in final_type.lower():
                    stats['adguard_advanced'] += 1
                elif "hosts" in final_type.lower():
                    stats['hosts_rules'] += 1
                elif "adblock_basic" in final_type.lower():
                    stats['adblock_basic'] += 1
                else:
                    stats['unknown'] += 1

                # 转换规则
                converted_rule = self._convert_rule_based_on_type(raw_rule, final_type)
                
                if converted_rule:
                    category = self._determine_rule_category(converted_rule, final_type)
                    self.converted_rules.append((converted_rule, final_type, category))
                    stats['success'] += 1
                else:
                    stats['failed'] += 1
                    print(f"  转换失败（{file_name}:{line_num}）：{raw_rule}")

            except Exception as e:
                stats['failed'] += 1
                print(f"  处理失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        print(f"【步骤2完成】转换统计：")
        print(f"  总计: {stats['total']}条 → 成功{stats['success']}条, 失败{stats['failed']}条")
        print(f"  规则类型分布:")
        print(f"    Adblock基础规则: {stats['adblock_basic']}条")
        print(f"    AdGuard高级规则: {stats['adguard_advanced']}条")
        print(f"    Hosts规则: {stats['hosts_rules']}条")
        print(f"    未知规则: {stats['unknown']}条")

    def _classify_with_adblockparser(self, rule: str) -> str:
        """使用adblockparser进行基础语法验证和分类[citation:4][citation:7]"""
        if not self.rule_parser:
            return "unknown"
            
        try:
            # 创建包含单个规则的临时规则集进行验证
            test_rules = adblockparser.AdblockRules([rule], use_re2=False, max_mem=1024*1024)
            
            # 根据规则特征进行基础分类
            if rule.startswith('@@'):
                return "adblock_basic_exception_rule"
            elif rule.startswith('##'):
                return "adblock_basic_element_hiding"
            elif rule.startswith('||') and rule.endswith('^'):
                return "adblock_basic_domain_rule"
            elif rule.startswith('|') and rule.endswith('|'):
                return "adblock_basic_url_rule"
            elif '$' in rule and any(modifier in rule for modifier in 
                                   ['script', 'image', 'stylesheet', 'object', 'xmlhttprequest']):
                return "adblock_basic_precise_domain"
            else:
                return "adblock_basic_generic"
                
        except Exception as e:
            # adblockparser无法解析，可能是高级语法或无效规则
            return "adblock_invalid_or_advanced"

    def _classify_with_syntax_db(self, rule: str) -> str:
        """使用语法数据库进行高级AdGuard语法识别[citation:2]"""
        # 优先使用数据库中的高级模式匹配
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                rule_type_info = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                if rule_type_info in ['metadata', 'meta', 'comment']:
                    continue
                return pattern_name

        # 特殊处理AdGuard高级语法
        if self._is_adguard_advanced_rule(rule):
            return self._identify_adguard_specific_type(rule)
            
        return "unknown"

    def _is_adguard_advanced_rule(self, rule: str) -> bool:
        """检测AdGuard高级规则特征[citation:2][citation:6]"""
        adguard_advanced_indicators = [
            '#%#',  # 脚本注入
            '#@#',  # 元素隐藏白名单
            '#?#',  # 扩展CSS
            '#$#',  # 内容安全策略
            '#@$#', # 脚本白名单
            '$dnsrewrite',  # DNS重写
            '$removeparam',  # 参数移除
            '$redirect',     # 重定向
            '$csp',          # 内容安全策略
            '$removeheader', # 头部移除
            '$jsonprune',    # JSON修剪
        ]
        return any(indicator in rule for indicator in adguard_advanced_indicators)

    def _identify_adguard_specific_type(self, rule: str) -> str:
        """识别具体的AdGuard规则类型"""
        if '#%#' in rule:
            return "adguard_scriptlet"
        elif '$dnsrewrite' in rule:
            return "adguard_dns_rewrite"
        elif '$removeparam' in rule:
            return "adguard_removeparam"
        elif '$redirect' in rule:
            return "adguard_redirect"
        elif '$csp' in rule:
            return "adguard_csp"
        elif '#@#' in rule and not rule.startswith('##'):
            return "adguard_element_hiding_exception"
        elif '#@$#' in rule:
            return "adguard_script_exception"
        else:
            return "adguard_advanced_generic"

    def _determine_final_rule_type(self, rule: str, basic_type: str, advanced_type: str) -> str:
        """确定最终规则类型（优先高级分类）"""
        # 优先使用语法数据库的高级分类
        if advanced_type != "unknown":
            return advanced_type
            
        # 其次使用adblockparser的基础分类
        if basic_type != "unknown" and basic_type != "adblock_invalid_or_advanced":
            return basic_type
            
        # 最后使用后备识别
        return self._fallback_rule_identification(rule)

    def _fallback_rule_identification(self, rule: str) -> str:
        """后备规则识别逻辑"""
        if self._is_hosts_rule(rule):
            return "hosts_rule"
        elif self._is_adblock_basic_rule(rule):
            return "adblock_basic_generic"
        else:
            return "unknown"

    def _is_hosts_rule(self, rule: str) -> bool:
        """判断是否为hosts格式规则"""
        return re.match(r'^\s*(\d+\.\d+\.\d+\.\d+|\:\:[\d\w\:]+)\s+', rule) is not None

    def _is_adblock_basic_rule(self, rule: str) -> bool:
        """判断是否为基础Adblock规则"""
        basic_patterns = [
            r'^\|[\^]', r'^##', r'^@@', r'^\|', r'\|$', r'^\*', r'\*$', 
            r'^/', r'/$', r'^\$'
        ]
        return any(re.search(pattern, rule) for pattern in basic_patterns)

    def _convert_rule_based_on_type(self, rule: str, rule_type: str) -> Optional[str]:
        """根据规则类型进行转换"""
        try:
            # 对于已经是标准格式的规则，直接返回
            if self._is_standard_adblock_rule(rule):
                return rule
                
            # 根据规则类型进行特定转换
            if rule_type == "hosts_rule":
                return self._convert_hosts_rule(rule)
            elif "element_hiding" in rule_type:
                return self._normalize_element_hiding_rule(rule)
            elif "domain" in rule_type:
                return self._normalize_domain_rule(rule)
            elif "adguard" in rule_type:
                return self._handle_adguard_rule(rule, rule_type)
            else:
                # 默认情况下尝试标准化
                return self._normalize_generic_rule(rule)
                
        except Exception as e:
            print(f"  规则转换失败: {rule} → {str(e)}")
            return None

    def _is_standard_adblock_rule(self, rule: str) -> bool:
        """判断是否为标准Adblock规则"""
        standard_patterns = [
            r'^@@?[^#]',           # 黑白名单规则
            r'^##[^#]',            # 元素隐藏规则
            r'^#@#',               # 元素隐藏白名单
            r'^\|\|[^\|]+\^',      # 域名规则
            r'^\|[^\|]+\|',        # URL开始/结束规则
        ]
        return any(re.search(pattern, rule) for pattern in standard_patterns)

    def _convert_hosts_rule(self, rule: str) -> Optional[str]:
        """转换hosts规则为Adblock格式[citation:8]"""
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
        else:
            # 尝试修复格式
            if '##' in rule:
                return f"##{rule.split('##')[1]}"
            return rule

    def _normalize_domain_rule(self, rule: str) -> str:
        """标准化域名规则"""
        domain_match = re.search(r'([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*)', rule)
        if domain_match:
            domain = domain_match.group(1)
            return f"||{domain}^"
        return rule

    def _handle_adguard_rule(self, rule: str, rule_type: str) -> str:
        """处理AdGuard高级规则 - 保持原样"""
        # AdGuard高级规则通常已经是标准格式，直接返回
        return rule

    def _normalize_generic_rule(self, rule: str) -> str:
        """标准化通用规则"""
        # 尝试提取域名并转换为基本规则
        domain = self._extract_domain(rule)
        if domain:
            return f"||{domain}^"
        return rule

    def _extract_domain(self, rule: str) -> Optional[str]:
        """从规则中提取域名"""
        # 移除可能的协议头
        rule = re.sub(r'^https?://', '', rule)
        # 移除路径和参数
        rule = rule.split('/')[0].split('?')[0].split('#')[0]
        # 检查是否为有效域名格式
        domain_pattern = r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$'
        if re.match(domain_pattern, rule):
            return rule
        return None

    def _determine_rule_category(self, rule: str, rule_type: str) -> str:
        """确定规则分类（黑名单/白名单）"""
        if rule.startswith('@@'):
            return "allow"
        elif '#@#' in rule and not rule.startswith('##'):
            return "allow"
        elif "exception" in rule_type.lower():
            return "allow"
        else:
            return "block"

    # ------------------------------ 步骤3：去重 ------------------------------
    def step3_dedup(self) -> None:
        print(f"\n【步骤3：去重规则】使用布隆过滤器去重...")

        duplicate_count = 0

        for rule, rule_type, category in self.converted_rules:
            try:
                rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()

                rule_exists = rule in self.final_rules

                if (self.dedup_bloom and rule_hash in self.dedup_bloom) or rule_exists:
                    duplicate_count += 1
                    continue

                self.final_rules.add(rule)
                if self.dedup_bloom:
                    self.dedup_bloom.add(rule_hash)

            except Exception as e:
                print(f"  去重失败：{rule} → {str(e)}")

        print(f"  去重前 {len(self.converted_rules)} 条 → 去重后 {len(self.final_rules)} 条，重复 {duplicate_count} 条")

    # ------------------------------ 步骤4：多平台输出 ------------------------------
    def step4_output(self) -> None:
        print(f"\n【步骤4：保存结果】输出多平台规则到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        self._generate_platform_rules()
        print(f"【步骤4完成】多平台规则文件已保存！")

    def _generate_platform_rules(self) -> None:
        """生成各平台的规则文件"""
        self._generate_adblock_plus_rules()
        self._generate_ubo_rules()
        self._generate_adguard_rules()

    def _generate_adblock_plus_rules(self) -> None:
        """生成Adblock Plus格式规则"""
        adp_rules = []

        for rule in self.final_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.adp_supported_types:
                adp_rules.append(rule)

        if adp_rules:
            adp_path = os.path.join(self.output_dir, "adblock_abp.txt")
            sorted_adp = sorted(adp_rules, key=self._rule_sort_key)
            with open(adp_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_adp))
            print(f"  Adblock Plus：{adp_path}（{len(sorted_adp)} 条规则）")

    def _generate_ubo_rules(self) -> None:
        """生成uBlock Origin格式规则"""
        ubo_rules = []

        for rule in self.final_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ubo_supported_types:
                ubo_rules.append(rule)

        if ubo_rules:
            ubo_path = os.path.join(self.output_dir, "adblock_ubo.txt")
            sorted_ubo = sorted(ubo_rules, key=self._rule_sort_key)
            with open(ubo_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ubo))
            print(f"  uBlock Origin：{ubo_path}（{len(sorted_ubo)} 条规则）")

    def _generate_adguard_rules(self) -> None:
        """生成AdGuard格式规则"""
        ag_rules = []

        for rule in self.final_rules:
            rule_type = self._classify_with_syntax_db(rule)
            if rule_type in self.ag_supported_types:
                ag_rules.append(rule)

        if ag_rules:
            ag_path = os.path.join(self.output_dir, "adblock_adg.txt")
            sorted_ag = sorted(ag_rules, key=self._rule_sort_key)
            with open(ag_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ag))
            print(f"  AdGuard：{ag_path}（{len(sorted_ag)} 条规则）")

    # ------------------------------ 核心逻辑函数 ------------------------------
    def _is_comment_line_enhanced(self, rule: str) -> bool:
        """双重注释检测逻辑：语法数据库 + 内置逻辑"""
        if not rule.strip():
            return True

        if self._is_comment_builtin(rule):
            return True

        if self._is_comment_by_syntax_db(rule):
            return True

        return False

    def _is_comment_builtin(self, rule: str) -> bool:
        """内置注释检测逻辑"""
        if not rule.strip():
            return True

        if rule.startswith(("!", "# ")):
            return True

        if rule.startswith(("[", "//", "/*", "*", "*/")):
            return True

        if any(header in rule for header in ["Title:", "Description:", "Version:", "Last updated:", "Homepage:", "Expires:"]):
            return True

        if re.match(r'^[=*-]{3,}$', rule):
            return True

        return False

    def _is_comment_by_syntax_db(self, rule: str) -> bool:
        """使用语法数据库检测注释"""
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                rule_type = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                if rule_type in ['metadata', 'meta', 'comment']:
                    return True

        return False

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        """规则排序键"""
        if rule.startswith("@@"):
            return (0, rule)
        elif rule.startswith("##"):
            return (1, rule)
        elif rule.startswith("||"):
            return (2, rule)
        else:
            return (3, rule)

    # ------------------------------ 工具函数 ------------------------------
    def _load_syntax_db(self, path: str) -> Dict:
        """加载语法数据库"""
        search_paths = [
            path,
            os.path.join(os.path.dirname(__file__), os.path.basename(path)),
        ]
        for p in search_paths:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f:
                    if JSON5_AVAILABLE:
                        return json.load(f)
                    else:
                        return json.loads(self._clean_json_comments(f.read()))
        raise FileNotFoundError(f"语法数据库未找到，尝试路径：{search_paths}")

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
        print("AdBlock多平台规则处理流程 - 智能分类版")
        print(f"语法数据库版本: {self.syntax_db['version']}")
        print("分类逻辑: adblockparser基础验证 → 语法数据库高级分类 → 智能转换")
        print("输出: Adblock Plus, uBlock Origin, AdGuard 格式规则")
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
            print(f"  输出纯净规则: {len(self.final_rules)} 条")
            print(f"  输出格式: Adblock Plus, uBlock Origin, AdGuard")
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