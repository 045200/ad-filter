import os
import re
import glob
import hashlib
import json
from typing import Set, List, Dict, Tuple, Optional

# ------------------------------ 依赖加载 ------------------------------
try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    print("警告: pybloom_live 未安装，将使用哈希表进行去重")

try:
    import json5 as json
    JSON5_AVAILABLE = True
except ImportError:
    import json
    JSON5_AVAILABLE = False

# ------------------------------ 核心处理类 ------------------------------
class AdGuardPureConverter:
    def __init__(self, syntax_db_path: str, output_dir: str):
        # 加载语法数据库
        self.syntax_db = self._load_syntax_db(syntax_db_path)
        self.output_dir = output_dir

        # 编译所有语法模式
        self.compiled_patterns = self._compile_all_patterns()

        # 获取平台支持信息
        self.ag_supported_types = self.syntax_db['platform_support']['adguard_browser_extension']['supported_rule_types']
        self.ag_home_supported_types = self.syntax_db['platform_support']['adguard_home']['supported_rule_types']
        self.pihole_supported_types = self.syntax_db['platform_support']['pihole']['supported_rule_types']

        # 流程变量 - 分别存储原始黑白名单规则
        self.raw_block_rules = []  # 只存储黑名单规则
        self.raw_allow_rules = []  # 只存储白名单规则

        # 分别维护转换后的黑白名单规则
        self.converted_block_rules = []
        self.converted_allow_rules = []

        # 分别维护最终的黑白名单规则集合
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

    # ------------------------------ 步骤1：分别加载黑白名单规则 ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载规则】从 {input_dir} 分别读取黑白名单文件...")
        if not os.path.exists(input_dir):
            os.makedirs(input_dir, exist_ok=True)
            print(f"警告：输入目录不存在，已自动创建：{input_dir}")
            return

        # 分别处理黑名单文件和白名单文件
        self._load_block_files(input_dir)
        self._load_allow_files(input_dir)

        print(f"【步骤1完成】加载 {len(self.raw_block_rules)} 条黑名单规则，{len(self.raw_allow_rules)} 条白名单规则")

    def _load_block_files(self, input_dir: str) -> None:
        """专门加载黑名单文件"""
        block_patterns = [
            os.path.join(input_dir, "adblock*.txt"),
            os.path.join(input_dir, "block*.txt"),
            os.path.join(input_dir, "blacklist*.txt")
        ]
        
        for pattern in block_patterns:
            block_files = glob.glob(pattern)
            for file_path in block_files:
                file_name = os.path.basename(file_path)
                print(f"  处理黑名单文件：{file_name}")
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        raw_rule = line.strip()
                        if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                            continue
                        # 明确标记为黑名单规则
                        self.raw_block_rules.append((raw_rule, file_name, line_num, "block"))

    def _load_allow_files(self, input_dir: str) -> None:
        """专门加载白名单文件"""
        allow_patterns = [
            os.path.join(input_dir, "allow*.txt"),
            os.path.join(input_dir, "white*.txt"),
            os.path.join(input_dir, "whitelist*.txt")
        ]
        
        for pattern in allow_patterns:
            allow_files = glob.glob(pattern)
            for file_path in allow_files:
                file_name = os.path.basename(file_path)
                print(f"  处理白名单文件：{file_name}")
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        raw_rule = line.strip()
                        if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                            continue
                        # 明确标记为白名单规则
                        self.raw_allow_rules.append((raw_rule, file_name, line_num, "allow"))

    # ------------------------------ 步骤2：基于语法数据库的规则识别与转换 ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：语法识别与转换】分别处理黑白名单规则...")

        # 分别统计黑白名单的转换情况
        block_stats = self._convert_rules_list(self.raw_block_rules, self.converted_block_rules, "黑名单")
        allow_stats = self._convert_rules_list(self.raw_allow_rules, self.converted_allow_rules, "白名单")

        print(f"【步骤2完成】转换统计：")
        print(f"  黑名单: {block_stats['total']}条 → 成功{block_stats['success']}条, 失败{block_stats['failed']}条")
        print(f"  白名单: {allow_stats['total']}条 → 成功{allow_stats['success']}条, 失败{allow_stats['failed']}条")

    def _convert_rules_list(self, raw_rules: List, converted_rules: List, list_type: str) -> Dict:
        """转换指定的规则列表"""
        stats = {
            'total': len(raw_rules),
            'success': 0,
            'failed': 0,
            'adguard_kept': 0,
            'adguard_home_kept': 0,
            'hosts_converted': 0,
            'pihole_converted': 0,
            'unknown_converted': 0
        }

        for raw_rule, file_name, line_num, category in raw_rules:
            try:
                rule_type = self._identify_rule_type_with_db(raw_rule)
                converted_rule = self._convert_rule_by_type(raw_rule, rule_type)

                if converted_rule:
                    # 保持原始的分类标记
                    converted_rules.append((converted_rule, file_name, line_num, category))
                    stats['success'] += 1

                    # 统计转换情况
                    if rule_type in self.ag_supported_types:
                        stats['adguard_kept'] += 1
                    elif rule_type in self.ag_home_supported_types:
                        stats['adguard_home_kept'] += 1
                    elif rule_type == "hosts_rule":
                        stats['hosts_converted'] += 1
                    elif rule_type in self.pihole_supported_types:
                        stats['pihole_converted'] += 1
                    else:
                        stats['unknown_converted'] += 1
                else:
                    stats['failed'] += 1

            except Exception as e:
                stats['failed'] += 1
                print(f"  {list_type}转换失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        return stats

    def _identify_rule_type_with_db(self, rule: str) -> str:
        """使用语法数据库识别规则类型"""
        # 优先使用数据库中的模式匹配
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                # 检查是否为注释模式
                rule_type = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                if rule_type in ['metadata', 'meta', 'comment']:
                    continue  # 跳过注释
                return pattern_name

        # 后备识别逻辑
        return self._fallback_rule_identification(rule)

    def _fallback_rule_identification(self, rule: str) -> str:
        """后备规则识别逻辑"""
        # 使用数据库中的常见模式进行后备识别
        common_patterns = self.syntax_db['common_patterns']

        # Hosts规则识别
        if re.match(self.syntax_db['syntax_patterns']['hosts_rule'], rule):
            return "hosts_rule"

        # Pi-hole域名规则
        if re.match(self.syntax_db['syntax_patterns']['pihole_domain'], rule):
            return "pihole_domain"

        # 元素隐藏规则
        if rule.startswith('##') and any(char in rule for char in ['.', '#', '[', '>', '{']):
            return "adblock_basic_element_hiding"

        # 简单域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', rule):
            return "pihole_domain"

        return "unknown"

    def _convert_rule_by_type(self, rule: str, rule_type: str) -> Optional[str]:
        """根据规则类型转换规则"""
        # AdGuard格式直接保持
        if rule_type in self.ag_supported_types:
            return rule

        # AdGuard Home格式直接保持
        if rule_type in self.ag_home_supported_types:
            return rule

        # 使用数据库中的转换逻辑
        conversion_methods = {
            "hosts_rule": self._convert_hosts_rule,
            "pihole_domain": self._convert_pihole_domain_rule,
            "pihole_regex": self._convert_pihole_regex_rule,
            "adblock_basic_element_hiding": self._convert_element_hiding_rule,
            "unknown": self._convert_unknown_rule
        }

        converter = conversion_methods.get(rule_type, self._convert_unknown_rule)
        return converter(rule)

    def _convert_hosts_rule(self, rule: str) -> Optional[str]:
        """转换hosts规则 - 使用语法数据库模式"""
        match = re.match(self.syntax_db['syntax_patterns']['hosts_rule'], rule)
        if match:
            # 提取域名部分
            domain_part = rule.split()[1] if len(rule.split()) > 1 else rule.split('#')[0].strip().split()[-1]
            domain = domain_part.strip()
            if domain and not domain.startswith('#'):
                # 转换为AdGuard域名阻塞规则
                return f"||{domain}^"
        return None

    def _convert_pihole_domain_rule(self, rule: str) -> Optional[str]:
        """转换Pi-hole域名规则"""
        # Pi-hole白名单格式
        if rule.startswith('@@'):
            return rule

        # 简单域名规则转换为AdGuard格式
        if re.match(self.syntax_db['syntax_patterns']['pihole_domain'], rule):
            return f"||{rule}^"

        # 包含通配符的域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            return f"||{rule}^"

        return None

    def _convert_pihole_regex_rule(self, rule: str) -> Optional[str]:
        """转换Pi-hole正则规则"""
        # Pi-hole正则规则直接保持（AdGuard支持正则）
        if rule.startswith('/') and rule.endswith('/'):
            return rule
        return None

    def _convert_element_hiding_rule(self, rule: str) -> Optional[str]:
        """转换元素隐藏规则"""
        # 确保元素隐藏规则格式正确
        if rule.startswith('#') and not rule.startswith('##'):
            return f"##{rule.lstrip('#')}"
        return rule

    def _convert_unknown_rule(self, rule: str) -> Optional[str]:
        """转换未知格式规则"""
        # 尝试使用数据库中的常见模式进行转换
        common_patterns = self.syntax_db['common_patterns']

        # 尝试识别为域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', rule):
            return f"||{rule}^"

        # 包含通配符的简单规则
        if re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            return f"||{rule}^"

        # 尝试识别为URL模式
        if re.match(r'^https?://[^\s]+$', rule):
            return f"||{re.sub(r'^https?://', '', rule).split('/')[0]}^"

        return None

    # ------------------------------ 步骤3：分别对黑白名单独立去重 ------------------------------
    def step3_dedup(self) -> None:
        print(f"\n【步骤3：去重规则】分别对黑白名单独立去重...")

        # 分别处理黑名单去重
        block_duplicate_count = self._dedup_rule_list(self.converted_block_rules, "block")
        
        # 分别处理白名单去重  
        allow_duplicate_count = self._dedup_rule_list(self.converted_allow_rules, "allow")

        print(f"  黑名单：去重前 {len(self.converted_block_rules)} 条 → 去重后 {len(self.final_block_rules)} 条，重复 {block_duplicate_count} 条")
        print(f"  白名单：去重前 {len(self.converted_allow_rules)} 条 → 去重后 {len(self.final_allow_rules)} 条，重复 {allow_duplicate_count} 条")

    def _dedup_rule_list(self, rule_list: List, category: str) -> int:
        """对指定类别的规则列表进行去重"""
        duplicate_count = 0
        target_set = self.final_block_rules if category == "block" else self.final_allow_rules
        target_bloom = self.dedup_bloom_block if category == "block" else self.dedup_bloom_allow

        for rule, file_name, line_num, rule_category in rule_list:
            try:
                rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()

                # 在各自的集合中去重
                if (target_bloom and rule_hash in target_bloom) or (rule in target_set):
                    duplicate_count += 1
                    continue
                    
                target_set.add(rule)
                if target_bloom:
                    target_bloom.add(rule_hash)

            except Exception as e:
                print(f"  {category}去重失败（{file_name}:{line_num}）：{rule} → {str(e)}")

        return duplicate_count

    # ------------------------------ 步骤4：保存结果 ------------------------------
    def step4_output(self) -> None:
        print(f"\n【步骤4：保存结果】输出纯净规则到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        # 保存黑名单 - 纯净规则，无文件头元信息
        if self.final_block_rules:
            block_path = os.path.join(self.output_dir, "adblock_adg.txt")
            sorted_block = sorted(self.final_block_rules, key=self._rule_sort_key)
            with open(block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_block))
            print(f"  黑名单文件：{block_path}（{len(sorted_block)} 条纯净规则）")
        else:
            print("  警告：无黑名单规则，跳过生成黑名单文件")

        # 保存白名单 - 纯净规则，无文件头元信息
        if self.final_allow_rules:
            allow_path = os.path.join(self.output_dir, "allow_adg.txt")
            sorted_allow = sorted(self.final_allow_rules)
            with open(allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_allow))
            print(f"  白名单文件：{allow_path}（{len(sorted_allow)} 条纯净规则）")
        else:
            print("  警告：无白名单规则，跳过生成白名单文件")

        print(f"【步骤4完成】纯净规则文件已保存！")

    # ------------------------------ 核心逻辑函数 ------------------------------
    def _is_comment_line_enhanced(self, rule: str) -> bool:
        """双重注释检测逻辑：语法数据库 + 内置逻辑"""
        if not rule.strip():
            return True

        # 内置注释检测逻辑
        if self._is_comment_builtin(rule):
            return True

        # 语法数据库注释检测
        if self._is_comment_by_syntax_db(rule):
            return True

        return False

    def _is_comment_builtin(self, rule: str) -> bool:
        """内置注释检测逻辑"""
        # 空行
        if not rule.strip():
            return True

        # 标准注释前缀
        if rule.startswith(("!", "# ")):
            return True

        # 特殊注释格式
        if rule.startswith(("[", "//", "/*", "*", "*/")):
            return True

        # 过滤列表头部信息
        if any(header in rule for header in ["Title:", "Description:", "Version:", "Last updated:", "Homepage:", "Expires:"]):
            return True

        # 分割线
        if re.match(r'^[=*-]{3,}$', rule):
            return True

        return False

    def _is_comment_by_syntax_db(self, rule: str) -> bool:
        """使用语法数据库检测注释"""
        # 检查是否为数据库定义的注释模式
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                rule_type = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                # 如果是注释类型，返回True
                if rule_type in ['metadata', 'meta', 'comment']:
                    return True

        # 检查以#开头但不是有效规则的行
        if rule.startswith("#"):
            # 这些是以#开头的有效规则，不是注释
            valid_hash_rules = [
                rule.startswith("##"),    # 元素隐藏规则
                rule.startswith("#@#"),   # 元素隐藏例外
                rule.startswith("#?#"),   # 扩展CSS规则
                rule.startswith("#%#"),   # 脚本规则
                rule.startswith("#$#"),   # 样式规则
                rule.startswith("#@$#"),  # 样式例外
            ]

            # 如果是以#开头的有效规则，返回False（不是注释）
            if any(valid_hash_rules):
                return False

            # 其他以#开头但没有特定格式的行视为注释
            return True

        return False

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        """规则排序键 - 基于数据库中的规则类型"""
        rule_type = self._identify_rule_type_with_db(rule)
        rule_type_info = self.syntax_db['rule_types'].get(rule_type, 'blocking')

        # 白名单规则优先
        if rule.startswith("@@"):
            if "||" in rule:
                return (0, rule)  # 域名白名单
            elif "##" in rule:
                return (1, rule)  # 元素隐藏白名单
            else:
                return (2, rule)  # 其他白名单

        # 根据规则类型排序
        type_priority = {
            'exception': 3,
            'cosmetic_exception': 4,
            'dns_modification': 5,
            'scriptlet_injection': 6,
            'cosmetic': 7,
            'cosmetic_advanced': 8,
            'blocking': 9,
            'url_rewriting': 10,
            'resource_redirection': 11,
            'unknown': 12
        }

        priority = type_priority.get(rule_type_info, 12)
        return (priority, rule)

    # ------------------------------ 工具函数 ------------------------------
    def _load_syntax_db(self, path: str) -> Dict:
        """加载语法数据库"""
        search_paths = [
            path,
            os.path.join(os.path.dirname(__file__), os.path.basename(path)),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), os.path.basename(path))
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
                    break  # 行注释，跳过剩余部分
                elif not in_string and char == '/' and i + 1 < len(line) and line[i+1] == '*':
                    break  # 块注释开始，跳过该行
                else:
                    clean_line.append(char)
                i += 1

            if clean_line:
                lines.append(''.join(clean_line))

        return '\n'.join(lines)

    def _compile_all_patterns(self) -> Dict[str, re.Pattern]:
        """编译所有语法模式"""
        compiled = {}
        for pat_name, pat_str in self.syntax_db['syntax_patterns'].items():
            if isinstance(pat_str, str):
                try:
                    compiled[pat_name] = re.compile(pat_str, re.UNICODE)
                except re.error as e:
                    print(f"  警告：模式编译失败 {pat_name}: {e}")
                    continue  # 跳过无效正则
        return compiled

    # ------------------------------ 启动流程 ------------------------------
    def run_full_flow(self, input_dir: str) -> None:
        print("="*60)
        print("AdGuard纯净规则处理流程 - 独立黑白名单处理")
        print(f"语法数据库版本: {self.syntax_db['version']}")
        print("输入: 分别处理黑白名单文件")
        print("输出: 纯净AdGuard语法规则（黑白名单分离，无注释）")
        print("="*60)
        try:
            self.step1_input(input_dir)
            if not self.raw_block_rules and not self.raw_allow_rules:
                print("\n流程终止：未加载到有效规则")
                return
            
            self.step2_convert()
            self.step3_dedup()
            self.step4_output()

            print("\n" + "="*60)
            print("流程完成！")
            print(f"  输出纯净规则: {len(self.final_block_rules)} 条黑名单, {len(self.final_allow_rules)} 条白名单")
            print(f"  输出格式: 纯净语法规则（无空行和注释）")
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

    converter = AdGuardPureConverter(
        syntax_db_path=SYNTAX_DB_PATH,
        output_dir=OUTPUT_DIR
    )
    converter.run_full_flow(input_dir=INPUT_DIR)