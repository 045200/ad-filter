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
        
        # 平台支持配置
        self.ag_support = self.syntax_db['platform_support']['adguard_browser_extension']
        self.ag_home_support = self.syntax_db['platform_support']['adguard_home']
        self.pihole_support = self.syntax_db['platform_support']['pihole']
        
        # 编译正则模式
        self.compiled_patterns = self._compile_all_patterns()
        
        # 流程变量
        self.raw_rules = []
        self.converted_rules = []
        self.categorized_rules = {'block': [], 'allow': []}
        self.completed_rules = {'block': [], 'allow': []}
        self.final_rules = {'block': set(), 'allow': set()}

        # 去重配置
        bloom_cfg = self.syntax_db['performance_optimization']['bloom_filter_config']
        self.dedup_bloom = {
            cat: BloomFilter(
                capacity=bloom_cfg['initial_capacity'], 
                error_rate=bloom_cfg['error_rate']
            ) if BLOOM_AVAILABLE else None 
            for cat in ['block', 'allow']
        }

    # ------------------------------ 步骤1：加载规则 ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载规则】从 {input_dir} 读取规则文件...")
        if not os.path.exists(input_dir):
            os.makedirs(input_dir, exist_ok=True)
            print(f"警告：输入目录不存在，已自动创建：{input_dir}")
            return

        input_files = glob.glob(os.path.join(input_dir, "*.txt"), recursive=False)
        if not input_files:
            print(f"警告：输入目录 {input_dir} 下无TXT文件")
            return

        for file_path in input_files:
            file_name = os.path.basename(file_path)
            
            # 根据文件名确定规则类型
            file_type = self._determine_file_type(file_name)
            print(f"  处理文件：{file_name}（类型：{file_type}）")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    raw_rule = line.strip()
                    # 使用语法数据库的注释检测
                    if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                        continue
                    self.raw_rules.append((raw_rule, file_name, line_num, file_type))

        print(f"【步骤1完成】加载 {len(self.raw_rules)} 条非注释规则")

    def _determine_file_type(self, file_name: str) -> str:
        """根据文件名确定规则类型"""
        file_lower = file_name.lower()
        
        if any(keyword in file_lower for keyword in ['hosts', 'black', 'block']):
            return 'hosts_black'
        elif any(keyword in file_lower for keyword in ['adguard', 'adblock', 'filter']):
            return 'adguard_mixed'
        elif any(keyword in file_lower for keyword in ['pihole', 'white', 'allow', 'exception']):
            return 'pihole_white'
        else:
            return 'unknown'

    # ------------------------------ 步骤2：转换规则 ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：转换规则】处理 {len(self.raw_rules)} 条规则...")
        
        for raw_rule, file_name, line_num, file_type in self.raw_rules:
            try:
                # 根据文件类型进行转换
                if file_type == 'hosts_black':
                    converted_rule = self._convert_hosts_black_rule(raw_rule)
                elif file_type == 'pihole_white':
                    converted_rule = self._convert_pihole_white_rule(raw_rule)
                elif file_type == 'adguard_mixed':
                    converted_rule = self._convert_adguard_mixed_rule(raw_rule)
                else:
                    converted_rule = self._convert_unknown_rule(raw_rule)
                
                if converted_rule:
                    rule_type = self._identify_rule_type(converted_rule)
                    self.converted_rules.append((converted_rule, rule_type, file_name, line_num, file_type))
                    
            except Exception as e:
                print(f"  转换失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        print(f"【步骤2完成】成功转换 {len(self.converted_rules)} 条规则")

    def _convert_hosts_black_rule(self, rule: str) -> Optional[str]:
        """转换hosts黑名单规则"""
        # hosts格式: 127.0.0.1 domain.com
        if re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#]+)', rule):
            # 提取域名部分
            match = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#]+)', rule)
            if match:
                domain = match.group(2).strip()
                # 转换为AdGuard域名阻塞规则
                return f"||{domain}^"
        return None

    def _convert_pihole_white_rule(self, rule: str) -> Optional[str]:
        """转换Pi-hole白名单规则"""
        # Pi-hole白名单格式: 纯域名或@@开头的规则
        if rule.startswith('@@'):
            return rule  # 已经是AdGuard白名单格式
        elif re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            # 纯域名，转换为AdGuard白名单
            return f"@@||{rule}^"
        return None

    def _convert_adguard_mixed_rule(self, rule: str) -> Optional[str]:
        """处理AdGuard混合规则（可能包含黑白名单）"""
        # 如果是标准AdGuard格式，直接保留
        if any([
            rule.startswith('||') and rule.endswith('^'),
            rule.startswith('@@'),
            rule.startswith('##'),
            rule.startswith('#%#'),
            rule.startswith('#?#'),
            '$dnsrewrite' in rule,
            '$removeparam' in rule
        ]):
            return rule
        
        # 尝试识别并转换其他格式
        return self._auto_convert_rule(rule)

    def _convert_unknown_rule(self, rule: str) -> Optional[str]:
        """转换未知格式规则"""
        return self._auto_convert_rule(rule)

    def _auto_convert_rule(self, rule: str) -> Optional[str]:
        """自动转换规则格式"""
        # 尝试识别为域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            return f"||{rule}^"
        
        # 尝试识别为元素隐藏规则
        if rule.startswith('#') and any(char in rule for char in ['.', '#', '[', '>']):
            if not rule.startswith('##'):
                return f"##{rule.lstrip('#')}"
            return rule
        
        return rule

    # ------------------------------ 步骤3：归类规则 ------------------------------
    def step3_categorize(self) -> None:
        print(f"\n【步骤3：归类规则】区分黑白名单...")
        
        for converted_rule, rule_type, file_name, line_num, file_type in self.converted_rules:
            try:
                # 确定规则类别
                if file_type == 'pihole_white':
                    # Pi-hole白名单文件中的规则都归为白名单
                    self.categorized_rules["allow"].append((converted_rule, rule_type, file_name, line_num))
                elif converted_rule.startswith("@@"):
                    # AdGuard白名单格式
                    self.categorized_rules["allow"].append((converted_rule, rule_type, file_name, line_num))
                else:
                    # 其他情况归为黑名单
                    self.categorized_rules["block"].append((converted_rule, rule_type, file_name, line_num))
                    
            except Exception as e:
                print(f"  归类失败（{file_name}:{line_num}）：{converted_rule} → {str(e)}")
        
        print(f"【步骤3完成】黑名单：{len(self.categorized_rules['block'])} 条，白名单：{len(self.categorized_rules['allow'])} 条")

    # ------------------------------ 步骤4：补全规则 ------------------------------
    def step4_complete(self) -> None:
        print(f"\n【步骤4：补全规则】完善格式...")
        
        for category in ["block", "allow"]:
            for rule, rule_type, file_name, line_num in self.categorized_rules[category]:
                try:
                    completed_rule = self._complete_rule_format(rule, rule_type)
                    if completed_rule:
                        self.completed_rules[category].append((completed_rule, file_name, line_num))
                except Exception as e:
                    print(f"  补全失败（{file_name}:{line_num}）：{rule} → {str(e)}")
        
        print(f"【步骤4完成】补全后：黑名单 {len(self.completed_rules['block'])} 条，白名单 {len(self.completed_rules['allow'])} 条")

    def _complete_rule_format(self, rule: str, rule_type: str) -> Optional[str]:
        """补全规则格式"""
        # 域名规则补全
        if rule_type == "adblock_basic_domain_rule":
            if not rule.startswith("||"):
                return f"||{rule}^"
            elif not rule.endswith("^"):
                return f"{rule}^"
        
        # 脚本规则补全
        elif rule_type in ["adguard_scriptlet", "ubo_scriptlet"]:
            if not rule.startswith("#%#"):
                return f"#%# {rule}"
        
        # 扩展CSS补全
        elif rule_type in ["adguard_extended_css", "ubo_extended_css"]:
            if not rule.startswith("#?#"):
                return f"#?# {rule}"
        
        # 正则规则补全
        elif rule_type in ["adblock_basic_regex_rule", "regex_rule"]:
            if not (rule.startswith("/") and rule.endswith("/")):
                return f"/{rule}/"
        
        return rule

    # ------------------------------ 步骤5：去重规则 ------------------------------
    def step5_dedup(self) -> None:
        print(f"\n【步骤5：去重规则】移除重复...")
        
        for category in ["block", "allow"]:
            duplicate_count = 0
            for rule, file_name, line_num in self.completed_rules[category]:
                try:
                    rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()
                    if (self.dedup_bloom[category] and rule_hash in self.dedup_bloom[category]) or (rule in self.final_rules[category]):
                        duplicate_count += 1
                        continue
                    self.final_rules[category].add(rule)
                    if self.dedup_bloom[category]:
                        self.dedup_bloom[category].add(rule_hash)
                except Exception as e:
                    print(f"  去重失败（{file_name}:{line_num}）：{rule} → {str(e)}")
            
            print(f"  {category}：去重前 {len(self.completed_rules[category])} 条 → 去重后 {len(self.final_rules[category])} 条，重复 {duplicate_count} 条")

    # ------------------------------ 步骤6：保存结果 ------------------------------
    def step6_output(self) -> None:
        print(f"\n【步骤6：保存结果】输出纯净规则到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        # 保存黑名单 - 纯净规则，无文件头
        block_path = os.path.join(self.output_dir, "adblock_adg.txt")
        sorted_block = sorted(self.final_rules['block'], key=self._rule_sort_key)
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_block))
        print(f"  黑名单文件：{block_path}（{len(sorted_block)} 条纯净规则）")

        # 保存白名单 - 纯净规则，无文件头
        allow_path = os.path.join(self.output_dir, "allow_adg.txt")
        sorted_allow = sorted(self.final_rules['allow'])
        with open(allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_allow))
        print(f"  白名单文件：{allow_path}（{len(sorted_allow)} 条纯净规则）")

        print(f"【步骤6完成】纯净规则文件已保存！")

    # ------------------------------ 核心逻辑函数 ------------------------------
    def _is_comment_line_enhanced(self, rule: str) -> bool:
        """使用语法数据库的精确注释检测"""
        if not rule.strip():
            return True

        # 标准注释模式
        if rule.startswith(("!", "# ")):
            return True

        # 特殊处理：以#开头但不是有效规则的行
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

    def _identify_rule_type(self, rule: str) -> str:
        """识别规则类型"""
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                return pattern_name
        
        # 后备识别
        if self._is_hosts_rule(rule):
            return "hosts_rule"
        elif self._is_valid_element_hide_rule(rule):
            return "adblock_basic_element_hiding"
        elif re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            return "adblock_basic_domain_rule"
        
        return "unknown"

    def _is_hosts_rule(self, rule: str) -> bool:
        """检查是否为hosts规则"""
        return bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+[^\s#]+', rule))

    def _is_valid_element_hide_rule(self, rule: str) -> bool:
        """检查是否为有效的元素隐藏规则"""
        if not rule.startswith(("##", "#")):
            return False
        rule_content = rule.lstrip("#").strip()
        css_features = ['.', '#', '[', ']', '>', '+', ':', ',', '~', '(', ')']
        return any(feature in rule_content for feature in css_features)

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        """规则排序键"""
        if rule.startswith("@@") and "||" in rule:
            return (0, rule)  # 域名白名单
        elif rule.startswith("@@") and "##" in rule:
            return (1, rule)  # 元素隐藏白名单
        elif self._is_valid_element_hide_rule(rule):
            return (2, rule)  # 元素隐藏规则
        elif rule.startswith("||"):
            return (3, rule)  # 域名规则
        elif rule.startswith("|") and "|" in rule:
            return (4, rule)  # URL规则
        elif rule.startswith(("#%#", "#?#")):
            return (5, rule)  # 脚本和扩展CSS
        elif "$dnsrewrite" in rule:
            return (6, rule)  # DNS重写
        elif "$removeparam" in rule:
            return (7, rule)  # 参数移除
        else:
            return (8, rule)  # 其他规则

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
                except re.error:
                    continue  # 跳过无效正则
        return compiled

    # ------------------------------ 启动流程 ------------------------------
    def run_full_flow(self, input_dir: str) -> None:
        print("="*60)
        print("AdGuard纯净规则处理流程")
        print("输入: hosts黑名单 + AdGuard混合名单 + Pi-hole白名单")
        print("输出: 纯净AdGuard语法规则")
        print("="*60)
        try:
            self.step1_input(input_dir)
            if not self.raw_rules:
                print("\n流程终止：未加载到有效规则")
                return
            self.step2_convert()
            self.step3_categorize()
            self.step4_complete()
            self.step5_dedup()
            self.step6_output()
            
            print("\n" + "="*60)
            print("流程完成！")
            print(f"  输出纯净规则: {len(self.final_rules['block'])} 条黑名单, {len(self.final_rules['allow'])} 条白名单")
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