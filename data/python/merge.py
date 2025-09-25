#!/usr/bin/env python3
"""
AdGuard规则处理脚本（注释清零版）
修复点：彻底修正路径计算，确保输入./data/filter、输出./、ps.txt路径./data/mod/ps.txt
"""

import os
import re
import glob
import hashlib
from typing import Set, List, Dict, Tuple

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
    print("使用 JSON5 解析语法数据库（支持注释）")
except ImportError:
    import json
    JSON5_AVAILABLE = False
    print("警告: json5 未安装，将使用标准JSON解析（不支持注释）")

# ------------------------------ 核心处理类 ------------------------------
class AdGuardCommentFreeConverter:
    def __init__(self, syntax_db_path: str, output_dir: str):
        # 加载语法数据库（路径已修正）
        self.syntax_db = self._load_syntax_db(syntax_db_path)
        self.output_dir = output_dir  # 接收外部传入的输出目录（./）
        self.ag_support = self.syntax_db['platform_support']['adguard_browser_extension']
        self.compiled_patterns = self._compile_all_patterns()
        
        # 【关键修复】ps.txt路径：项目根目录/data/mod/ps.txt（不再多一层data）
        self.PS_CONFIG_PATH = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),  # 项目根目录（多算一层dirname，修正根目录）
                "data", "mod", "ps.txt"
            )
        )
        # 从外部文件加载注释配置（无内置）
        self.user_comment_keywords, self.comment_regex_patterns = self._load_external_comment_config()

        # 流程变量（不变）
        self.raw_rules = []
        self.converted_rules = []
        self.categorized_rules = {'block': [], 'allow': []}
        self.completed_rules = {'block': [], 'allow': []}
        self.final_rules = {'block': set(), 'allow': set()}

        # 去重配置（不变）
        bloom_cfg = self.syntax_db['performance_optimization']['bloom_filter_config']
        self.dedup_bloom = {
            cat: BloomFilter(
                capacity=bloom_cfg['initial_capacity'], 
                error_rate=bloom_cfg['error_rate']
            ) if BLOOM_AVAILABLE else None 
            for cat in ['block', 'allow']
        }

    # ------------------------------ 核心：加载ps.txt（路径已修复） ------------------------------
    def _load_external_comment_config(self) -> Tuple[List[str], List[str]]:
        keywords = []
        regex_patterns = []

        # 检查ps.txt是否在正确路径（./data/mod/ps.txt）
        if not os.path.exists(self.PS_CONFIG_PATH):
            raise FileNotFoundError(
                f"注释配置文件不存在！请在以下路径创建 ps.txt：\n{self.PS_CONFIG_PATH}\n"
                "参考格式：\nKEYWORD:中国移动,抖音\nREGEX:^#!.*!#$\nREGEX:^#-+.*-+#$"
            )

        # 读取解析ps.txt
        with open(self.PS_CONFIG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith('#'):
                    continue
                # 解析关键词
                if clean_line.startswith("KEYWORD:"):
                    keyword_content = clean_line[len("KEYWORD:"):].strip()
                    if keyword_content:
                        keywords = [k.strip() for k in keyword_content.split(',') if k.strip()]
                # 解析正则
                elif clean_line.startswith("REGEX:"):
                    regex_content = clean_line[len("REGEX:"):].strip()
                    if regex_content:
                        regex_patterns.append(regex_content)
                else:
                    print(f"警告：{self.PS_CONFIG_PATH} 第{line_num}行格式无效，已跳过：{clean_line}")

        # 配置校验
        if not keywords:
            print(f"警告：{self.PS_CONFIG_PATH} 未配置有效关键词（需KEYWORD:行）")
        if not regex_patterns:
            print(f"警告：{self.PS_CONFIG_PATH} 未配置有效正则（需REGEX:行）")

        return keywords, regex_patterns

    # ------------------------------ 步骤1：输入（路径修复为./data/filter） ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载规则】从 {input_dir} 读取TXT规则...")
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
            print(f"  处理文件：{file_name}")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    raw_rule = line.strip()
                    if not raw_rule or self._is_comment_by_config(raw_rule):
                        continue
                    self.raw_rules.append((raw_rule, file_name, line_num))

        print(f"【步骤1完成】加载 {len(self.raw_rules)} 条非注释规则")

    # ------------------------------ 步骤2-6：逻辑不变（仅路径已修复） ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：转换规则】处理 {len(self.raw_rules)} 条规则...")
        for raw_rule, file_name, line_num in self.raw_rules:
            try:
                rule_type = self._identify_rule_type(raw_rule)
                if rule_type == "hosts_rule":
                    converted_rule = raw_rule
                elif rule_type == "pihole_domain":
                    converted_rule = f"||{raw_rule.lower()}^"
                elif rule_type in ["adguard_dns_rewrite", "adguard_removeparam", "adguard_scriptlet"]:
                    converted_rule = self._convert_special_rule(raw_rule, rule_type)
                else:
                    converted_rule = raw_rule
                self.converted_rules.append((converted_rule, rule_type, file_name, line_num))
            except Exception as e:
                print(f"  转换失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")
        print(f"【步骤2完成】成功转换 {len(self.converted_rules)} 条规则")

    def step3_categorize(self) -> None:
        print(f"\n【步骤3：归类规则】区分黑白名单...")
        for converted_rule, rule_type, file_name, line_num in self.converted_rules:
            try:
                if converted_rule.startswith("@@"):
                    self.categorized_rules["allow"].append((converted_rule, rule_type, file_name, line_num))
                elif any([
                    rule_type == "hosts_rule",
                    rule_type in ["adguard_dns_rewrite", "adguard_removeparam", "adguard_scriptlet", "adguard_extended_css"],
                    rule_type in ["adblock_basic_domain_rule", "adblock_basic_url_rule", "adblock_basic_element_hiding", "pihole_domain"],
                    "$block" in converted_rule and "$allow" not in converted_rule,
                    self._is_valid_element_hide_rule(converted_rule)
                ]):
                    self.categorized_rules["block"].append((converted_rule, rule_type, file_name, line_num))
                else:
                    self.categorized_rules["block"].append((converted_rule, rule_type, file_name, line_num))
            except Exception as e:
                print(f"  归类失败（{file_name}:{line_num}）：{converted_rule} → {str(e)}")
        print(f"【步骤3完成】黑名单：{len(self.categorized_rules['block'])} 条，白名单：{len(self.categorized_rules['allow'])} 条")

    def step4_complete(self) -> None:
        print(f"\n【步骤4：补全规则】完善格式...")
        for category in ["block", "allow"]:
            for rule, rule_type, file_name, line_num in self.categorized_rules[category]:
                try:
                    completed_rule = rule
                    if rule_type == "adblock_basic_domain_rule" and "||" not in rule:
                        completed_rule = f"||{rule.lower()}^"
                    elif rule_type == "adguard_scriptlet" and not rule.startswith("#%#"):
                        completed_rule = f"#%# {rule}".strip()
                    elif rule_type == "adguard_extended_css" and not rule.startswith("#?#"):
                        completed_rule = f"#?# {rule}".strip()
                    elif rule_type in ["adblock_basic_regex_rule", "regex_rule"] and not rule.startswith("/"):
                        completed_rule = f"/{rule}/"
                    self.completed_rules[category].append((completed_rule, file_name, line_num))
                except Exception as e:
                    print(f"  补全失败（{file_name}:{line_num}）：{rule} → {str(e)}")
        print(f"【步骤4完成】补全后：黑名单 {len(self.completed_rules['block'])} 条，白名单 {len(self.completed_rules['allow'])} 条")

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

    def step6_output(self) -> None:
        print(f"\n【步骤6：保存结果】输出到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        # 输出黑名单到项目根目录（./adblock_adg_clean.txt）
        block_path = os.path.join(self.output_dir, "adblock_adg.txt")
        sorted_block = sorted([r for r in self.final_rules['block'] if not self._is_comment_by_config(r)], key=self._rule_sort_key)
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_block))
        print(f"  黑名单文件：{block_path}（{len(sorted_block)} 条）")

        # 输出白名单到项目根目录（./allow_adg_clean.txt）
        allow_path = os.path.join(self.output_dir, "allow_adg.txt")
        sorted_allow = sorted([r for r in self.final_rules['allow'] if not self._is_comment_by_config(r)])
        with open(allow_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_allow))
        print(f"  白名单文件：{allow_path}（{len(sorted_allow)} 条）")

        print(f"【步骤6完成】文件已保存到项目根目录！")

    # ------------------------------ 辅助函数（不变） ------------------------------
    def _is_comment_by_config(self, rule: str) -> bool:
        # 匹配ps.txt中的正则
        for regex in self.comment_regex_patterns:
            try:
                if re.fullmatch(regex, rule, re.UNICODE):
                    return True
            except re.error:
                print(f"警告：无效正则 {regex}，已跳过")
                continue
        # 匹配ps.txt中的关键词（##开头）
        if rule.startswith("##"):
            rule_content = rule.lstrip("##").strip()
            for keyword in self.user_comment_keywords:
                if keyword in rule_content:
                    return True
        # 常规注释
        if rule.startswith(("!", "# ")) or re.fullmatch(r"^#\d+([/年日月 :]+\d+)*", rule):
            return True
        return False

    def _load_syntax_db(self, path: str) -> Dict:
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
        in_string = False
        escaped = False
        cleaned = []
        for char in content:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = not in_string
            elif not in_string and (char == '#' or (char == '/' and cleaned and cleaned[-1] == '/')):
                break
            cleaned.append(char)
        return ''.join(cleaned)

    def _compile_all_patterns(self) -> Dict[str, re.Pattern]:
        compiled = {}
        supported_types = self.ag_support['supported_rule_types'] + ['pihole_domain', 'hosts_rule']
        for pat_name, pat_str in self.syntax_db['syntax_patterns'].items():
            if pat_name in supported_types and isinstance(pat_str, str):
                try:
                    compiled[pat_name] = re.compile(pat_str, re.UNICODE)
                except re.error:
                    print(f"警告：跳过无效正则 {pat_name}")
        return compiled

    def _identify_rule_type(self, rule: str) -> str:
        if self.compiled_patterns.get('hosts_rule') and self.compiled_patterns['hosts_rule'].match(rule):
            return 'hosts_rule'
        if self._is_valid_element_hide_rule(rule):
            return 'adblock_basic_element_hiding'
        for pat_name, pat in self.compiled_patterns.items():
            if pat.match(rule):
                return pat_name
        if self.compiled_patterns.get('pihole_domain') and self.compiled_patterns['pihole_domain'].match(rule):
            return 'pihole_domain'
        return 'unknown'

    def _convert_special_rule(self, rule: str, rule_type: str) -> str:
        if rule_type == "adguard_dns_rewrite" and "||" not in rule:
            match = re.search(r'([a-zA-Z0-9.-]+)\s*\$dnsrewrite=(.+)', rule)
            if match:
                return f"||{match.group(1).lower()}^$dnsrewrite={match.group(2).strip()}"
        elif rule_type == "adguard_removeparam" and "||" not in rule:
            match = re.search(r'([a-zA-Z0-9.-]+)\s*\$removeparam=(.+)', rule)
            if match:
                return f"||{match.group(1).lower()}^$removeparam={match.group(2).strip()}"
        return rule

    def _is_valid_element_hide_rule(self, rule: str) -> bool:
        if not rule.startswith(("##", "#")):
            return False
        rule_content = rule.lstrip("#").strip()
        css_features = ['.', '#', '[', ']', '>', '+', ':', ',', '~', '(', ')']
        return any(feature in rule_content for feature in css_features)

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        if self.compiled_patterns.get('hosts_rule') and self.compiled_patterns['hosts_rule'].match(rule):
            return (0, rule)
        elif self._is_valid_element_hide_rule(rule):
            return (1, rule)
        elif rule.startswith(("||", "@|")):
            return (2, rule)
        elif rule.startswith(("#%#", "#?#")):
            return (3, rule)
        elif "$dnsrewrite" in rule or "$removeparam" in rule:
            return (4, rule)
        else:
            return (5, rule)

    # ------------------------------ 启动流程 ------------------------------
    def run_full_flow(self, input_dir: str) -> None:
        print("="*60)
        print("AdGuard规则处理流程（路径修复版）")
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
            print("流程完成！当前路径配置：")
            print(f"  输入目录：{input_dir}")
            print(f"  输出目录：{self.output_dir}")
            print(f"  注释配置：{self.PS_CONFIG_PATH}")
            print("="*60)
        except Exception as e:
            print(f"\n流程失败：{str(e)}")


# ------------------------------ 主函数（关键：修复路径计算） ------------------------------
if __name__ == "__main__":
    # 脚本路径：./data/python/merge.py（项目根目录下的data/python）
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # ./data/python
    PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))  # 项目根目录（./），修复核心！
    SYNTAX_DB_PATH = os.path.join(SCRIPT_DIR, "syntax_db.json")  # ./data/python/adblock_syntax_db.json

    # 【用户要求的路径】
    INPUT_DIR = os.path.join(PROJECT_ROOT, "data", "filter")  # ./data/filter（正确！）
    OUTPUT_DIR = PROJECT_ROOT  # ./（项目根目录，正确！）

    # 启动脚本
    converter = AdGuardCommentFreeConverter(
        syntax_db_path=SYNTAX_DB_PATH,
        output_dir=OUTPUT_DIR
    )
    converter.run_full_flow(input_dir=INPUT_DIR)
