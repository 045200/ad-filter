#!/usr/bin/env python3
"""
AdGuard混合语法处理脚本（优化：保留Hosts+正确归类混合语法）
流程：输入-转换(跳过Hosts)-归类(混合语法适配)-补全-合并去重-输出
"""

import os
import re
import glob
import hashlib
from typing import Set, List, Dict, Tuple

# ------------------------------ 依赖加载（保留原有） ------------------------------
try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    print("警告: pybloom_live 未安装，使用哈希表单重去重")

try:
    import json5 as json
    JSON5_AVAILABLE = True
    print("使用 JSON5 解析语法数据库（保留原有）")
except ImportError:
    import json
    JSON5_AVAILABLE = False
    print("警告: json5 未安装，使用标准JSON解析（保留原有）")

# ------------------------------ 核心类（严格遵循六步流程，仅优化Hosts和归类） ------------------------------
class AdGuardMixedSyntaxConverter:
    def __init__(self, syntax_db_path: str, output_dir: str):
        self.syntax_db = self._load_syntax_db(syntax_db_path)
        self.output_dir = output_dir
        self.ag_support = self.syntax_db['platform_support']['adguard_browser_extension']
        self.compiled_patterns = self._compile_all_patterns()
        
        # 流程中间变量（保留原有）
        self.raw_rules = []
        self.converted_rules = []
        self.categorized_rules = {'block': [], 'allow': []}
        self.completed_rules = {'block': [], 'allow': []}
        self.final_rules = {'block': set(), 'allow': set()}

        # 去重配置（保留原有）
        bloom_cfg = self.syntax_db['performance_optimization']['bloom_filter_config']
        self.dedup_bloom = {
            cat: BloomFilter(
                capacity=bloom_cfg['initial_capacity'],
                error_rate=bloom_cfg['error_rate']
            ) if BLOOM_AVAILABLE else None
            for cat in ['block', 'allow']
        }

    # ------------------------------ 步骤1：输入（保留原有） ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：输入】加载 {input_dir} 下的规则...")
        if not os.path.exists(input_dir):
            os.makedirs(input_dir, exist_ok=True)
            print(f"警告：输入目录不存在，已自动创建（{input_dir}）")
            return

        input_files = glob.glob(os.path.join(input_dir, '*.txt'), recursive=False)
        if not input_files:
            print(f"警告：输入目录下无TXT文件（{input_dir}）")
            return

        for file in input_files:
            file_name = os.path.basename(file)
            print(f"  加载文件：{file_name}")
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    raw_rule = line.strip()
                    # 保留原有：跳过空行和纯注释（保留aglint注释）
                    if not raw_rule or (raw_rule.startswith(('!', '# ')) and 'aglint-' not in raw_rule):
                        continue
                    self.raw_rules.append((raw_rule, file_name, line_num))
        
        print(f"【步骤1完成】共加载 {len(self.raw_rules)} 条非空/非注释规则")

    # ------------------------------ 步骤2：转换（核心优化：保留Hosts原始语法，不转换） ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：转换】处理 {len(self.raw_rules)} 条原始规则（Hosts不转换）...")
        for raw_rule, file_name, line_num in self.raw_rules:
            try:
                rule_type = self._identify_rule_type(raw_rule)
                # 核心优化1：Hosts规则保留原始语法（AdGuard支持，不转换为||domain^）
                if rule_type == 'hosts_rule':
                    converted = raw_rule  # 直接保留Hosts格式（如127.0.0.1 test.com）
                # 其他规则转换逻辑不变（纯域名→AdGuard、专属规则→标准格式）
                elif rule_type == 'pihole_domain':
                    converted = f"||{raw_rule.lower()}^"
                elif rule_type in ['adguard_dns_rewrite', 'adguard_removeparam', 'adguard_scriptlet']:
                    converted = self._convert_exclusive_rule(raw_rule, rule_type)
                else:
                    converted = raw_rule

                self.converted_rules.append((converted, rule_type, file_name, line_num))
            except Exception as e:
                print(f"  转换失败（{file_name}:{line_num}）：{raw_rule} → 错误：{str(e)}")
        
        print(f"【步骤2完成】共转换成功 {len(self.converted_rules)} 条规则（Hosts均保留原始格式）")

    # ------------------------------ 步骤3：归类（核心优化：混合语法正确分黑白名单） ------------------------------
    def step3_categorize(self) -> None:
        print(f"\n【步骤3：归类】混合语法适配（正确分黑白名单）...")
        for converted_rule, rule_type, file_name, line_num in self.converted_rules:
            try:
                # 核心优化2：混合语法归类逻辑（优先级：例外标识>规则类型）
                # 1. 白名单（allow）判定：只要含@@（例外标识），无论基础/专属语法
                if converted_rule.startswith('@@'):
                    category = 'allow'
                # 2. 黑名单（block）判定：所有拦截类规则（含Hosts、AdGuard专属、基础拦截）
                elif any([
                    # Hosts规则（原始格式，AdGuard支持拦截）
                    rule_type == 'hosts_rule',
                    # AdGuard专属拦截规则
                    rule_type in ['adguard_dns_rewrite', 'adguard_removeparam', 'adguard_scriptlet', 'adguard_extended_css'],
                    # 基础拦截规则
                    rule_type in ['adblock_basic_domain_rule', 'adblock_basic_url_rule', 'adblock_basic_element_hiding', 'pihole_domain'],
                    # 其他隐含拦截规则（如带$block修饰符）
                    '$block' in converted_rule and '$allow' not in converted_rule
                ]):
                    category = 'block'
                # 3. 默认：其他规则归block（如无标识的扩展CSS、正则）
                else:
                    category = 'block'

                self.categorized_rules[category].append((converted_rule, rule_type, file_name, line_num))
            except Exception as e:
                print(f"  归类失败（{file_name}:{line_num}）：{converted_rule} → 错误：{str(e)}")
        
        print(f"【步骤3完成】归类结果：黑名单={len(self.categorized_rules['block'])} 条，白名单={len(self.categorized_rules['allow'])} 条")

    # ------------------------------ 步骤4：补全（保留原有，仅补全非Hosts规则） ------------------------------
    def step4_complete(self) -> None:
        print(f"\n【步骤4：补全】处理 {sum(len(v) for v in self.categorized_rules.values())} 条规则（Hosts不补全）...")
        for category in ['block', 'allow']:
            for rule, rule_type, file_name, line_num in self.categorized_rules[category]:
                try:
                    completed = rule
                    # 核心优化3：Hosts规则不补全，保留原始格式
                    if rule_type == 'hosts_rule':
                        pass  # 不做任何修改
                    # 其他规则补全逻辑不变
                    elif rule_type == 'adblock_basic_domain_rule' and '||' not in rule:
                        completed = f"||{rule.lower()}^"
                    elif rule_type == 'adguard_scriptlet' and not rule.startswith('#%#'):
                        completed = f"#%# {rule}".strip()
                    elif rule_type == 'adguard_extended_css' and not rule.startswith('#?#'):
                        completed = f"#?# {rule}".strip()
                    elif rule_type in ['adblock_basic_regex_rule', 'regex_rule'] and not rule.startswith('/'):
                        completed = f"/{rule}/"

                    self.completed_rules[category].append((completed, file_name, line_num))
                except Exception as e:
                    print(f"  补全失败（{file_name}:{line_num}）：{rule} → 错误：{str(e)}")
        
        print(f"【步骤4完成】补全结果：黑名单={len(self.completed_rules['block'])} 条，白名单={len(self.completed_rules['allow'])} 条")

    # ------------------------------ 步骤5：合并去重（保留原有） ------------------------------
    def step5_dedup(self) -> None:
        print(f"\n【步骤5：合并去重】处理 {sum(len(v) for v in self.completed_rules.values())} 条规则...")
        for category in ['block', 'allow']:
            duplicate_count = 0
            for rule, file_name, line_num in self.completed_rules[category]:
                try:
                    rule_hash = hashlib.md5(rule.encode('utf-8')).hexdigest()
                    # 布隆预判
                    if self.dedup_bloom[category] and rule_hash in self.dedup_bloom[category]:
                        duplicate_count += 1
                        continue
                    # 哈希精确去重
                    if rule in self.final_rules[category]:
                        duplicate_count += 1
                        continue
                    # 加入最终集合
                    self.final_rules[category].add(rule)
                    if self.dedup_bloom[category]:
                        self.dedup_bloom[category].add(rule_hash)
                except Exception as e:
                    print(f"  去重失败（{file_name}:{line_num}）：{rule} → 错误：{str(e)}")
            
            print(f"  {category}（{'白名单' if category=='allow' else '黑名单'}）：去重前={len(self.completed_rules[category])} 条，去重后={len(self.final_rules[category])} 条，重复={duplicate_count} 条")
        
        print(f"【步骤5完成】最终规则：黑名单={len(self.final_rules['block'])} 条，白名单={len(self.final_rules['allow'])} 条")

    # ------------------------------ 步骤6：输出（保留原有双文件） ------------------------------
    def step6_output(self) -> None:
        print(f"\n【步骤6：输出】保存黑白名单到 {self.output_dir}...")
        os.makedirs(self.output_dir, exist_ok=True)

        # 输出黑名单（adblock_adg.txt，含Hosts、AdGuard专属）
        block_path = os.path.join(self.output_dir, 'adblock_adg.txt')
        with open(block_path, 'w', encoding='utf-8') as f:
            # 排序：Hosts→基础规则→AdGuard专属（符合AdGuard匹配优先级）
            sorted_block = sorted(self.final_rules['block'], key=self._rule_sort_key)
            f.write('\n'.join(sorted_block))
        print(f"  黑名单：{block_path}（{len(sorted_block)} 条，含Hosts原始格式）")

        # 输出白名单（allow_adg.txt）
        allow_path = os.path.join(self.output_dir, 'allow_adg.txt')
        with open(allow_path, 'w', encoding='utf-8') as f:
            sorted_allow = sorted(self.final_rules['allow'])
            f.write('\n'.join(sorted_allow))
        print(f"  白名单：{allow_path}（{len(sorted_allow)} 条）")

        print(f"【步骤6完成】双文件输出完毕")

    # ------------------------------ 辅助函数（仅优化Hosts相关判断） ------------------------------
    def _load_syntax_db(self, path: str) -> Dict:
        paths = [
            path,
            os.path.join(os.path.dirname(__file__), os.path.basename(path)),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'python', os.path.basename(path))
        ]
        for p in paths:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f:
                    if JSON5_AVAILABLE:
                        return json.load(f)
                    else:
                        return json.loads(self._clean_json_comments(f.read()))
        raise FileNotFoundError(f"语法数据库未找到（尝试路径：{paths}）")

    def _clean_json_comments(self, content: str) -> str:
        in_str, esc = False, False
        cleaned = []
        for c in content:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = not in_str
            elif not in_str and (c == '#' or (c == '/' and cleaned and cleaned[-1] == '/')):
                break
            cleaned.append(c)
        return ''.join(cleaned)

    def _compile_all_patterns(self) -> Dict[str, re.Pattern]:
        compiled = {}
        supported_types = self.ag_support['supported_rule_types'] + ['pihole_domain', 'hosts_rule']
        for pat_name, pat_str in self.syntax_db['syntax_patterns'].items():
            if pat_name in supported_types and isinstance(pat_str, str):
                try:
                    compiled[pat_name] = re.compile(pat_str, re.UNICODE)
                except re.error:
                    print(f"警告：跳过无效正则模式 {pat_name}")
        return compiled

    def _identify_rule_type(self, rule: str) -> str:
        # 优先识别Hosts（避免被误判为其他类型）
        if self.compiled_patterns['hosts_rule'].match(rule):
            return 'hosts_rule'
        # 再识别其他类型
        for pat_name, pat in self.compiled_patterns.items():
            if pat.match(rule):
                return pat_name
        # 兜底：纯域名
        if self.compiled_patterns['pihole_domain'].match(rule):
            return 'pihole_domain'
        return 'unknown'

    def _convert_exclusive_rule(self, rule: str, rule_type: str) -> str:
        if rule_type == 'adguard_dns_rewrite' and '||' not in rule:
            domain_match = re.search(r'([a-zA-Z0-9.-]+)\s*\$dnsrewrite=(.+)', rule)
            if domain_match:
                return f"||{domain_match.group(1).lower()}^$dnsrewrite={domain_match.group(2).strip()}"
        elif rule_type == 'adguard_removeparam' and '||' not in rule:
            domain_match = re.search(r'([a-zA-Z0-9.-]+)\s*\$removeparam=(.+)', rule)
            if domain_match:
                return f"||{domain_match.group(1).lower()}^$removeparam={domain_match.group(2).strip()}"
        return rule

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        # 排序优先级：Hosts→基础规则→AdGuard专属（符合AdGuard匹配逻辑）
        if self.compiled_patterns['hosts_rule'].match(rule):  # Hosts规则优先
            return (0, rule)
        elif rule.startswith('||') and '$' not in rule:  # 基础域名规则
            return (1, rule)
        elif rule.startswith('##'):  # 基础元素隐藏
            return (2, rule)
        elif '$dnsrewrite' in rule:  # AdGuard DNS重写
            return (3, rule)
        elif '$removeparam' in rule:  # AdGuard参数移除
            return (4, rule)
        elif rule.startswith('#%#'):  # AdGuard Scriptlet
            return (5, rule)
        else:
            return (6, rule)

    # ------------------------------ 流程启动（保留原有） ------------------------------
    def run_full_flow(self, input_dir: str) -> None:
        print("="*60)
        print("AdGuard混合语法处理流程（Hosts保留+混合归类优化）")
        print("="*60)
        try:
            self.step1_input(input_dir)
            if not self.raw_rules:
                print("流程终止：无有效输入规则")
                return
            self.step2_convert()
            self.step3_categorize()
            self.step4_complete()
            self.step5_dedup()
            self.step6_output()
            print("\n" + "="*60)
            print("完整流程执行完毕！")
            print(f"黑名单（含Hosts）：{self.output_dir}/adblock_adg.txt")
            print(f"白名单：{self.output_dir}/allow_adg.txt")
            print("="*60)
        except Exception as e:
            print(f"\n流程执行失败：{str(e)}")


# ------------------------------ 主函数（保留原有路径） ------------------------------
if __name__ == "__main__":
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
    INPUT_DIR = os.path.join(PROJECT_ROOT, 'data', 'filter')    # 上游混合语法输入目录
    OUTPUT_DIR = PROJECT_ROOT                                    # 输出目录（根目录）
    SYNTAX_DB_PATH = os.path.join(SCRIPT_DIR, 'adblock_syntax_db.json')

    converter = AdGuardMixedSyntaxConverter(
        syntax_db_path=SYNTAX_DB_PATH,
        output_dir=OUTPUT_DIR
    )
    converter.run_full_flow(input_dir=INPUT_DIR)
