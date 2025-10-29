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

        # 流程变量 - 分别存储原始黑白名单规则
        self.raw_block_rules = []
        self.raw_allow_rules = []

        # 分别维护转换后的黑白名单规则（包含类型信息）
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

    def _init_adblock_parser(self):
        """初始化adblockparser规则解析器"""
        if not ADBLOCK_PARSER_AVAILABLE:
            self.rule_parser = None
            return

        try:
            # 使用空规则列表初始化解析器用于规则验证
            self.rule_parser = adblockparser.AdblockRules([], use_re2=True, max_mem=512*1024*1024)
        except Exception as e:
            print(f"警告: adblockparser初始化失败: {e}，将使用基础模式匹配")
            self.rule_parser = None

    # ------------------------------ 步骤1：从合并的rule.txt加载并分类规则 ------------------------------
    def step1_input(self, input_dir: str) -> None:
        print(f"\n【步骤1：加载并分类规则】从 {input_dir} 读取rule.txt并分类黑白名单...")
        if not os.path.exists(input_dir):
            os.makedirs(input_dir, exist_ok=True)
            print(f"警告：输入目录不存在，已自动创建：{input_dir}")
            return

        # 查找rule.txt文件
        rule_file_path = os.path.join(input_dir, "rule.txt")
        if not os.path.exists(rule_file_path):
            print(f"错误：未找到rule.txt文件在路径 {rule_file_path}")
            return

        self._load_and_classify_rules(rule_file_path)

        print(f"【步骤1完成】分类结果：{len(self.raw_block_rules)} 条黑名单规则，{len(self.raw_allow_rules)} 条白名单规则")

    def _load_and_classify_rules(self, file_path: str) -> None:
        """从rule.txt加载规则并根据语法分类为黑白名单"""
        print(f"  处理合并规则文件：rule.txt")

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                raw_rule = line.strip()
                
                # 跳过注释和空行
                if not raw_rule or self._is_comment_line_enhanced(raw_rule):
                    continue

                # 根据规则语法分类
                category = self._classify_rule_by_syntax(raw_rule)
                
                if category == "block":
                    self.raw_block_rules.append((raw_rule, "rule.txt", line_num, "block"))
                elif category == "allow":
                    self.raw_allow_rules.append((raw_rule, "rule.txt", line_num, "allow"))
                else:
                    print(f"    警告：无法分类的规则（{line_num}），已跳过: {raw_rule}")

    def _classify_rule_by_syntax(self, rule: str) -> str:
        """根据规则语法分类为黑名单或白名单"""
        # 1. 纯域名规则 - 只作为白名单（最高优先级）
        if self._is_pure_domain(rule):
            return "allow"
            
        # 2. AdGuard/AdGuard Home 白名单语法（@@开头）
        if self._is_adguard_allow_rule(rule):
            return "allow"
            
        # 3. AdGuard/AdGuard Home 黑名单语法（非@@开头）
        if self._is_adguard_block_rule(rule):
            return "block"
            
        # 4. Hosts格式规则（IP地址 + 域名）
        if self._is_hosts_rule(rule):
            return "block"
            
        # 5. 使用语法数据库进行高级分类
        rule_type = self._identify_rule_type_with_db(rule)
        if rule_type in ['exception', 'allow', 'whitelist']:
            return "allow"
        elif rule_type in ['blocking', 'cosmetic', 'scriptlet']:
            return "block"
            
        return "unknown"

    def _is_adguard_block_rule(self, rule: str) -> bool:
        """判断是否为AdGuard黑名单规则"""
        # 如果是纯域名，直接返回False（确保纯域名不会被误判为黑名单）
        if self._is_pure_domain(rule):
            return False
            
        # AdGuard黑名单特征
        block_indicators = [
            '##',    # 元素隐藏规则
            '#$#',   # 内容安全策略
            '#%#',   # 扩展规则
            '#@$#',  # 脚本规则
        ]
        
        # 不是白名单（不以@@开头）且包含黑名单特征
        if not rule.startswith('@@') and any(indicator in rule for indicator in block_indicators):
            return True
            
        # 常规AdGuard/AdBlock规则模式
        adguard_block_patterns = [
            r'^\|[\^]', r'^\|', r'\|$', r'^\*', r'\*$', r'^/', r'/$', r'^\$'
        ]
        if not rule.startswith('@@') and any(re.search(pattern, rule) for pattern in adguard_block_patterns):
            return True
            
        return False

    def _is_adguard_allow_rule(self, rule: str) -> bool:
        """判断是否为AdGuard白名单规则"""
        # 明确的AdGuard白名单语法
        if rule.startswith('@@'):
            return True
            
        # AdGuard元素隐藏白名单
        if '#@#' in rule:
            return True
            
        # 其他白名单指示符
        allow_indicators = [
            '#@$#',  # 脚本白名单  
            '#@%#',  # 扩展白名单
            '#@?#'   # 内容安全策略白名单
        ]
        if any(indicator in rule for indicator in allow_indicators):
            return True
            
        return False

    def _is_hosts_rule(self, rule: str) -> bool:
        """判断是否为hosts格式规则"""
        # 如果是纯域名，直接返回False
        if self._is_pure_domain(rule):
            return False
        return re.match(r'^\s*(\d+\.\d+\.\d+\.\d+|\:\:[\d\w\:]+)\s+', rule) is not None

    def _is_pure_domain(self, rule: str) -> bool:
        """判断是否为纯域名 - 严格检测"""
        # 移除首尾空白
        rule = rule.strip()
        
        # 排除空字符串
        if not rule:
            return False
            
        # 排除包含任何Adblock特殊字符的规则
        adblock_chars = ['|', '*', '^', '$', '#', '@', '!', '/', '?', '=', '&', '%', '~', '+', '(', ')', '[', ']', '{', '}', '<', '>', '\\']
        if any(char in rule for char in adblock_chars):
            return False
            
        # 排除包含空格的规则
        if ' ' in rule:
            return False
            
        # 匹配严格的域名格式：字母、数字、点、连字符，且有点号分隔
        domain_pattern = r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$'
        if re.match(domain_pattern, rule) is not None:
            return True
            
        # 排除IP地址
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        if re.match(ip_pattern, rule):
            return False
            
        return False

    # ------------------------------ 步骤2：基于语法数据库的规则识别与转换 ------------------------------
    def step2_convert(self) -> None:
        print(f"\n【步骤2：语法识别与转换】分别处理黑白名单规则...")

        block_stats = self._convert_block_rules_list(self.raw_block_rules, self.converted_block_rules, "黑名单")
        allow_stats = self._convert_allow_rules_list(self.raw_allow_rules, self.converted_allow_rules, "白名单")

        print(f"【步骤2完成】转换统计：")
        print(f"  黑名单: {block_stats['total']}条 → 成功{block_stats['success']}条, 失败{block_stats['failed']}条")
        print(f"  白名单: {allow_stats['total']}条 → 成功{allow_stats['success']}条, 失败{allow_stats['failed']}条")

    def _convert_block_rules_list(self, raw_rules: List, converted_rules: List, list_type: str) -> Dict:
        """转换黑名单规则列表 - 全部转为黑名单语法"""
        stats = {
            'total': len(raw_rules),
            'success': 0,
            'failed': 0
        }

        for raw_rule, file_name, line_num, category in raw_rules:
            try:
                # 关键修复：在黑名单转换中，如果发现纯域名，直接跳过并记录警告
                if self._is_pure_domain(raw_rule):
                    print(f"  严重错误：在黑名单中发现纯域名规则（{file_name}:{line_num}），纯域名只能作为白名单，已跳过: {raw_rule}")
                    stats['failed'] += 1
                    continue

                converted_rule = self._convert_to_block_syntax(raw_rule)
                if converted_rule:
                    # 双重检查：确保转换后的规则不是白名单格式
                    if converted_rule.startswith('@@'):
                        print(f"  严重错误：黑名单规则转换后变成了白名单（{file_name}:{line_num}），已跳过: {raw_rule} -> {converted_rule}")
                        stats['failed'] += 1
                        continue

                    rule_type = self._identify_rule_type_with_db(converted_rule)
                    converted_rules.append((converted_rule, rule_type, category))
                    stats['success'] += 1
                else:
                    stats['failed'] += 1

            except Exception as e:
                stats['failed'] += 1
                print(f"  {list_type}转换失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        return stats

    def _convert_allow_rules_list(self, raw_rules: List, converted_rules: List, list_type: str) -> Dict:
        """转换白名单规则列表 - 全部转为白名单语法"""
        stats = {
            'total': len(raw_rules),
            'success': 0,
            'failed': 0
        }

        for raw_rule, file_name, line_num, category in raw_rules:
            try:
                converted_rule = self._convert_to_allow_syntax(raw_rule)
                if converted_rule:
                    # 确保转换后的规则是白名单格式（有@@前缀）
                    if not converted_rule.startswith('@@'):
                        print(f"  警告：白名单规则转换后丢失了@@前缀（{file_name}:{line_num}），已修复: {raw_rule} -> @@{converted_rule}")
                        converted_rule = f"@@{converted_rule}"

                    rule_type = self._identify_rule_type_with_db(converted_rule)
                    converted_rules.append((converted_rule, rule_type, category))
                    stats['success'] += 1
                else:
                    stats['failed'] += 1

            except Exception as e:
                stats['failed'] += 1
                print(f"  {list_type}转换失败（{file_name}:{line_num}）：{raw_rule} → {str(e)}")

        return stats

    def _convert_to_block_syntax(self, rule: str) -> Optional[str]:
        """将任意规则转换为Adblock黑名单语法"""
        # 关键修复：在黑名单转换中，如果发现纯域名，直接返回None
        if self._is_pure_domain(rule):
            return None

        # 如果已经是Adblock格式且是黑名单，直接返回
        if self._is_adblock_rule(rule) and not rule.startswith('@@'):
            return rule

        # 处理hosts格式
        if self._is_hosts_rule(rule):
            return self._convert_hosts_to_block(rule)

        # 处理AdGuard格式规则
        if self._is_adguard_block_rule(rule):
            return self._convert_adguard_to_block(rule)

        # 处理其他格式
        return self._convert_unknown_to_block(rule)

    def _convert_to_allow_syntax(self, rule: str) -> Optional[str]:
        """将任意规则转换为Adblock白名单语法"""
        # 处理纯域名 - 这是纯域名唯一合法的转换路径
        if self._is_pure_domain(rule):
            return f"@@||{rule}^"

        # 如果已经是Adblock白名单格式，直接返回
        if self._is_adblock_rule(rule) and rule.startswith('@@'):
            return rule

        # 处理AdGuard白名单格式
        if self._is_adguard_allow_rule(rule):
            return self._convert_adguard_to_allow(rule)

        # 处理其他格式
        return self._convert_unknown_to_allow(rule)

    def _convert_adguard_to_block(self, rule: str) -> Optional[str]:
        """转换AdGuard黑名单规则为标准Adblock格式"""
        # 关键检查：确保不是纯域名
        if self._is_pure_domain(rule):
            return None
            
        # 简单的AdGuard规则可以直接使用
        if self._is_basic_adblock_rule(rule):
            return rule
            
        # 处理元素隐藏规则
        if '##' in rule:
            return rule
            
        # 提取域名并转换为基本规则
        domain = self._extract_domain(rule)
        if domain and not self._is_pure_domain(domain):  # 确保提取的域名不是纯域名
            return f"||{domain}^"
            
        return None

    def _convert_adguard_to_allow(self, rule: str) -> Optional[str]:
        """转换AdGuard白名单规则为标准Adblock格式"""
        # 如果已经是@@开头，直接返回
        if rule.startswith('@@'):
            return rule
            
        # 处理AdGuard元素隐藏白名单
        if '#@#' in rule:
            # 将#@#替换为##并添加@@前缀
            converted = rule.replace('#@#', '##')
            return f"@@{converted}"
            
        # 提取域名并转换为基本白名单规则
        domain = self._extract_domain(rule)
        if domain:
            return f"@@||{domain}^"
            
        return None

    def _convert_hosts_to_block(self, rule: str) -> Optional[str]:
        """转换hosts规则为黑名单语法"""
        # 关键检查：确保不是纯域名
        if self._is_pure_domain(rule):
            return None
            
        parts = rule.split()
        if len(parts) >= 2:
            domain = parts[1].strip()
            if domain and not domain.startswith('#') and not self._is_pure_domain(domain):
                return f"||{domain}^"
        return None

    def _convert_unknown_to_block(self, rule: str) -> Optional[str]:
        """转换未知格式规则为黑名单语法"""
        # 关键修复：在未知格式转换中也要检查纯域名
        if self._is_pure_domain(rule):
            return None
            
        # 尝试提取域名
        domain = self._extract_domain(rule)
        if domain and not self._is_pure_domain(domain):  # 确保提取的域名不是纯域名
            return f"||{domain}^"
        return None

    def _convert_unknown_to_allow(self, rule: str) -> Optional[str]:
        """转换未知格式规则为白名单语法"""
        # 尝试提取域名
        domain = self._extract_domain(rule)
        if domain:
            return f"@@||{domain}^"
        return None

    def _extract_domain(self, rule: str) -> Optional[str]:
        """从规则中提取域名"""
        # 移除可能的协议头
        rule = re.sub(r'^https?://', '', rule)

        # 移除路径和参数
        rule = rule.split('/')[0].split('?')[0].split('#')[0]

        # 检查是否为有效域名格式
        if self._is_pure_domain(rule):
            return rule

        # 尝试匹配IP地址或localhost
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', rule) or rule == 'localhost':
            return rule

        return None

    def _is_adblock_rule(self, rule: str) -> bool:
        """判断是否为Adblock格式规则"""
        # 如果是纯域名，直接返回False
        if self._is_pure_domain(rule):
            return False
            
        adblock_patterns = [
            r'^\|[\^]', r'^##', r'^@@', r'^\|', r'\|$', r'^\*', r'\*$', 
            r'^/', r'/$', r'^\$', r'#@#', r'#@\$#', r'#\$#', r'#%#', r'#@%#'
        ]
        return any(re.search(pattern, rule) for pattern in adblock_patterns)

    def _identify_rule_type_with_db(self, rule: str) -> str:
        """使用语法数据库识别规则类型"""
        # 如果是纯域名，直接返回白名单类型
        if self._is_pure_domain(rule):
            return "pure_domain_allow"
            
        # 优先使用数据库中的高级模式匹配
        for pattern_name, pattern in self.compiled_patterns.items():
            if pattern.match(rule):
                rule_type = self.syntax_db['rule_types'].get(pattern_name, 'unknown')
                if rule_type in ['metadata', 'meta', 'comment']:
                    continue
                return pattern_name

        # 使用adblockparser验证基础规则
        if self.rule_parser and self._is_basic_adblock_rule(rule):
            try:
                test_rules = adblockparser.AdblockRules([rule], use_re2=False, max_mem=1024*1024)
                return "adblock_basic_domain_rule"
            except:
                pass

        # 后备识别逻辑
        return self._fallback_rule_identification(rule)

    def _is_basic_adblock_rule(self, rule: str) -> bool:
        """判断是否为基础Adblock规则"""
        if self._is_comment_line_enhanced(rule):
            return False
            
        # 如果是纯域名，直接返回False
        if self._is_pure_domain(rule):
            return False

        basic_patterns = [
            r'^\|[\^]', r'^##', r'^@@', r'^\|', r'\|$', r'^\*', r'\*$', 
            r'^/', r'/$', r'^\$'
        ]
        return any(re.search(pattern, rule) for pattern in basic_patterns)

    def _fallback_rule_identification(self, rule: str) -> str:
        """后备规则识别逻辑"""
        # 如果是纯域名，直接返回白名单类型
        if self._is_pure_domain(rule):
            return "pure_domain_allow"
            
        if re.match(self.syntax_db['advanced_syntax_patterns']['hosts_rule'], rule):
            return "hosts_rule"

        if re.match(self.syntax_db['advanced_syntax_patterns']['pihole_domain'], rule):
            return "pihole_domain"

        if rule.startswith('##') and any(char in rule for char in ['.', '#', '[', '>', '{']):
            return "adblock_basic_element_hiding"

        if re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', rule):
            return "pihole_domain"

        return "unknown"

    # ------------------------------ 步骤3：分别对黑白名单独立去重 ------------------------------
    def step3_dedup(self) -> None:
        print(f"\n【步骤3：去重规则】分别对黑白名单独立去重...")

        block_duplicate_count = self._dedup_rule_list(self.converted_block_rules, "block")
        allow_duplicate_count = self._dedup_rule_list(self.converted_allow_rules, "allow")

        print(f"  黑名单：去重前 {len(self.converted_block_rules)} 条 → 去重后 {len(self.final_block_rules)} 条，重复 {block_duplicate_count} 条")
        print(f"  白名单：去重前 {len(self.converted_allow_rules)} 条 → 去重后 {len(self.final_allow_rules)} 条，重复 {allow_duplicate_count} 条")

    def _dedup_rule_list(self, rule_list: List, category: str) -> int:
        """对指定类别的规则列表进行去重"""
        duplicate_count = 0
        target_set = self.final_block_rules if category == "block" else self.final_allow_rules
        target_bloom = self.dedup_bloom_block if category == "block" else self.dedup_bloom_allow

        for rule, rule_type, rule_category in rule_list:
            try:
                rule_hash = hashlib.md5(rule.encode("utf-8")).hexdigest()

                rule_exists = rule in target_set

                if (target_bloom and rule_hash in target_bloom) or rule_exists:
                    duplicate_count += 1
                    continue

                target_set.add(rule)
                if target_bloom:
                    target_bloom.add(rule_hash)

            except Exception as e:
                print(f"  {category}去重失败：{rule} → {str(e)}")

        return duplicate_count

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
        adp_block_rules = []
        adp_allow_rules = []

        for rule in self.final_block_rules:
            # 最终检查：确保黑名单中没有纯域名
            if self._is_pure_domain(rule):
                print(f"  最终检查错误：在黑名单输出中发现纯域名，已跳过: {rule}")
                continue
                
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.adp_supported_types:
                adp_block_rules.append(rule)

        for rule in self.final_allow_rules:
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.adp_supported_types:
                adp_allow_rules.append(rule)

        # 保存Adblock Plus黑名单
        if adp_block_rules:
            adp_block_path = os.path.join(self.output_dir, "adblock_abp.txt")
            sorted_adp_block = sorted(adp_block_rules, key=self._rule_sort_key)
            with open(adp_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_adp_block))
            print(f"  Adblock Plus黑名单：{adp_block_path}（{len(sorted_adp_block)} 条规则）")

        # 保存Adblock Plus白名单
        if adp_allow_rules:
            adp_allow_path = os.path.join(self.output_dir, "allow_abp.txt")
            sorted_adp_allow = sorted(adp_allow_rules)
            with open(adp_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_adp_allow))
            print(f"  Adblock Plus白名单：{adp_allow_path}（{len(sorted_adp_allow)} 条规则）")

    def _generate_ubo_rules(self) -> None:
        """生成uBlock Origin格式规则"""
        ubo_block_rules = []
        ubo_allow_rules = []

        for rule in self.final_block_rules:
            # 最终检查：确保黑名单中没有纯域名
            if self._is_pure_domain(rule):
                print(f"  最终检查错误：在黑名单输出中发现纯域名，已跳过: {rule}")
                continue
                
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.ubo_supported_types:
                ubo_block_rules.append(rule)

        for rule in self.final_allow_rules:
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.ubo_supported_types:
                ubo_allow_rules.append(rule)

        # 保存uBlock Origin黑名单
        if ubo_block_rules:
            ubo_block_path = os.path.join(self.output_dir, "adblock_ubo.txt")
            sorted_ubo_block = sorted(ubo_block_rules, key=self._rule_sort_key)
            with open(ubo_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ubo_block))
            print(f"  uBlock Origin黑名单：{ubo_block_path}（{len(sorted_ubo_block)} 条规则）")

        # 保存uBlock Origin白名单
        if ubo_allow_rules:
            ubo_allow_path = os.path.join(self.output_dir, "allow_ubo.txt")
            sorted_ubo_allow = sorted(ubo_allow_rules)
            with open(ubo_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ubo_allow))
            print(f"  uBlock Origin白名单：{ubo_allow_path}（{len(sorted_ubo_allow)} 条规则）")

    def _generate_adguard_rules(self) -> None:
        """生成AdGuard格式规则"""
        ag_block_rules = []
        ag_allow_rules = []

        for rule in self.final_block_rules:
            # 最终检查：确保黑名单中没有纯域名
            if self._is_pure_domain(rule):
                print(f"  最终检查错误：在黑名单输出中发现纯域名，已跳过: {rule}")
                continue
                
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.ag_supported_types:
                ag_block_rules.append(rule)

        for rule in self.final_allow_rules:
            rule_type = self._identify_rule_type_with_db(rule)
            if rule_type in self.ag_supported_types:
                ag_allow_rules.append(rule)

        # 保存AdGuard黑名单
        if ag_block_rules:
            ag_block_path = os.path.join(self.output_dir, "adblock_adg.txt")
            sorted_ag_block = sorted(ag_block_rules, key=self._rule_sort_key)
            with open(ag_block_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ag_block))
            print(f"  AdGuard黑名单：{ag_block_path}（{len(sorted_ag_block)} 条规则）")

        # 保存AdGuard白名单
        if ag_allow_rules:
            ag_allow_path = os.path.join(self.output_dir, "allow_adg.txt")
            sorted_ag_allow = sorted(ag_allow_rules)
            with open(ag_allow_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_ag_allow))
            print(f"  AdGuard白名单：{ag_allow_path}（{len(sorted_ag_allow)} 条规则）")

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

        if rule.startswith("#"):
            valid_hash_rules = [
                rule.startswith("##"),
                rule.startswith("#@#"),
                rule.startswith("#?#"),
                rule.startswith("#%#"),
                rule.startswith("#$#"),
                rule.startswith("#@$#"),
            ]

            if any(valid_hash_rules):
                return False

            return True

        return False

    def _rule_sort_key(self, rule: str) -> Tuple[int, str]:
        """规则排序键"""
        if rule.startswith("@@"):
            if "||" in rule:
                return (0, rule)
            elif "##" in rule:
                return (1, rule)
            else:
                return (2, rule)

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

        rule_type = self._identify_rule_type_with_db(rule)
        rule_type_info = self.syntax_db['rule_types'].get(rule_type, 'blocking')

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
        print("AdBlock多平台规则处理流程 - 合并规则文件处理")
        print(f"语法数据库版本: {self.syntax_db['version']}")
        print("输入: 合并的rule.txt文件（包含AdGuard/hosts/domain规则）")
        print("分类: AdGuard黑名单语法、hosts语法 → 黑名单 | AdGuard白名单语法、纯域名 → 白名单")
        print("输出: Adblock Plus, uBlock Origin, AdGuard 格式规则")
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