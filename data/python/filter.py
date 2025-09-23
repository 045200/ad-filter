import os
import re
import json
import sys
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Pattern
from dataclasses import dataclass, field
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 尝试导入Bloom过滤器，如果不可用则使用集合作为回退
try:
    from pybloom_live import BloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    logger.warning("pybloom_live未安装，使用集合进行去重，性能可能受影响")

@dataclass
class UnifiedConfig:
    """统一配置类"""
    # 基础路径配置 - 所有路径都基于GitHub根目录
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))

    # 输入文件 - 直接在GitHub根目录
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"

    # 输出目录 - 也是GitHub根目录
    OUTPUT_DIR: Path = BASE_DIR

    # 语法数据库 - 放在根目录
    SYNTAX_DB_FILE: Path = BASE_DIR / "data" / "python" / "adblock_syntax_db.json"

    # Mihomo工具配置 - 修正为github根目录的data路径下
    MIHOMO_TOOL_PATH: Path = BASE_DIR / "data" / "mihomo-tool"

    # 输出文件配置 - 更新为更合理的结构
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {
            "block": "adblock_clash.yaml",  # 独立黑名单
            "allow": "allow_clash.yaml"     # 独立白名单
        },
        "surge": {
            "block": "adblock_surge.conf"   # 仅黑名单，DOMAIN-SET格式
        },
        "pihole": {
            "block": "adblock_pihole.txt",
            "allow": "allow_pihole.txt"  # 独立白名单
        },
        "ublock_origin": {
            "block": "adblock_ubo.txt",
            "allow": "allow_ubo.txt"  # 独立白名单
        },
        "adblock_plus": {
            "block": "adblock_abp.txt",
            "allow": "allow_abp.txt"  # 独立白名单
        },
        "hosts": {
            "block": "hosts.txt"  # 仅黑名单
        },
        "mihomo_output": {
            "block": "adb.mrs"  # 仅保留黑名单，移除白名单输出
        }
    })

    # 功能开关
    ENABLE_MIHOMO_COMPILATION: bool = True
    ENABLE_DEDUPLICATION: bool = True
    ENABLE_BLOOM_FILTER: bool = BLOOM_AVAILABLE
    ENABLE_WHITELIST_FILTERING: bool = True  # 启用白名单过滤功能
    VERBOSE_LOGGING: bool = False

    # 性能配置
    BATCH_PROCESSING_SIZE: int = 1000
    BLOOM_FILTER_CAPACITY: int = 1000000
    BLOOM_FILTER_ERROR_RATE: float = 0.001


class UnifiedRuleParser:
    """统一规则解析器 - 基于语法数据库"""

    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.syntax_db = self.load_syntax_database()
        self.compiled_patterns = self.compile_patterns()
        self.platform_support = self.syntax_db.get("platform_support", {})
        
        # 增强AdGuard语法模式
        self.adguard_domain_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+[a-zA-Z0-9])\^?$')

    def load_syntax_database(self) -> Dict:
        """加载语法数据库"""
        if not self.config.SYNTAX_DB_FILE.exists():
            raise FileNotFoundError(f"找不到语法数据库: {self.config.SYNTAX_DB_FILE}")

        try:
            with open(self.config.SYNTAX_DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise RuntimeError(f"加载语法数据库失败: {e}")

    def compile_patterns(self) -> Dict[str, Pattern]:
        """预编译所有正则表达式模式"""
        compiled = {}
        patterns = self.syntax_db.get("syntax_patterns", {})

        for name, pattern_str in patterns.items():
            try:
                compiled[name] = re.compile(pattern_str)
            except re.error as e:
                logger.warning(f"无法编译模式 {name}: {e}")
                compiled[name] = re.compile(r".*")  # 匹配任何内容作为回退

        return compiled

    def parse_rule(self, rule: str) -> Dict[str, Any]:
        """解析单条规则"""
        result = {
            "original": rule,
            "type": "unknown",
            "pattern_type": "unknown",
            "content": "",
            "modifiers": [],
            "is_exception": rule.startswith("@@"),
            "is_comment": rule.startswith(("!", "#")),
            "is_valid": False,
            "domain": ""  # 新增：提取的纯净域名
        }

        if result["is_comment"] or not rule.strip():
            return result

        # 移除例外前缀
        rule_content = rule[2:] if result["is_exception"] else rule

        # 首先检查是否是AdGuard域名规则 (||domain^)
        adguard_match = self.adguard_domain_pattern.match(rule_content)
        if adguard_match:
            result["pattern_type"] = "adguard_domain_rule"
            result["type"] = "block"
            result["content"] = adguard_match.group(1)
            result["domain"] = self.extract_clean_domain(result["content"])
            result["is_valid"] = True
            return result

        # 使用数据库模式匹配规则类型
        for pattern_name, pattern in self.compiled_patterns.items():
            try:
                match = pattern.match(rule_content)
                if match:
                    result["pattern_type"] = pattern_name
                    result["type"] = self.syntax_db["rule_types"].get(pattern_name, "unknown")
                    result["is_valid"] = result["type"] not in ["invalid", "comment"]

                    # 提取规则内容
                    if match.lastindex and match.lastindex >= 1:
                        result["content"] = match.group(1)
                    else:
                        result["content"] = match.group(0)
                    
                    # 尝试提取域名
                    result["domain"] = self.extract_clean_domain(result["content"])
                    break
            except Exception as e:
                logger.debug(f"模式 {pattern_name} 匹配失败: {e}")
                continue

        # 如果未匹配任何模式，尝试基本解析
        if result["pattern_type"] == "unknown":
            if re.match(r"^[a-zA-Z0-9.*-]+$", rule_content):
                result["pattern_type"] = "domain_rule"
                result["type"] = "block"
                result["content"] = rule_content
                result["domain"] = self.extract_clean_domain(rule_content)
                result["is_valid"] = True

        # 增强修饰符提取
        if "$" in rule_content and result["is_valid"]:
            parts = rule_content.split("$", 1)
            result["content"] = parts[0].strip()

            modifiers = []
            for mod in parts[1].split(","):
                mod = mod.strip()
                if "=" in mod:
                    mod_name, mod_value = mod.split("=", 1)
                    modifiers.append((mod_name.strip(), mod_value.strip()))
                else:
                    modifiers.append((mod.strip(), None))

            result["modifiers"] = modifiers

        return result

    def extract_clean_domain(self, content: str) -> str:
        """从规则内容中提取纯净域名"""
        # 处理AdGuard格式 (||domain.com^)
        if content.startswith('||') and content.endswith('^'):
            return content[2:-1]
        
        # 处理包含通配符的域名
        domain = content.replace('*.', '').replace('*', '')
        
        # 移除其他特殊字符
        domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
        
        # 确保是有效域名格式
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return domain
        
        return content  # 如果无法提取纯净域名，返回原内容

    def is_supported_by_platform(self, rule_info: Dict[str, Any], platform: str) -> bool:
        """检查规则是否被特定平台支持"""
        if platform not in self.platform_support:
            return False

        platform_config = self.platform_support[platform]
        rule_type = rule_info["pattern_type"]

        # 检查规则类型支持
        supported_types = platform_config.get("supported_rule_types", [])
        unsupported_types = platform_config.get("unsupported_rule_types", [])

        if rule_type in unsupported_types:
            return False

        if supported_types and rule_type not in supported_types:
            return False

        # 检查修饰符支持
        unsupported_mods = platform_config.get("unsupported_modifiers", [])
        if any(mod[0] in unsupported_mods for mod in rule_info["modifiers"]):
            return False

        # 特殊处理
        if platform == "hosts" and rule_info["is_exception"]:
            return False

        if platform == "adguard_home" and rule_type in ["element_hiding_basic", "element_hiding_exception", 
                                                      "extended_css", "adguard_scriptlet"]:
            return False

        return True

    def convert_rule_for_platform(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """将规则转换为特定平台格式"""
        if not self.is_supported_by_platform(rule_info, platform):
            return None

        rule_type = rule_info["pattern_type"]
        content = rule_info["content"]
        domain = rule_info["domain"]
        is_exception = rule_info["is_exception"]

        # Clash平台转换 - 使用+.domain.com格式
        if platform == "clash":
            if rule_type in ["domain_rule", "adguard_domain_rule"] and domain:
                # Clash格式：+.domain.com
                return f"+.{domain}"
            return None

        # Surge平台转换 (DOMAIN-SET格式) - 使用.domain.com格式
        elif platform == "surge":
            if not is_exception and rule_type in ["domain_rule", "adguard_domain_rule"] and domain:
                # Surge DOMAIN-SET格式：.domain.com
                return f".{domain}"
            return None

        # Pi-hole转换
        elif platform == "pihole":
            if rule_type in ["domain_rule", "adguard_domain_rule"] and domain:
                return f"@@{domain}" if is_exception else domain
            elif rule_type == "hosts_rule":
                return rule_info["original"] if "0.0.0.0" in rule_info["original"] else f"0.0.0.0 {domain}"

        # Hosts文件转换
        elif platform == "hosts":
            if rule_type in ["domain_rule", "adguard_domain_rule"] and not is_exception and domain:
                return f"0.0.0.0 {domain}"
            elif rule_type == "hosts_rule" and not is_exception:
                return rule_info["original"]

        # uBlock Origin和AdBlock Plus保持原格式
        elif platform in ["ublock_origin", "adblock_plus"]:
            return rule_info["original"]

        return None


class WhitelistFilter:
    """白名单过滤器 - 专门用于Mihomo编译前的过滤"""
    
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.whitelist_domains = self.load_whitelist_domains()
        
    def load_whitelist_domains(self) -> Set[str]:
        """从allow文件加载白名单域名集合"""
        domains = set()
        
        # 从白名单文件加载域名
        if self.config.INPUT_ALLOW.exists():
            try:
                with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith(('!', '#')):
                            continue
                        
                        # 提取域名
                        domain = self.extract_domain_from_rule(line)
                        if domain:
                            domains.add(domain)
                            # 同时添加父域名
                            parts = domain.split('.')
                            if len(parts) > 2:
                                parent_domain = '.'.join(parts[-2:])
                                domains.add(parent_domain)
            except Exception as e:
                logger.warning(f"加载白名单文件失败: {e}")
        
        logger.info(f"白名单过滤器加载了 {len(domains)} 个域名")
        return domains
    
    def extract_domain_from_rule(self, rule: str) -> Optional[str]:
        """从规则中提取域名"""
        # 处理@@开头的例外规则
        if rule.startswith('@@'):
            rule = rule[2:]
        
        # 处理AdGuard域名规则 (||domain^)
        if rule.startswith('||') and rule.endswith('^'):
            return rule[2:-1]
        
        # 处理普通域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            # 移除通配符
            domain = rule.replace('*.', '').replace('*', '')
            if '.' in domain and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return domain
        
        return None
    
    def should_filter_domain(self, domain: str) -> bool:
        """检查域名是否应该被过滤（在白名单中）"""
        if not domain or '.' not in domain:
            return False
            
        # 检查完整域名
        if domain in self.whitelist_domains:
            return True
        
        # 检查父域名
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.whitelist_domains:
                return True
        
        return False
    
    def filter_block_rules(self, block_rules: List[str]) -> Tuple[List[str], int]:
        """过滤黑名单规则，移除误杀域名"""
        if not self.config.ENABLE_WHITELIST_FILTERING:
            return block_rules, 0
        
        filtered_rules = []
        filtered_count = 0
        
        for rule in block_rules:
            # 从Clash规则中提取域名 (+.domain.com)
            if rule.startswith('+.'):
                domain = rule[2:]  # 移除'+.'前缀
                if self.should_filter_domain(domain):
                    filtered_count += 1
                    if self.config.VERBOSE_LOGGING:
                        logger.debug(f"过滤误杀域名: {domain} (规则: {rule})")
                    continue
            
            filtered_rules.append(rule)
        
        if filtered_count > 0:
            logger.info(f"白名单过滤: 移除了 {filtered_count} 条可能误杀的规则")
        
        return filtered_rules, filtered_count


class UnifiedConverter:
    """统一规则转换器"""

    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.parser = UnifiedRuleParser(config)
        self.whitelist_filter = WhitelistFilter(config)
        self.stats = {
            "total_processed": 0,
            "platforms": {},
            "duplicates": 0,
            "unsupported": 0,
            "whitelist_filtered": 0,
            "mihomo_hashes": {}
        }

        # 初始化平台统计
        for platform in self.parser.platform_support.keys():
            self.stats["platforms"][platform] = {
                "block_rules": 0,
                "allow_rules": 0,
                "supported": 0,
                "unsupported": 0
            }

        # 初始化布隆过滤器和哈希表
        self.bloom_filter = None
        self.seen_rules = set()

        if self.config.ENABLE_BLOOM_FILTER and BLOOM_AVAILABLE:
            self.bloom_filter = BloomFilter(
                capacity=self.config.BLOOM_FILTER_CAPACITY,
                error_rate=self.config.BLOOM_FILTER_ERROR_RATE
            )
        elif self.config.ENABLE_DEDUPLICATION:
            logger.info("使用哈希表进行去重")

    def process_files(self) -> Dict[str, Dict[str, List[str]]]:
        """处理所有文件并生成多平台规则"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 初始化平台规则存储
        platform_rules = {}
        for platform in self.parser.platform_support.keys():
            platform_rules[platform] = {"block": [], "allow": []}

        # 处理黑名单文件
        if self.config.INPUT_BLOCK.exists():
            logger.info(f"处理黑名单文件: {self.config.INPUT_BLOCK}")
            self.process_single_file(self.config.INPUT_BLOCK, platform_rules, "block")
        else:
            logger.warning(f"黑名单文件不存在: {self.config.INPUT_BLOCK}")

        # 处理白名单文件
        if self.config.INPUT_ALLOW.exists():
            logger.info(f"处理白名单文件: {self.config.INPUT_ALLOW}")
            self.process_single_file(self.config.INPUT_ALLOW, platform_rules, "allow")
        else:
            logger.warning(f"白名单文件不存在: {self.config.INPUT_ALLOW}")

        # 去重处理
        if self.config.ENABLE_DEDUPLICATION:
            for platform in platform_rules.keys():
                for rule_type in ["block", "allow"]:
                    if platform == "hosts" and rule_type == "allow":
                        continue
                    if platform == "surge" and rule_type == "allow":
                        continue  # Surge不输出白名单

                    original_count = len(platform_rules[platform][rule_type])
                    platform_rules[platform][rule_type] = list(set(platform_rules[platform][rule_type]))
                    removed = original_count - len(platform_rules[platform][rule_type])
                    self.stats["duplicates"] += removed
                    logger.info(f"平台 {platform} {rule_type} 规则去重: 移除 {removed} 条重复规则")

        return platform_rules

    def process_single_file(self, file_path: Path, platform_rules: Dict, rule_class: str):
        """处理单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                line_count = 0
                for line in f:
                    line_count += 1
                    line = line.strip()
                    if not line:
                        continue

                    batch.append(line)

                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        self.process_batch(batch, platform_rules, rule_class)
                        batch = []

                if batch:
                    self.process_batch(batch, platform_rules, rule_class)

            logger.info(f"成功处理文件 {file_path}，共 {line_count} 行")

        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")
            import traceback
            logger.error(f"详细错误信息: {traceback.format_exc()}")

    def process_batch(self, batch: List[str], platform_rules: Dict, rule_class: str):
        """处理批量规则"""
        for rule in batch:
            try:
                self.stats["total_processed"] += 1

                # 双重去重检查
                if self.config.ENABLE_DEDUPLICATION:
                    if self.bloom_filter is not None and rule in self.bloom_filter:
                        if rule in self.seen_rules:
                            self.stats["duplicates"] += 1
                            continue

                    if self.bloom_filter is not None:
                        self.bloom_filter.add(rule)
                    self.seen_rules.add(rule)

                # 解析规则
                parsed = self.parser.parse_rule(rule)
                if not parsed["is_valid"]:
                    continue

                # 为每个平台转换规则
                for platform in self.parser.platform_support.keys():
                    # 特殊处理：Surge和hosts不处理白名单
                    if platform in ["surge", "hosts"] and rule_class == "allow":
                        continue

                    converted = self.parser.convert_rule_for_platform(parsed, platform)

                    if converted:
                        # 确保规则被正确分类
                        target_class = rule_class
                        if parsed["is_exception"]:
                            target_class = "allow"
                        else:
                            target_class = "block"

                        platform_rules[platform][target_class].append(converted)
                        self.stats["platforms"][platform]["supported"] += 1
                        self.stats["platforms"][platform][f"{target_class}_rules"] += 1
                    else:
                        self.stats["platforms"][platform]["unsupported"] += 1
                        self.stats["unsupported"] += 1
            except Exception as e:
                logger.error(f"处理规则时出错: {rule}, 错误: {e}")
                import traceback
                logger.error(f"详细错误信息: {traceback.format_exc()}")

    def save_results(self, platform_rules: Dict):
        """保存所有平台的规则"""
        logger.info("保存多平台规则文件...")

        # 保存所有平台规则
        for platform, rules in platform_rules.items():
            # Clash使用独立黑白名单输出
            if platform == "clash":
                # 保存黑名单
                if rules["block"]:
                    output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform]["block"]
                    content_with_header = ["#RULE-SET,ad-filter,REJECT", "payload:"] + [f"  - '{line}'" for line in rules["block"]]
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content_with_header))
                    logger.info(f"已保存 {platform} 黑名单规则: {output_file} ({len(rules['block'])} 条)")

                # 保存白名单
                if rules["allow"]:
                    output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform]["allow"]
                    content_with_header = ["#RULE-SET,ad-filter,DIRECT", "payload:"] + [f"  - '{line}'" for line in rules["allow"]]
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content_with_header))
                    logger.info(f"已保存 {platform} 白名单规则: {output_file} ({len(rules['allow'])} 条)")

            # Surge使用DOMAIN-SET格式，只输出黑名单
            elif platform == "surge":
                if rules["block"]:
                    output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform]["block"]
                    # Surge DOMAIN-SET格式：每行一个域名，前面加点
                    content_with_header = ["#DOMAIN-SET,ad-filter,REJECT"] + rules["block"]
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content_with_header))
                    logger.info(f"已保存 {platform} 黑名单规则: {output_file} ({len(rules['block'])} 条)")

            # 其他平台使用独立输出
            else:
                for rule_type in ["block", "allow"]:
                    if platform == "hosts" and rule_type == "allow":
                        continue
                    if platform == "surge" and rule_type == "allow":
                        continue

                    if rules[rule_type]:
                        output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform][rule_type]
                        with open(output_file, 'w', encoding='utf-8') as f:
                            f.write("\n".join(rules[rule_type]))

                        logger.info(f"已保存 {platform} {rule_type} 规则: {output_file} ({len(rules[rule_type])} 条)")

        # 编译Mihomo规则集（使用预处理过滤）
        if self.config.ENABLE_MIHOMO_COMPILATION:
            self.compile_mihomo_rules(platform_rules)

    def compile_mihomo_rules(self, platform_rules: Dict):
        """编译Mihomo规则集 - 使用allow文件过滤adblock文件"""
        if not self.config.MIHOMO_TOOL_PATH.exists():
            logger.warning("Mihomo工具不存在，跳过编译")
            return

        logger.info("编译Mihomo规则集...")

        try:
            # 1. 预处理：使用allow文件过滤黑名单规则
            # 注意：这里直接使用原始黑名单规则，而不是已经转换的Clash规则
            # 这样可以确保过滤逻辑更准确
            original_block_rules = self.load_original_block_rules()
            filtered_block_rules, filtered_count = self.filter_block_rules_with_allowlist(original_block_rules)
            self.stats["whitelist_filtered"] = filtered_count

            if not filtered_block_rules:
                logger.warning("过滤后没有剩余的黑名单规则，跳过Mihomo编译")
                return

            # 2. 将过滤后的规则转换为Clash格式
            clash_rules = self.convert_rules_to_clash_format(filtered_block_rules)

            # 3. 编译过滤后的黑名单（adb.mrs）
            mihomo_block_output = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["block"]

            # 创建临时的Clash格式黑名单文件，保持隐式格式
            temp_block_file = self.config.OUTPUT_DIR / "temp_block_clash.yaml"
            
            # 直接使用+.domain.com格式
            content_with_header = ["payload:"] + [f"  - '{rule}'" for rule in clash_rules]
            with open(temp_block_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(content_with_header))

            # Mihomo命令：输入格式为yaml，规则类型为domain
            cmd_block = [
                str(self.config.MIHOMO_TOOL_PATH),
                "convert-ruleset",
                "domain",
                "yaml",
                str(temp_block_file),
                str(mihomo_block_output)
            ]

            logger.info(f"执行黑名单编译命令: {' '.join(cmd_block)}")
            result = subprocess.run(cmd_block, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info(f"Mihomo黑名单编译成功: {mihomo_block_output}")
                
                # 计算并验证SHA256散列值
                sha256_hash = self.calculate_file_hash(mihomo_block_output)
                self.stats["mihomo_hashes"]["adb.mrs"] = sha256_hash
                logger.info(f"adb.mrs SHA256: {sha256_hash}")
                
                # 验证文件完整性
                if self.verify_mihomo_file(mihomo_block_output):
                    logger.info("✓ adb.mrs 文件完整性验证通过")
                else:
                    logger.warning("⚠ adb.mrs 文件可能损坏或为空")
            else:
                logger.error(f"adb.mrs编译失败，退出码: {result.returncode}")
                logger.error(f"标准错误: {result.stderr}")
                logger.error(f"标准输出: {result.stdout}")

            # 清理临时文件
            temp_block_file.unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            logger.error("Mihomo编译超时")
        except Exception as e:
            logger.error(f"Mihomo编译异常: {e}")
            import traceback
            logger.error(f"详细错误信息: {traceback.format_exc()}")

    def load_original_block_rules(self) -> List[str]:
        """加载原始黑名单规则"""
        rules = []
        if self.config.INPUT_BLOCK.exists():
            try:
                with open(self.config.INPUT_BLOCK, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith(('!', '#')):
                            rules.append(line)
            except Exception as e:
                logger.error(f"加载原始黑名单规则失败: {e}")
        return rules

    def filter_block_rules_with_allowlist(self, block_rules: List[str]) -> Tuple[List[str], int]:
        """使用allow文件过滤黑名单规则"""
        if not self.config.ENABLE_WHITELIST_FILTERING or not self.config.INPUT_ALLOW.exists():
            return block_rules, 0

        # 加载白名单域名
        allow_domains = set()
        try:
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(('!', '#')):
                        continue
                    
                    # 提取域名
                    domain = self.extract_domain_from_adguard_rule(line)
                    if domain:
                        allow_domains.add(domain)
        except Exception as e:
            logger.error(f"加载白名单文件失败: {e}")
            return block_rules, 0

        filtered_rules = []
        filtered_count = 0

        for rule in block_rules:
            # 提取规则中的域名
            rule_domain = self.extract_domain_from_adguard_rule(rule)
            
            # 如果规则域名在白名单中，则过滤掉
            if rule_domain and any(self.is_domain_match(rule_domain, allow_domain) for allow_domain in allow_domains):
                filtered_count += 1
                if self.config.VERBOSE_LOGGING:
                    logger.debug(f"过滤误杀规则: {rule} (匹配白名单)")
                continue
            
            filtered_rules.append(rule)

        if filtered_count > 0:
            logger.info(f"Mihomo编译前白名单过滤: 移除了 {filtered_count} 条可能误杀的规则")

        return filtered_rules, filtered_count

    def extract_domain_from_adguard_rule(self, rule: str) -> Optional[str]:
        """从AdGuard规则中提取域名"""
        # 处理@@开头的例外规则
        if rule.startswith('@@'):
            rule = rule[2:]
        
        # 处理AdGuard域名规则 (||domain^)
        if rule.startswith('||') and rule.endswith('^'):
            return rule[2:-1]
        
        # 处理普通域名规则
        if re.match(r'^[a-zA-Z0-9.*-]+$', rule):
            # 移除通配符
            domain = rule.replace('*.', '').replace('*', '')
            if '.' in domain and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return domain
        
        return None

    def is_domain_match(self, rule_domain: str, allow_domain: str) -> bool:
        """检查规则域名是否与白名单域名匹配"""
        # 精确匹配
        if rule_domain == allow_domain:
            return True
        
        # 子域名匹配：rule_domain是allow_domain的子域名
        if rule_domain.endswith('.' + allow_domain):
            return True
        
        # 通配符匹配：如果白名单域名包含通配符
        if '*' in allow_domain:
            # 将通配符转换为正则表达式
            pattern = allow_domain.replace('.', '\\.').replace('*', '.*')
            if re.match(f'^{pattern}$', rule_domain):
                return True
        
        return False

    def convert_rules_to_clash_format(self, rules: List[str]) -> List[str]:
        """将规则转换为Clash格式"""
        clash_rules = []
        parser = UnifiedRuleParser(self.config)
        
        for rule in rules:
            parsed = parser.parse_rule(rule)
            if parsed["is_valid"] and not parsed["is_exception"]:
                domain = parsed["domain"]
                if domain:
                    clash_rules.append(f"+.{domain}")
        
        return clash_rules

    def calculate_file_hash(self, file_path: Path) -> str:
        """计算文件的SHA256散列值"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # 分块读取以处理大文件
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算文件哈希失败: {e}")
            return "计算失败"

    def verify_mihomo_file(self, file_path: Path) -> bool:
        """验证Mihomo文件完整性"""
        try:
            if not file_path.exists():
                logger.error(f"文件不存在: {file_path}")
                return False
            
            file_size = file_path.stat().st_size
            if file_size == 0:
                logger.warning(f"文件为空: {file_path}")
                return False
            
            # 检查文件头（Mihomo规则集文件通常有特定格式）
            with open(file_path, 'rb') as f:
                header = f.read(100)  # 读取前100字节
            
            # 基本的二进制文件检查
            if len(header) < 10:
                logger.warning(f"文件过小: {file_path}")
                return False
            
            logger.info(f"Mihomo文件验证: {file_path} (大小: {file_size} 字节)")
            return True
            
        except Exception as e:
            logger.error(f"文件验证失败: {e}")
            return False

    def print_statistics(self):
        """打印转换统计信息"""
        logger.info("=" * 60)
        logger.info("规则转换统计")
        logger.info("=" * 60)
        logger.info(f"总共处理规则: {self.stats['total_processed']}")
        logger.info(f"重复规则移除: {self.stats['duplicates']}")
        logger.info(f"不支持规则: {self.stats['unsupported']}")
        logger.info(f"Mihomo白名单过滤规则: {self.stats['whitelist_filtered']}")

        for platform, stats in self.stats['platforms'].items():
            logger.info(f"{platform.upper()} - 支持规则: {stats['supported']}, 不支持规则: {stats['unsupported']}")
            if platform not in ["hosts", "surge"]:
                logger.info(f"  - 拦截规则: {stats['block_rules']}, 放行规则: {stats['allow_rules']}")
            else:
                logger.info(f"  - 拦截规则: {stats['block_rules']}")

        # 打印Mihomo文件哈希验证结果
        if self.stats['mihomo_hashes']:
            logger.info("=" * 40)
            logger.info("Mihomo规则集文件验证")
            logger.info("=" * 40)
            for filename, hash_value in self.stats['mihomo_hashes'].items():
                logger.info(f"{filename}: {hash_value}")
            
            # 总体验证状态
            all_valid = all(self.verify_mihomo_file(self.config.OUTPUT_DIR / filename) 
                          for filename in self.stats['mihomo_hashes'].keys())
            
            if all_valid:
                logger.info("✓ 所有Mihomo规则集文件验证通过")
            else:
                logger.warning("⚠ 部分Mihomo规则集文件验证失败")


def main():
    """主函数"""
    try:
        config = UnifiedConfig()
        converter = UnifiedConverter(config)

        logger.info("开始规则转换...")
        platform_rules = converter.process_files()

        logger.info("保存转换结果并编译Mihomo规则集...")
        converter.save_results(platform_rules)

        converter.print_statistics()
        logger.info("规则转换及Mihomo编译完成!")

    except Exception as e:
        logger.error(f"规则转换失败: {e}")
        import traceback
        logger.error(f"详细错误信息: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()