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

    # 输出文件配置 - 直接输出到GitHub根目录
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {
            "block": "adblock_clash.yaml",
            "allow": "allow_clash.yaml"
        },
        "surge": {
            "block": "adblock_surge.conf",
            "allow": "allow_surge.conf"
        },
        "pihole": {
            "block": "adblock_pihole.txt",
            "allow": "allow_pihole.txt"
        },
        "ublock_origin": {
            "block": "adblock_ubo.txt",
            "allow": "allow_ubo.txt"
        },
        "adblock_plus": {
            "block": "adblock_abp.txt",
            "allow": "allow_abp.txt"
        },
        "hosts": {
            "block": "hosts.txt"
        },
        "mihomo_source": {
            "block": "adblock_clash_for_mihomo.yaml",
            "allow": "allow_clash_for_mihomo.yaml"
        },
        "mihomo_output": {
            "block": "adb.mrs",
            "allow": "allow.mrs"
        }
    })

    # 功能开关
    ENABLE_MIHOMO_COMPILATION: bool = True
    ENABLE_DEDUPLICATION: bool = True
    ENABLE_BLOOM_FILTER: bool = BLOOM_AVAILABLE
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
            "is_valid": False
        }

        if result["is_comment"] or not rule.strip():
            return result

        # 移除例外前缀
        rule_content = rule[2:] if result["is_exception"] else rule

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

        platform_config = self.platform_support.get(platform, {})
        rule_format = platform_config.get("rule_format", {})
        rule_type = rule_info["pattern_type"]
        content = rule_info["content"]
        original_rule = rule_info["original"]
        is_exception = rule_info["is_exception"]

        # 确定动作
        action = "DIRECT" if is_exception else "REJECT"

        # 应用平台特定转换规则
        if rule_type in rule_format:
            format_str = rule_format[rule_type]
            format_params = {
                'domain': content,
                'pattern': content,
                'action': action,
                'rule': original_rule
            }

            try:
                return format_str.format(**format_params)
            except KeyError as e:
                logger.warning(f"格式化字符串缺少键 {e}，使用原始规则: {original_rule}")
                return original_rule

        # 默认转换逻辑
        if platform in ["clash", "surge"]:
            if rule_type == "domain_rule":
                if content.startswith('*.'):
                    base_domain = content[2:]
                    return f"DOMAIN-SUFFIX,{base_domain},{action}"
                else:
                    return f"DOMAIN-SUFFIX,{content},{action}"
            elif rule_type == "regex_rule":
                if platform == "clash":
                    return f"DOMAIN-KEYWORD,{content},{action}"
                else:
                    return f"URL-REGEX,{content},{action}"

        elif platform == "pihole":
            if rule_type == "domain_rule":
                return f"@@{content}" if is_exception else content
            elif rule_type == "hosts_rule":
                return original_rule if "0.0.0.0" in original_rule else f"0.0.0.0 {content}"

        elif platform == "hosts":
            if rule_type == "domain_rule":
                return f"0.0.0.0 {content}"
            elif rule_type == "hosts_rule":
                return original_rule

        # uBlock Origin和AdBlock Plus保持原格式，但过滤不支持的修饰符
        elif platform in ["ublock_origin", "adblock_plus"]:
            unsupported_mods = platform_config.get("unsupported_modifiers", [])
            for mod in unsupported_mods:
                if f"${mod}" in original_rule:
                    if "$" in original_rule:
                        parts = original_rule.split("$", 1)
                        return parts[0].strip()
                    break
            return original_rule

        return None


class UnifiedConverter:
    """统一规则转换器"""

    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.parser = UnifiedRuleParser(config)
        self.stats = {
            "total_processed": 0,
            "platforms": {},
            "duplicates": 0,
            "unsupported": 0
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
                    if platform == "hosts" and rule_class == "allow":
                        continue

                    converted = self.parser.convert_rule_for_platform(parsed, platform)

                    if converted:
                        platform_rules[platform][rule_class].append(converted)
                        self.stats["platforms"][platform]["supported"] += 1
                        self.stats["platforms"][platform][f"{rule_class}_rules"] += 1
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

        # 首先保存常规Clash规则文件（带payload头）
        for platform, rules in platform_rules.items():
            for rule_type in ["block", "allow"]:
                if platform == "hosts" and rule_type == "allow":
                    continue
                if not rules[rule_type]:
                    continue

                output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform][rule_type]
                content = rules[rule_type]

                if platform == "clash":
                    content_with_header = ["payload:"] + content
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content_with_header))
                else:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content))

                logger.info(f"已保存 {platform} {rule_type} 规则: {output_file} ({len(rules[rule_type])} 条)")

        # 为Mihomo编译源生成文件（也带payload头）
        if "clash" in platform_rules and "block" in platform_rules["clash"]:
            clash_block_rules = platform_rules["clash"]["block"]
            mihomo_source_block_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["block"]
            
            valid_rules = [rule for rule in clash_block_rules if rule.strip()]
            content_with_header = ["payload:"] + valid_rules
            
            with open(mihomo_source_block_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(content_with_header))
            
            logger.info(f"已保存 Mihomo 编译源黑名单规则: {mihomo_source_block_file} ({len(valid_rules)} 条)")

        if "clash" in platform_rules and "allow" in platform_rules["clash"] and platform_rules["clash"]["allow"]:
            clash_allow_rules = platform_rules["clash"]["allow"]
            mihomo_source_allow_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["allow"]
            
            valid_rules = [rule for rule in clash_allow_rules if rule.strip()]
            content_with_header = ["payload:"] + valid_rules
            
            with open(mihomo_source_allow_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(content_with_header))
            
            logger.info(f"已保存 Mihomo 编译源白名单规则: {mihomo_source_allow_file} ({len(valid_rules)} 条)")

        # 编译Mihomo规则集
        if self.config.ENABLE_MIHOMO_COMPILATION:
            self.compile_mihomo_rules()

    def compile_mihomo_rules(self):
        """编译Mihomo规则集"""
        if not self.config.MIHOMO_TOOL_PATH.exists():
            logger.warning("Mihomo工具不存在，跳过编译")
            return

        logger.info("编译Mihomo规则集...")

        try:
            # 编译黑名单
            mihomo_source_block = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["block"]
            if not mihomo_source_block.exists() or mihomo_source_block.stat().st_size == 0:
                logger.warning("Mihomo源黑名单文件不存在或为空，跳过Mihomo编译")
                return

            mihomo_block = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["block"]

            cmd = [
                str(self.config.MIHOMO_TOOL_PATH),
                "convert-ruleset",
                "domain",
                "yaml",
                str(mihomo_source_block),
                str(mihomo_block)
            ]

            logger.info(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info(f"Mihomo黑名单编译成功: {mihomo_block}")
            else:
                logger.error(f"Mihomo黑名单编译失败，退出码: {result.returncode}")
                logger.error(f"标准错误: {result.stderr}")
                logger.error(f"标准输出: {result.stdout}")

            # 编译白名单
            mihomo_source_allow = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["allow"]
            if mihomo_source_allow.exists() and mihomo_source_allow.stat().st_size > 0:
                mihomo_allow = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["allow"]

                cmd = [
                    str(self.config.MIHOMO_TOOL_PATH),
                    "convert-ruleset",
                    "domain",
                    "yaml",
                    str(mihomo_source_allow),
                    str(mihomo_allow)
                ]

                logger.info(f"执行命令: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0:
                    logger.info(f"Mihomo白名单编译成功: {mihomo_allow}")
                else:
                    logger.error(f"Mihomo白名单编译失败，退出码: {result.returncode}")
                    logger.error(f"标准错误: {result.stderr}")
                    logger.error(f"标准输出: {result.stdout}")
            else:
                logger.warning("Mihomo源白名单文件不存在或为空，跳过Mihomo白名单编译")

        except subprocess.TimeoutExpired:
            logger.error("Mihomo编译超时")
        except Exception as e:
            logger.error(f"Mihomo编译异常: {e}")
            import traceback
            logger.error(f"详细错误信息: {traceback.format_exc()}")

    def print_statistics(self):
        """打印转换统计信息"""
        logger.info("=" * 50)
        logger.info("规则转换统计")
        logger.info("=" * 50)
        logger.info(f"总共处理规则: {self.stats['total_processed']}")
        logger.info(f"重复规则移除: {self.stats['duplicates']}")
        logger.info(f"不支持规则: {self.stats['unsupported']}")

        for platform, stats in self.stats['platforms'].items():
            logger.info(f"{platform.upper()} - 支持规则: {stats['supported']}, 不支持规则: {stats['unsupported']}")
            if platform != "hosts":
                logger.info(f"  - 拦截规则: {stats['block_rules']}, 放行规则: {stats['allow_rules']}")
            else:
                logger.info(f"  - 拦截规则: {stats['block_rules']}")


def main():
    """主函数"""
    try:
        config = UnifiedConfig()
        converter = UnifiedConverter(config)

        logger.info("开始规则转换...")
        platform_rules = converter.process_files()

        logger.info("保存转换结果...")
        converter.save_results(platform_rules)

        converter.print_statistics()
        logger.info("规则转换完成!")

    except Exception as e:
        logger.error(f"规则转换失败: {e}")
        import traceback
        logger.error(f"详细错误信息: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()