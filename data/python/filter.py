#!/usr/bin/env python3
"""
增强版统一规则转换器 - 支持AdGuard到多平台规则转换（纯净规则版）
支持平台：Clash, Surge, Mihomo, Pi-hole, uBlock Origin, Adblock Plus, Hosts文件
核心逻辑：仅Mihomo黑名单执行白名单过滤（防止误杀），其他平台保持原始黑白名单独立逻辑
输出特性：无文件头元信息，仅含纯净规则；按语法数据库补充Clash/Surge规则集头与动作
"""

import os
import re
import json
import sys
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Pattern
from dataclasses import dataclass, field
import logging
from datetime import datetime

# --------------------------
# 全局常量（统一管理，便于维护）
# --------------------------
CLASH_BLOCK_PREFIX = "+."
CLASH_ALLOW_PREFIX = "-."
SURGE_DOMAIN_PREFIX = "."
HOSTS_BLOCK_TEMPLATE = "0.0.0.0 {domain}"
MAX_RULE_LENGTH = 2000  # 基于语法数据库validation_rules
MIN_RULE_LENGTH = 3     # 基于语法数据库validation_rules
VALID_DOMAIN_CHARS = re.compile(r'^[a-zA-Z0-9.-]+$')

# --------------------------
# 日志配置（支持详细模式，便于调试）
# --------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# --------------------------
# 通用工具类（消除冗余逻辑）
# --------------------------
class Utils:
    @staticmethod
    def extract_domain_from_adguard_rule(rule: str) -> Optional[str]:
        """从AdGuard规则提取并标准化域名"""
        if not rule or len(rule) < MIN_RULE_LENGTH:
            return None
        
        # 处理例外前缀
        clean_rule = rule[2:] if rule.startswith('@@') else rule
        
        # 匹配AdGuard标准格式（||domain^）
        adg_match = re.match(r'^\|\|([a-zA-Z0-9.*-]+[a-zA-Z0-9])\^?$', clean_rule)
        if adg_match:
            domain = adg_match.group(1)
            return Utils.normalize_domain(domain)
        
        # 匹配普通域名
        if VALID_DOMAIN_CHARS.match(clean_rule):
            domain = clean_rule.replace('*.', '').replace('*', '')
            return Utils.normalize_domain(domain) if '.' in domain else None
        
        return None

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """域名标准化：转小写、去通配符、去尾部点"""
        if not domain:
            return ""
        return domain.lower().replace('*.', '').replace('*', '').rstrip('.')

    @staticmethod
    def is_valid_rule(rule: str) -> bool:
        """规则有效性校验：排除注释、空行、长度异常"""
        rule_stripped = rule.strip()
        if not rule_stripped or rule_stripped.startswith(('!', '#', '\n', '\r')):
            return False
        if len(rule_stripped) < MIN_RULE_LENGTH or len(rule_stripped) > MAX_RULE_LENGTH:
            logger.debug(f"无效规则（长度异常）：{rule_stripped}")
            return False
        return True

    @staticmethod
    def calculate_file_hash(file_path: Path) -> str:
        """计算文件SHA256哈希"""
        if not file_path.exists() or file_path.is_dir():
            logger.error(f"哈希计算失败：{file_path} 不是有效文件")
            return "invalid_file"
        
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算{file_path}哈希出错：{str(e)[:30]}")
            return f"error:{str(e)[:20]}"

    @staticmethod
    def verify_file_integrity(file_path: Path) -> bool:
        """验证文件完整性：存在性、非空、最小大小"""
        if not file_path.exists():
            logger.error(f"文件不存在：{file_path}")
            return False
        
        file_size = file_path.stat().st_size
        if file_size == 0:
            logger.warning(f"空文件：{file_path}")
            return False
        if file_size < 10:
            logger.warning(f"文件过小（{file_size}字节）：{file_path}")
            return False
        
        logger.debug(f"文件验证通过：{file_path}（{file_size}字节）")
        return True

# --------------------------
# 配置类（集中管理路径与开关）
# --------------------------
@dataclass
class UnifiedConfig:
    # 基础路径
    BASE_DIR: Path = Path(os.getenv('GITHUB_WORKSPACE', Path.cwd()))
    
    # 输入文件
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"
    
    # 输出配置
    OUTPUT_DIR: Path = BASE_DIR
    OUTPUT_FILES: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        "clash": {"block": "adblock_clash.yaml", "allow": "allow_clash.yaml"},
        "surge": {"block": "adblock_surge.txt"},
        "pihole": {"block": "adblock_pihole.txt", "allow": "allow_pihole.txt"},
        "ublock_origin": {"block": "adblock_ubo.txt", "allow": "allow_ubo.txt"},
        "adblock_plus": {"block": "adblock_abp.txt", "allow": "allow_abp.txt"},
        "hosts": {"block": "hosts.txt"},
        "mihomo_output": {"block": "adb.mrs"}
    })
    
    # 语法数据库路径（多路径 fallback）
    SYNTAX_DB_FILES: List[Path] = field(default_factory=lambda: [
        Path("data/python/adblock_syntax_db.json"),
        Path("adblock_syntax_db.json"),
        Path(__file__).parent / "adblock_syntax_db.json"
    ])
    
    # Mihomo工具路径
    MIHOMO_TOOL_PATH: Path = BASE_DIR / "data/mihomo-tool"
    
    # 功能开关（支持环境变量控制）
    ENABLE_MIHOMO_COMPILATION: bool = os.getenv('ENABLE_MIHOMO', 'true').lower() == 'true'
    ENABLE_DEDUPLICATION: bool = os.getenv('ENABLE_DEDUPE', 'true').lower() == 'true'
    ENABLE_WHITELIST_FILTERING: bool = os.getenv('ENABLE_WHITELIST', 'true').lower() == 'true'
    VERBOSE_LOGGING: bool = os.getenv('VERBOSE_LOGGING', 'false').lower() == 'true'
    
    # 性能配置
    BATCH_PROCESSING_SIZE: int = 1000
    BLOOM_FILTER_CAPACITY: int = 1_000_000
    BLOOM_FILTER_ERROR_RATE: float = 0.001
    
    # CI环境标识
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    GITHUB_REPOSITORY: str = os.getenv('GITHUB_REPOSITORY', 'unknown/repo')
    GITHUB_SHA: str = os.getenv('GITHUB_SHA', 'unknown')

    def get_syntax_db_path(self) -> Optional[Path]:
        """获取有效语法数据库路径"""
        for path in self.SYNTAX_DB_FILES:
            full_path = self.BASE_DIR / path if not path.is_absolute() else path
            if full_path.exists() and full_path.is_file():
                return full_path
        return None

# --------------------------
# 白名单过滤器（仅服务于Mihomo）
# --------------------------
class WhitelistFilter:
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.whitelist_domains: Set[str] = self._load_whitelist()
        logger.info(f"白名单加载完成：共{len(self.whitelist_domains)}个域名")

    def _load_whitelist(self) -> Set[str]:
        """加载并标准化白名单域名"""
        domains = set()
        if not self.config.INPUT_ALLOW.exists():
            logger.warning(f"白名单文件不存在：{self.config.INPUT_ALLOW}")
            return domains
        
        try:
            with open(self.config.INPUT_ALLOW, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not Utils.is_valid_rule(line):
                        continue
                    
                    domain = Utils.extract_domain_from_adguard_rule(line)
                    if domain:
                        domains.add(domain)
        except Exception as e:
            logger.error(f"加载白名单失败：{e}")
        
        return domains

    def filter_block_rules(self, block_rules: List[str]) -> Tuple[List[str], int]:
        """过滤黑名单规则（仅Mihomo使用）：移除匹配白名单的规则"""
        if not self.config.ENABLE_WHITELIST_FILTERING or not self.whitelist_domains:
            return block_rules, 0
        
        filtered = []
        filtered_count = 0
        
        for rule in block_rules:
            # 提取规则中的域名（处理Clash格式：+.domain → domain）
            rule_domain = Utils.extract_domain_from_adguard_rule(rule.lstrip(CLASH_BLOCK_PREFIX))
            if not rule_domain:
                filtered.append(rule)
                continue
            
            # 检查域名是否在白名单（含子域名匹配）
            if self._is_domain_in_whitelist(rule_domain):
                filtered_count += 1
                logger.debug(f"Mihomo白名单过滤规则：{rule}（匹配域名：{rule_domain}）")
                continue
            
            filtered.append(rule)
        
        return filtered, filtered_count

    def _is_domain_in_whitelist(self, domain: str) -> bool:
        """检查域名是否在白名单（支持子域名匹配）"""
        if domain in self.whitelist_domains:
            return True
        # 匹配子域名（如sub.abc.com → abc.com）
        parts = domain.split('.')
        for i in range(1, len(parts)-1):  # 避免匹配顶级域名
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.whitelist_domains:
                return True
        return False

# --------------------------
# 规则解析器（基于语法数据库）
# --------------------------
class UnifiedRuleParser:
    def __init__(self, config: UnifiedConfig, syntax_db: Dict):
        self.config = config
        self.syntax_db = syntax_db
        self.platform_support = self.syntax_db.get("platform_support", {})
        self.compiled_patterns: Dict[str, Pattern] = self._compile_patterns()
        self.adg_modifier_pattern = re.compile(r'\$([a-zA-Z-]+)(?:=([^,\s]+))?(?:,|$)')

    def _compile_patterns(self) -> Dict[str, Pattern]:
        """预编译语法数据库中的正则"""
        compiled = {}
        patterns = self.syntax_db.get("syntax_patterns", {})
        
        for name, pattern_str in patterns.items():
            if name == "comment":
                continue
            
            try:
                # 为域名规则添加行首匹配
                if name.endswith('_rule') and not pattern_str.startswith('^'):
                    pattern_str = '^' + pattern_str
                compiled[name] = re.compile(pattern_str, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"编译正则失败（{name}）：{e}，使用宽松匹配")
                compiled[name] = re.compile(r'.*')
        
        logger.info(f"成功编译{len(compiled)}个语法模式")
        return compiled

    def parse_rule(self, rule: str) -> Dict[str, Any]:
        """解析单条规则，返回结构化信息"""
        result = {
            "original": rule,
            "type": "unknown",
            "pattern_type": "unknown",
            "content": "",
            "domain": "",
            "modifiers": [],
            "is_exception": rule.startswith("@@"),
            "is_comment": rule.startswith(('!', '#')),
            "is_valid": False
        }

        # 处理注释/空行
        if result["is_comment"] or not Utils.is_valid_rule(rule):
            result["type"] = "comment" if result["is_comment"] else "invalid"
            return result

        # 移除例外前缀
        clean_rule = rule[2:] if result["is_exception"] else rule
        result["is_valid"] = True

        # 优先解析AdGuard标准域名规则
        adg_domain_match = re.match(r'^\|\|([a-zA-Z0-9.*-]+[a-zA-Z0-9])\^?$', clean_rule)
        if adg_domain_match:
            result["pattern_type"] = "adguard_domain_rule"
            result["type"] = "block"
            result["content"] = adg_domain_match.group(1)
            result["domain"] = Utils.normalize_domain(result["content"])
            self._extract_modifiers(clean_rule, result)
            return result

        # 基于语法数据库匹配其他规则类型
        for pattern_name, pattern in self.compiled_patterns.items():
            match = pattern.match(clean_rule)
            if not match:
                continue
            
            result["pattern_type"] = pattern_name
            result["type"] = self.syntax_db["rule_types"].get(pattern_name, "block")
            result["content"] = match.group(1) if match.lastindex else match.group(0)
            
            # 提取域名（仅域名类规则）
            if pattern_name in ["domain_rule", "adguard_domain_rule", "pihole_domain"]:
                result["domain"] = Utils.normalize_domain(result["content"])
            
            self._extract_modifiers(clean_rule, result)
            break

        # 兜底处理未知规则
        if result["pattern_type"] == "unknown":
            result["pattern_type"] = "generic_rule"
            result["type"] = "block"
            result["content"] = clean_rule
            result["domain"] = Utils.extract_domain_from_adguard_rule(clean_rule) or ""

        return result

    def _extract_modifiers(self, rule: str, result: Dict[str, Any]) -> None:
        """提取规则中的修饰符"""
        if '$' not in rule:
            return
        
        modifiers = self.adg_modifier_pattern.findall(rule)
        for mod_name, mod_value in modifiers:
            if not mod_name:
                continue
            result["modifiers"].append((mod_name.lower(), mod_value.strip() if mod_value else None))

    def is_supported_by_platform(self, rule_info: Dict[str, Any], platform: str) -> bool:
        """检查规则是否支持指定平台"""
        if platform not in self.platform_support:
            logger.debug(f"平台{platform}未在语法数据库中定义")
            return False
        
        platform_cfg = self.platform_support[platform]
        rule_type = rule_info["pattern_type"]
        modifiers = [mod[0] for mod in rule_info["modifiers"]]

        # 检查规则类型支持
        supported_types = platform_cfg.get("supported_rule_types", [])
        unsupported_types = platform_cfg.get("unsupported_rule_types", [])
        if rule_type in unsupported_types or (supported_types and rule_type not in supported_types):
            return False

        # 检查修饰符支持
        unsupported_mods = platform_cfg.get("unsupported_modifiers", [])
        special_mods = platform_cfg.get("special_modifiers", [])
        for mod in modifiers:
            if mod in unsupported_mods and mod not in special_mods:
                logger.debug(f"平台{platform}不支持修饰符{mod}：{rule_info['original']}")
                return False

        # 平台特殊限制
        if platform == "hosts" and rule_info["is_exception"]:
            return False
        if platform == "surge" and rule_info["is_exception"]:
            return False

        return True

    def convert_to_platform(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """将规则转换为指定平台格式"""
        if not self.is_supported_by_platform(rule_info, platform):
            return None
        
        platform_cfg = self.platform_support[platform]
        rule_type = rule_info["pattern_type"]
        rule_format = platform_cfg.get("rule_format", {}).get(rule_type)

        # 优先使用语法数据库定义的格式
        if rule_format:
            format_params = {
                'domain': rule_info["domain"] or rule_info["content"],
                'pattern': rule_info["content"],
                'rule': rule_info["original"],
                'name': self._get_ruleset_name(platform, rule_info["is_exception"])
            }
            try:
                converted = rule_format.format(**format_params)
                return self._adjust_platform_specific(converted, rule_info, platform)
            except KeyError as e:
                logger.warning(f"格式填充失败（{rule_type}）：缺少键{e}，使用原始规则")

        # 兜底转换逻辑
        return self._fallback_conversion(rule_info, platform)

    def _get_ruleset_name(self, platform: str, is_exception: bool) -> str:
        """根据平台和规则类型获取规则集名称（匹配输出文件名）"""
        if platform == "clash":
            return "allow_clash" if is_exception else "adblock_clash"
        elif platform == "surge":
            return "allow_surge" if is_exception else "adblock_surge"
        return "default_ruleset"

    def _adjust_platform_specific(self, rule: str, rule_info: Dict[str, Any], platform: str) -> str:
        """平台特定调整（如例外规则前缀）"""
        if not rule_info["is_exception"]:
            return rule
        
        if platform in ["ublock_origin", "adblock_plus"]:
            if rule_info["pattern_type"].startswith("element_hiding"):
                return rule.replace("##", "#@#")
            return f"@@{rule}"
        
        if platform == "pihole":
            return f"@@{rule}"
        
        return rule

    def _fallback_conversion(self, rule_info: Dict[str, Any], platform: str) -> Optional[str]:
        """兜底转换逻辑"""
        domain = rule_info["domain"]
        is_exception = rule_info["is_exception"]

        if not domain:
            return rule_info["original"] if rule_info["is_valid"] else None

        conversions = {
            "clash": f"{CLASH_ALLOW_PREFIX}{domain}" if is_exception else f"{CLASH_BLOCK_PREFIX}{domain}",
            "surge": f"{SURGE_DOMAIN_PREFIX}{domain}" if not is_exception else None,
            "pihole": f"@@{domain}" if is_exception else domain,
            "hosts": HOSTS_BLOCK_TEMPLATE.format(domain=domain) if not is_exception else None,
            "ublock_origin": f"@@||{domain}^" if is_exception else f"||{domain}^",
            "adblock_plus": f"@@||{domain}^" if is_exception else f"||{domain}^"
        }

        return conversions.get(platform)

# --------------------------
# 主转换器（协调所有流程）
# --------------------------
class UnifiedConverter:
    def __init__(self, config: UnifiedConfig):
        self.config = config
        self.syntax_db = self._load_syntax_db()
        self.parser = UnifiedRuleParser(config, self.syntax_db)
        self.whitelist_filter = WhitelistFilter(config)  # 仅服务于Mihomo
        self.bloom_filter = self._init_bloom_filter()
        self.seen_rules: Set[str] = set()
        self.stats = self._init_stats()

    def _load_syntax_db(self) -> Dict:
        """加载语法数据库"""
        db_path = self.config.get_syntax_db_path()
        if not db_path:
            raise FileNotFoundError(f"未找到语法数据库，尝试路径：{self.config.SYNTAX_DB_FILES}")
        
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                db = json.load(f)
            # 验证数据库完整性
            required_fields = db.get("integrity_checks", {}).get("required_fields", [
                "version", "syntax_patterns", "rule_types", "platform_support"
            ])
            missing_fields = [f for f in required_fields if f not in db]
            if missing_fields:
                raise ValueError(f"语法数据库缺少必要字段：{missing_fields}")
            
            logger.info(f"成功加载语法数据库（版本：{db.get('version', 'unknown')}）：{db_path}")
            return db
        except Exception as e:
            raise RuntimeError(f"加载语法数据库失败：{e}") from e

    def _init_bloom_filter(self) -> Optional[Any]:
        """初始化布隆过滤器（用于去重）"""
        if not self.config.ENABLE_DEDUPLICATION:
            logger.info("去重功能已禁用，不初始化布隆过滤器")
            return None
        
        try:
            from pybloom_live import BloomFilter
            bf = BloomFilter(
                capacity=self.config.BLOOM_FILTER_CAPACITY,
                error_rate=self.config.BLOOM_FILTER_ERROR_RATE
            )
            logger.info("使用布隆过滤器进行去重")
            return bf
        except ImportError:
            logger.warning("pybloom_live未安装，仅使用集合去重（性能可能下降）")
            return None

    def _init_stats(self) -> Dict[str, Any]:
        """初始化统计信息（核心修复：将block_rules/allow_rules改为block/allow）"""
        platform_stats = {}
        for platform in self.parser.platform_support.keys():
            platform_stats[platform] = {
                "block": 0, "allow": 0, "supported": 0, 
                "unsupported": 0, "adguard_converted": 0
            }
        
        return {
            "total_processed": 0, "original_counts": {"block": 0, "allow": 0},
            "duplicates": 0, "unsupported": 0, "mihomo_whitelist_filtered": 0,
            "mihomo_hashes": {}, "adguard_specific_rules": 0,
            "platforms": platform_stats
        }

    def run(self) -> None:
        """主流程：加载→转换→保存→Mihomo编译→统计"""
        try:
            # 1. 初始化平台规则存储
            platform_rules = self._init_platform_rules()
            
            # 2. 处理输入文件（黑白名单独立转换，无交叉过滤）
            self._process_input_file(self.config.INPUT_BLOCK, platform_rules, "block")
            self._process_input_file(self.config.INPUT_ALLOW, platform_rules, "allow")
            
            # 3. 全平台规则去重
            platform_rules = self._deduplicate_rules(platform_rules)
            
            # 4. 保存所有平台产物（Mihomo除外）
            self._save_platform_rules(platform_rules)
            
            # 5. 单独处理Mihomo：提取→过滤→编译
            if self.config.ENABLE_MIHOMO_COMPILATION:
                self._compile_mihomo_with_whitelist(platform_rules)
            
            # 6. 输出统计
            self._print_stats()
            logger.info("规则转换流程全部完成！")
        except Exception as e:
            logger.error(f"转换流程失败：{e}", exc_info=True)
            sys.exit(1)

    def _init_platform_rules(self) -> Dict[str, Dict[str, List[str]]]:
        """初始化平台规则存储结构"""
        return {
            platform: {"block": [], "allow": []} 
            for platform in self.parser.platform_support.keys()
        }

    def _process_input_file(self, file_path: Path, platform_rules: Dict, rule_class: str) -> None:
        """处理单个输入文件（批量解析+转换）"""
        if not file_path.exists():
            logger.warning(f"跳过不存在的文件：{file_path}")
            return
        
        logger.info(f"开始处理文件：{file_path}（规则类型：{rule_class}）")
        batch: List[str] = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                self.stats["total_processed"] += 1
                
                # 统计原始有效规则数
                if Utils.is_valid_rule(line):
                    self.stats["original_counts"][rule_class] += 1
                
                # 批量处理
                batch.append(line)
                if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                    self._process_batch(batch, platform_rules, rule_class, line_num - len(batch) + 1)
                    batch = []
            
            # 处理剩余批次
            if batch:
                self._process_batch(batch, platform_rules, rule_class, len(f.readlines()) - len(batch) + 1)

    def _process_batch(self, batch: List[str], platform_rules: Dict, rule_class: str, start_line: int) -> None:
        """批量处理规则（提升性能）"""
        for idx, line in enumerate(batch):
            line_num = start_line + idx
            if not Utils.is_valid_rule(line) or line.startswith(('!', '#')):
                continue
            
            # 去重检查
            if self._is_duplicate_rule(line):
                self.stats["duplicates"] += 1
                continue
            
            # 解析规则
            parsed = self.parser.parse_rule(line)
            if not parsed["is_valid"]:
                self.stats["unsupported"] += 1
                logger.debug(f"无效规则（行{line_num}）：{line}")
                continue
            
            # 统计AdGuard特定规则
            if parsed["pattern_type"].startswith("adguard_"):
                self.stats["adguard_specific_rules"] += 1
            
            # 转换到各平台
            target_class = "allow" if parsed["is_exception"] or rule_class == "allow" else "block"
            for platform in platform_rules.keys():
                # 跳过不支持例外规则的平台
                if target_class == "allow" and platform in ["hosts", "surge"]:
                    continue
                
                converted = self.parser.convert_to_platform(parsed, platform)
                if not converted:
                    self.stats["platforms"][platform]["unsupported"] += 1
                    continue
                
                # 保存转换后的规则
                platform_rules[platform][target_class].append(converted)
                self.stats["platforms"][platform][target_class] += 1
                self.stats["platforms"][platform]["supported"] += 1
                
                # 统计AdGuard规则转换数
                if parsed["pattern_type"].startswith("adguard_"):
                    self.stats["platforms"][platform]["adguard_converted"] += 1

    def _is_duplicate_rule(self, rule: str) -> bool:
        """检查规则是否重复（布隆过滤器+集合双重校验）"""
        if not self.config.ENABLE_DEDUPLICATION:
            return False
        
        if self.bloom_filter and rule in self.bloom_filter:
            if rule in self.seen_rules:
                return True
        
        # 添加到去重容器
        if self.bloom_filter:
            self.bloom_filter.add(rule)
        self.seen_rules.add(rule)
        return False

    def _deduplicate_rules(self, platform_rules: Dict) -> Dict[str, Dict[str, List[str]]]:
        """对各平台规则进行去重"""
        if not self.config.ENABLE_DEDUPLICATION:
            return platform_rules
        
        logger.info("开始对各平台规则去重...")
        for platform, rules in platform_rules.items():
            for rule_type in ["block", "allow"]:
                if platform in ["hosts", "surge"] and rule_type == "allow":
                    continue
                
                original_count = len(rules[rule_type])
                unique_rules = list(set(rules[rule_type]))
                rules[rule_type] = unique_rules
                removed = original_count - len(unique_rules)
                self.stats["duplicates"] += removed
                
                if removed > 0:
                    logger.info(f"平台{platform}（{rule_type}）：去重前{original_count}条 → 去重后{len(unique_rules)}条（移除{removed}条）")
        
        return platform_rules

    def _save_platform_rules(self, platform_rules: Dict) -> None:
        """保存各平台规则文件（Mihomo除外）- 无文件头，补充Clash/Surge规则集头"""
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"开始保存规则文件到：{self.config.OUTPUT_DIR}")

        # 平台保存逻辑映射
        save_handlers = {
            "clash": self._save_clash_rules,
            "surge": self._save_surge_rules,
            "hosts": self._save_hosts_rules,
            "default": self._save_default_rules
        }

        for platform, rules in platform_rules.items():
            if platform == "mihomo":  # Mihomo单独处理，此处跳过
                continue
            handler = save_handlers.get(platform, save_handlers["default"])
            handler(platform, rules)

    def _save_clash_rules(self, platform: str, rules: Dict[str, List[str]]) -> None:
        """保存Clash规则 - 无文件头，补充RULE-SET头+payload结构（语法数据库标准）"""
        for rule_type in ["block", "allow"]:
            if not rules[rule_type]:
                continue
            
            output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform][rule_type]
            # 1. 补充Clash规则集头（按语法数据库：#RULE-SET,{name},{action}）
            ruleset_name = "adblock_clash" if rule_type == "block" else "allow_clash"
            ruleset_action = "REJECT" if rule_type == "block" else "DIRECT"
            ruleset_header = f"#RULE-SET,{ruleset_name},{ruleset_action}"
            # 2. 构建纯净规则内容（仅payload+规则）
            rule_lines = [f"  - '{rule}'" for rule in rules[rule_type]]
            content = "\n".join([ruleset_header, "payload:"] + rule_lines)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"已保存Clash {rule_type} 规则：{output_path}（{len(rules[rule_type])}条）")

    def _save_surge_rules(self, platform: str, rules: Dict[str, List[str]]) -> None:
        """保存Surge规则 - 无文件头，补充DOMAIN-SET头（语法数据库标准）"""
        if not rules["block"]:
            return
        
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform]["block"]
        # 1. 补充Surge域名集头（按语法数据库：#DOMAIN-SET,{name},REJECT）
        ruleset_header = "#DOMAIN-SET,adblock_surge,REJECT"
        # 2. 构建纯净规则内容（仅头+规则）
        content = "\n".join([ruleset_header] + rules["block"])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"已保存Surge 规则：{output_path}（{len(rules['block'])}条）")

    def _save_hosts_rules(self, platform: str, rules: Dict[str, List[str]]) -> None:
        """保存Hosts规则 - 无文件头，仅纯净规则"""
        if not rules["block"]:
            return
        
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform]["block"]
        # 仅保留纯净规则，无任何头信息
        content = "\n".join(rules["block"])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"已保存Hosts 规则：{output_path}（{len(rules['block'])}条）")

    def _save_default_rules(self, platform: str, rules: Dict[str, List[str]]) -> None:
        """默认保存逻辑（Pi-hole、uBlock等）- 无文件头，仅纯净规则"""
        for rule_type in ["block", "allow"]:
            if platform in ["hosts", "surge"] and rule_type == "allow":
                continue
            if not rules[rule_type]:
                continue
            if rule_type not in self.config.OUTPUT_FILES.get(platform, {}):
                logger.debug(f"平台{platform}无{rule_type}规则输出配置，跳过")
                continue
            
            output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform][rule_type]
            # 仅保留纯净规则，无任何头信息
            content = "\n".join(rules[rule_type])
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"已保存{platform.upper()} {rule_type} 规则：{output_path}（{len(rules[rule_type])}条）")

    def _compile_mihomo_with_whitelist(self, platform_rules: Dict) -> None:
        """Mihomo专属流程：提取Clash黑名单→白名单过滤→编译"""
        # 1. 提取Clash黑名单中的域名规则（仅+.domain格式）
        clash_block_rules = platform_rules.get("clash", {}).get("block", [])
        mihomo_source_rules = [r for r in clash_block_rules if r.startswith(CLASH_BLOCK_PREFIX)]
        
        if not mihomo_source_rules:
            logger.warning("无有效Clash域名规则，无法生成Mihomo黑名单")
            return
        logger.info(f"Mihomo编译前：从Clash提取{len(mihomo_source_rules)}条域名规则")

        # 2. 执行白名单过滤（仅Mihomo生效）
        filtered_rules, filtered_count = self.whitelist_filter.filter_block_rules(mihomo_source_rules)
        self.stats["mihomo_whitelist_filtered"] = filtered_count
        if not filtered_rules:
            logger.warning("Mihomo规则经白名单过滤后为空，跳过编译")
            return
        logger.info(f"Mihomo白名单过滤：移除{filtered_count}条误杀规则，剩余{len(filtered_rules)}条")

        # 3. 编译Mihomo规则（使用语法数据库标准Clash规则格式）
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["block"]
        temp_path = ""
        try:
            # 创建临时Clash规则文件（含标准RULE-SET头）
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.yaml', delete=False) as temp_f:
                temp_f.write("#RULE-SET,adblock_clash,REJECT\n")
                temp_f.write("payload:\n")
                for rule in filtered_rules:
                    temp_f.write(f"  - '{rule}'\n")
                temp_path = temp_f.name

            # 执行编译命令
            cmd = [
                str(self.config.MIHOMO_TOOL_PATH),
                "convert-ruleset",
                "domain",
                "yaml",
                temp_path,
                str(output_path)
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=True)

            # 验证结果
            if Utils.verify_file_integrity(output_path):
                file_hash = Utils.calculate_file_hash(output_path)
                self.stats["mihomo_hashes"]["adb.mrs"] = file_hash
                logger.info(f"Mihomo黑名单编译完成：{output_path}（SHA256：{file_hash}）")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Mihomo编译超时（300秒）")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Mihomo编译命令失败（退出码{e.returncode}）：{e.stderr}")
        except Exception as e:
            raise RuntimeError(f"Mihomo编译异常：{str(e)}")
        finally:
            # 清理临时文件
            if temp_path and Path(temp_path).exists():
                Path(temp_path).unlink(missing_ok=True)
                logger.debug(f"清理Mihomo临时文件：{temp_path}")

    def _print_stats(self) -> None:
        """打印统计报告（同步修改统计项名称）"""
        logger.info("\n" + "="*60)
        logger.info("规则转换统计报告")
        logger.info("="*60)
        
        # 基础统计
        logger.info(f"1. 基础信息")
        logger.info(f"   - 总处理行数：{self.stats['total_processed']}")
        logger.info(f"   - 原始黑名单规则：{self.stats['original_counts']['block']}")
        logger.info(f"   - 原始白名单规则：{self.stats['original_counts']['allow']}")
        logger.info(f"   - 重复规则移除：{self.stats['duplicates']}")
        logger.info(f"   - 不支持规则：{self.stats['unsupported']}")
        logger.info(f"   - AdGuard特定规则：{self.stats['adguard_specific_rules']}")
        
        # Mihomo专属统计
        logger.info(f"\n2. Mihomo专属处理")
        clash_block = self._init_platform_rules().get("clash", {}).get("block", [])
        mihomo_source = len([r for r in clash_block if r.startswith(CLASH_BLOCK_PREFIX)])
        logger.info(f"   - 从Clash提取规则数：{mihomo_source}")
        logger.info(f"   - 白名单过滤移除数：{self.stats['mihomo_whitelist_filtered']}")
        logger.info(f"   - 最终编译规则数：{mihomo_source - self.stats['mihomo_whitelist_filtered']}")
        
        # 各平台产物统计
        logger.info(f"\n3. 各平台产物结果（无白名单过滤）")
        for platform, stats in self.stats["platforms"].items():
            if platform == "mihomo":
                continue
            total = stats["block"] + stats["allow"]
            logger.info(f"   - {platform.upper()}：")
            logger.info(f"     总规则：{total} | 拦截规则：{stats['block']} | 放行规则：{stats['allow']}")
            logger.info(f"     支持规则：{stats['supported']} | 不支持规则：{stats['unsupported']}")
            logger.info(f"     AdGuard规则转换：{stats['adguard_converted']}")
        
        # Mihomo校验信息
        if self.stats["mihomo_hashes"]:
            logger.info(f"\n4. Mihomo规则校验")
            for filename, file_hash in self.stats["mihomo_hashes"].items():
                logger.info(f"   - {filename}：SHA256 = {file_hash}")
        
        # GitHub Actions摘要
        if self.config.GITHUB_ACTIONS:
            self._generate_github_summary()

    def _generate_github_summary(self) -> None:
        """生成GitHub Actions步骤摘要（同步修改统计项名称）"""
        summary_path = os.getenv('GITHUB_STEP_SUMMARY')
        if not summary_path:
            return
        
        summary = f"""## 多平台规则转换结果
**执行时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**仓库**: {self.config.GITHUB_REPOSITORY}
**提交**: [{self.config.GITHUB_SHA[:7]}](https://github.com/{self.config.GITHUB_REPOSITORY}/commit/{self.config.GITHUB_SHA})

### 1. 处理统计
| 项目 | 数量 |
|------|------|
| 总处理行数 | {self.stats['total_processed']} |
| 原始黑名单规则 | {self.stats['original_counts']['block']} |
| 原始白名单规则 | {self.stats['original_counts']['allow']} |
| 重复规则移除 | {self.stats['duplicates']} |
| 不支持规则 | {self.stats['unsupported']} |
| AdGuard特定规则 | {self.stats['adguard_specific_rules']} |

### 2. Mihomo专属处理
| 项目 | 数量 |
|------|------|
| 从Clash提取规则数 | {len([r for r in self._init_platform_rules().get('clash', {}).get('block', []) if r.startswith(CLASH_BLOCK_PREFIX)])} |
| 白名单过滤移除数 | {self.stats['mihomo_whitelist_filtered']} |
| 最终编译规则数 | {len([r for r in self._init_platform_rules().get('clash', {}).get('block', []) if r.startswith(CLASH_BLOCK_PREFIX)]) - self.stats['mihomo_whitelist_filtered']} |

### 3. 各平台产物（无白名单过滤）
| 平台 | 总规则 | 拦截规则 | 放行规则 |
|------|--------|----------|----------|
"""
        for platform, stats in self.stats["platforms"].items():
            if platform == "mihomo":
                continue
            total = stats["block"] + stats["allow"]
            summary += f"| {platform.upper()} | {total} | {stats['block']} | {stats['allow']} |\n"
        
        if self.stats["mihomo_hashes"]:
            summary += "\n### 4. Mihomo规则校验\n"
            for filename, file_hash in self.stats["mihomo_hashes"].items():
                summary += f"- `{filename}`: `{file_hash}`\n"
        
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(summary)
        logger.info("已生成GitHub Actions步骤摘要")

# --------------------------
# 脚本入口
# --------------------------
def main():
    # 初始化配置
    config = UnifiedConfig()
    # 调整日志级别
    if config.VERBOSE_LOGGING:
        logger.setLevel(logging.DEBUG)
        logger.debug("启用详细日志模式")
    
    try:
        converter = UnifiedConverter(config)
        converter.run()
    except Exception as e:
        logger.error(f"脚本执行失败：{e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
