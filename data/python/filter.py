#!/usr/bin/env python3
import os
import re
import json
import sys
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Pattern
from dataclasses import dataclass, field
import logging
from pybloom_live import ScalableBloomFilter


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@dataclass
class ConvertConfig:
    BASE_DIR: Path = Path(os.getenv("RULE_CONVERT_BASE", Path.cwd()))
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"
    OUTPUT_DIR: Path = BASE_DIR
    SYNTAX_DB: Path = BASE_DIR / "data" / "python" / "syntax_db.json"
    MIHOMO_BIN: Path = BASE_DIR / "data" / "mihomo-tool"
    
    # 原有输出配置
    OUTPUT_CLASH_BLOCK: str = "adblock_clash.yaml"
    OUTPUT_CLASH_ALLOW: str = "allow_clash.yaml"
    OUTPUT_MIHOMO: str = "adb.mrs"
    
    # 新增目标平台输出配置
    OUTPUT_ADBLOCK_PLUS_BLOCK: str = "adblock_abp.txt"
    OUTPUT_ADBLOCK_PLUS_ALLOW: str = "allow_abp.txt"
    OUTPUT_UBO_BLOCK: str = "adblock_ubo.txt"
    OUTPUT_UBO_ALLOW: str = "allow_ubo.txt"
    OUTPUT_PIHOLE: str = "pihole.list"
    OUTPUT_HOSTS: str = "hosts.txt"
    OUTPUT_SURGE_BLOCK: str = "adblock_surge.yaml"
    OUTPUT_SURGE_ALLOW: str = "allow_surge.yaml"
    
    # Hosts配置
    HOSTS_BLOCK_IP: str = "0.0.0.0"  # Hosts拦截默认IP
    HOSTS_ALLOW_IP: str = "127.0.0.1"  # Hosts放行默认IP（可选）

    ADGUARD_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", "hosts_rule",
        "adguard_home_dns_rewrite", "adblock_basic_element_hiding", "adguard_scriptlet",
        "adguard_extended_css", "adguard_removeparam", "pihole_domain"
    })
    CONVERTIBLE_SYNTAX: Set[str] = field(default_factory=lambda: {
        "adblock_basic_domain_rule", "adblock_basic_exception_rule", "hosts_rule", "adguard_home_dns_rewrite"
    })

    BATCH_SIZE: int = 1000
    USE_BLOOM: bool = True
    ENABLE_MIHOMO: bool = True


class SyntaxParser:
    def __init__(self, config: ConvertConfig):
        self.config = config
        self.syntax_db = self._load_db()
        self.compiled_patterns = self._compile_patterns()
        self.bloom = self._init_bloom()
        self.rule_type_cache: Dict[str, str] = {}
        self.domain_cache: Dict[str, str] = {}
        # 加载各平台支持的规则类型（从外部语法数据库）
        self.platform_supported_rules: Dict[str, Set[str]] = self._load_platform_supported_rules()

    def _load_db(self) -> Dict:
        if not self.config.SYNTAX_DB.exists():
            logger.error(f"语法数据库缺失：{self.config.SYNTAX_DB}")
            sys.exit(1)
        try:
            with open(self.config.SYNTAX_DB, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("数据库格式错误（需标准JSON）")
            sys.exit(1)
        except Exception as e:
            logger.error(f"数据库加载失败：{str(e)}")
            sys.exit(1)

    def _compile_patterns(self) -> Dict[str, Pattern]:
        # 完全基于外部语法数据库编译正则，不内置
        compiled = {}
        # 基础通用规则（注释、空行）
        compiled["adblock_basic_comment"] = re.compile(
            self.syntax_db["syntax_patterns"]["adblock_basic_comment"], 
            re.UNICODE
        )
        compiled["empty_rule"] = re.compile(r"^\s*$", re.UNICODE)

        # 各AdGuard语法规则（从数据库读取正则）
        for syntax in self.config.ADGUARD_SYNTAX:
            if syntax in self.syntax_db["syntax_patterns"]:
                compiled[syntax] = re.compile(
                    self.syntax_db["syntax_patterns"][syntax], 
                    re.IGNORECASE | re.UNICODE
                )
        return compiled

    def _init_bloom(self) -> Dict[str, ScalableBloomFilter]:
        if not self.config.USE_BLOOM:
            return {}
        bloom_cfg = self.syntax_db.get("performance_optimization", {}).get("bloom_filter_config", {})
        return {
            "block": ScalableBloomFilter(initial_capacity=bloom_cfg.get("initial_capacity", 50000), error_rate=0.001),
            "allow": ScalableBloomFilter(initial_capacity=bloom_cfg.get("initial_capacity", 10000), error_rate=0.001)
        }

    def _load_platform_supported_rules(self) -> Dict[str, Set[str]]:
        """从外部数据库加载各平台支持的规则类型"""
        platform_support = self.syntax_db.get("platform_support", {})
        return {
            "adblock_plus": set(platform_support.get("adblock_plus", {}).get("supported_rule_types", [])),
            "ubo": set(platform_support.get("ublock_origin", {}).get("supported_rule_types", [])),
            "pihole": set(platform_support.get("adguard_home", {}).get("supported_rule_types", [])),  # Pi-hole与AdGuard Home规则兼容
            "hosts": {"hosts_rule", "adblock_basic_domain_rule"},  # Hosts支持域名转IP格式
            "surge": set(platform_support.get("adblock_plus", {}).get("supported_rule_types", []))  # Surge基础规则与Adblock Plus兼容
        }

    def get_adguard_rule_type(self, rule: str) -> str:
        if not rule:
            return "empty_rule"
        if rule in self.rule_type_cache:
            return self.rule_type_cache[rule]

        if self.compiled_patterns["adblock_basic_comment"].match(rule):
            self.rule_type_cache[rule] = "adblock_basic_comment"
            return "adblock_basic_comment"
        if self.compiled_patterns["empty_rule"].match(rule):
            self.rule_type_cache[rule] = "empty_rule"
            return "empty_rule"

        for syntax in self.config.ADGUARD_SYNTAX:
            if self.compiled_patterns.get(syntax) and self.compiled_patterns[syntax].match(rule):
                self.rule_type_cache[rule] = syntax
                return syntax

        self.rule_type_cache[rule] = "non_adguard"
        return "non_adguard"

    def extract_convertible_domain(self, rule: str, rule_type: str) -> Optional[str]:
        if rule_type not in self.config.CONVERTIBLE_SYNTAX:
            return None
        if (rule, rule_type) in self.domain_cache:
            return self.domain_cache[(rule, rule_type)]

        domain = None
        # 基于规则类型提取域名（从数据库语法定义反向解析）
        if rule_type == "adblock_basic_domain_rule":
            match = self.compiled_patterns[rule_type].match(rule)
            domain = match.group(1).lower() if match else None
        elif rule_type == "adblock_basic_exception_rule":
            match = self.compiled_patterns[rule_type].match(rule)
            domain = match.group(1).lower() if match else None
        elif rule_type == "hosts_rule":
            match = self.compiled_patterns[rule_type].match(rule)
            domain = match.group(1).lower() if match else None
        elif rule_type == "adguard_home_dns_rewrite":
            match = self.compiled_patterns[rule_type].match(rule)
            domain = match.group(1).lower() if match else None
        elif rule_type == "pihole_domain":
            match = self.compiled_patterns[rule_type].match(rule)
            domain = match.group(0).lower() if match else None

        self.domain_cache[(rule, rule_type)] = domain
        return domain

    def is_valid_domain(self, domain: str) -> bool:
        if not domain:
            return False
        valid_chars = self.syntax_db["validation_rules"]["valid_domain_chars"]
        return bool(re.match(rf"^[{valid_chars}]+$", domain)) and len(domain) <= 253

    def is_platform_support_rule(self, platform: str, rule_type: str) -> bool:
        """判断规则类型是否被目标平台支持"""
        return rule_type in self.platform_supported_rules.get(platform, set())


class RuleConverter:
    def __init__(self, config: ConvertConfig):
        self.config = config
        self.parser = SyntaxParser(config)

        self.adguard_rules = {"black": [], "white": []}
        self.adguard_stats = {
            "black": {syntax: 0 for syntax in config.ADGUARD_SYNTAX},
            "white": {syntax: 0 for syntax in config.ADGUARD_SYNTAX},
            "comment": 0, "empty": 0, "non_adguard": 0
        }

        # 扩展可转换域名存储（按平台分类）
        self.convertible_domains: Dict[str, Dict[str, Set[str]]] = {
            "adblock_plus": {"block": set(), "allow": set()},
            "ubo": {"block": set(), "allow": set()},
            "pihole": {"block": set()},  # Pi-hole无放行规则
            "hosts": {"block": set(), "allow": set()},
            "surge": {"block": set(), "allow": set()},
            "clash": {"block": set(), "allow": set()}  # 保留原有Clash
        }
        self.convert_stats = {
            "total_convertible": 0, "duplicate": 0, "invalid_domain": 0,
            "valid": {
                "adblock_plus": {"block": 0, "allow": 0},
                "ubo": {"block": 0, "allow": 0},
                "pihole": {"block": 0},
                "hosts": {"block": 0, "allow": 0},
                "surge": {"block": 0, "allow": 0},
                "clash": {"block": 0, "allow": 0}
            }
        }

    def _stats_adguard_black_white(self, rule: str, rule_type: str, is_allow_file: bool) -> None:
        if rule_type == "adblock_basic_comment":
            self.adguard_stats["comment"] += 1
            return
        if rule_type == "empty_rule":
            self.adguard_stats["empty"] += 1
            return
        if rule_type == "non_adguard":
            self.adguard_stats["non_adguard"] += 1
            return

        target_list = "white" if is_allow_file or rule_type == "adblock_basic_exception_rule" else "black"
        self.adguard_rules[target_list].append(rule)
        if rule_type in self.adguard_stats[target_list]:
            self.adguard_stats[target_list][rule_type] += 1

    def _deduplicate_domain(self, domain: str, platform: str, target: str) -> bool:
        """按平台去重域名"""
        if not domain or platform not in self.convertible_domains:
            return False
        domain_hash = hashlib.md5(domain.encode("utf-8")).hexdigest()

        # 布隆过滤器去重（若启用）
        if self.config.USE_BLOOM and domain_hash not in self.parser.bloom[target]:
            pass
        elif domain in self.convertible_domains[platform][target]:
            self.convert_stats["duplicate"] += 1
            return True

        if self.config.USE_BLOOM:
            self.parser.bloom[target].add(domain_hash)
        self.convertible_domains[platform][target].add(domain)
        self.convert_stats["valid"][platform][target] += 1
        return False

    def process_adguard_rules(self) -> None:
        logger.info("="*60)
        logger.info("第一步：处理AdGuard规则（支持多平台转换）")
        logger.info("="*60)

        for is_allow, file_path in [(True, self.config.INPUT_ALLOW), (False, self.config.INPUT_BLOCK)]:
            file_type = "放行（白名单）" if is_allow else "拦截（黑名单）"
            if not file_path.exists():
                logger.warning(f"AdGuard{file_type}文件不存在：{file_path} → 跳过")
                continue
            logger.info(f"处理AdGuard{file_type}文件：{file_path.name}")

            line_count = 0
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    line_count += 1

                    adguard_rule_type = self.parser.get_adguard_rule_type(line)
                    self._stats_adguard_black_white(line, adguard_rule_type, is_allow)

                    # 仅处理可转换且平台支持的规则
                    if adguard_rule_type in self.config.CONVERTIBLE_SYNTAX:
                        self.convert_stats["total_convertible"] += 1
                        domain = self.parser.extract_convertible_domain(line, adguard_rule_type)
                        
                        # 域名有效性校验
                        if not self.parser.is_valid_domain(domain):
                            self.convert_stats["invalid_domain"] += 1
                            continue
                        
                        # 按平台分配域名（判断平台是否支持该规则类型）
                        target = "allow" if is_allow else "block"
                        for platform in self.convertible_domains.keys():
                            if self.parser.is_platform_support_rule(platform, adguard_rule_type):
                                self._deduplicate_domain(domain, platform, target)

                    if line_count % self.config.BATCH_SIZE == 0:
                        logger.debug(f"已处理{line_count}行（{file_type}）")

            logger.info(f"处理完成：{file_path.name} → 共{line_count}行")

    def print_adguard_black_white_stats(self) -> None:
        logger.info("\n" + "="*60)
        logger.info("第二步：AdGuard规则与多平台转换统计")
        logger.info("="*60)

        total_black = len(self.adguard_rules["black"])
        total_white = len(self.adguard_rules["white"])
        logger.info(f"1. 整体统计：")
        logger.info(f"   - AdGuard黑名单规则总数：{total_black}条")
        logger.info(f"   - AdGuard白名单规则总数：{total_white}条")
        logger.info(f"   - 注释规则：{self.adguard_stats['comment']}条")
        logger.info(f"   - 空规则：{self.adguard_stats['empty']}条")
        logger.info(f"   - 非AdGuard规则：{self.adguard_stats['non_adguard']}条")

        logger.info(f"\n2. 黑名单规则类型细分：")
        for syntax, count in self.adguard_stats["black"].items():
            if count > 0:
                logger.info(f"   - {syntax}：{count}条")

        logger.info(f"\n3. 白名单规则类型细分：")
        for syntax, count in self.adguard_stats["white"].items():
            if count > 0:
                logger.info(f"   - {syntax}：{count}条")

        logger.info(f"\n4. 多平台转换统计：")
        logger.info(f"   - 总可转换规则：{self.convert_stats['total_convertible']}条")
        logger.info(f"   - 无效域名：{self.convert_stats['invalid_domain']}条")
        logger.info(f"   - 重复域名：{self.convert_stats['duplicate']}条")
        for platform in self.convert_stats["valid"].keys():
            if platform == "pihole":
                logger.info(f"   - {platform}：拦截{self.convert_stats['valid'][platform]['block']}条")
            else:
                logger.info(f"   - {platform}：拦截{self.convert_stats['valid'][platform]['block']}条 | 放行{self.convert_stats['valid'][platform]['allow']}条")
        logger.info("="*60)

    def _generate_adblock_plus_product(self) -> None:
        """生成Adblock Plus规则（基于外部数据库格式定义）"""
        adb_plus_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_ADBLOCK_PLUS_BLOCK,
                "rule_format": self.parser.syntax_db["platform_support"]["adblock_plus"]["rule_format"]["adblock_basic_domain_rule"],
                "domains": sorted(self.convertible_domains["adblock_plus"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_ADBLOCK_PLUS_ALLOW,
                "rule_format": self.parser.syntax_db["platform_support"]["adblock_plus"]["rule_format"]["adblock_basic_exception_rule"],
                "domains": sorted(self.convertible_domains["adblock_plus"]["allow"])
            }
        }

        for target, cfg in adb_plus_cfg.items():
            if not cfg["domains"]:
                logger.warning(f"Adblock Plus{target}无有效域名 → 跳过")
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                f.write(f"! Adblock Plus {target}规则（自动转换）\n")
                f.write(f"! 生成时间：{self._get_current_time()}\n")
                f.write(f"! 规则数量：{len(cfg['domains'])}条\n\n")
                for domain in cfg["domains"]:
                    # 替换格式占位符（如{domain}）
                    rule = cfg["rule_format"].format(domain=domain.rstrip('^'))
                    f.write(f"{rule}\n")
            logger.info(f"Adblock Plus{target}产物：{cfg['path']}（{len(cfg['domains'])}条）")

    def _generate_ubo_product(self) -> None:
        """生成UBO规则（基于外部数据库格式定义）"""
        ubo_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_UBO_BLOCK,
                "domain_format": self.parser.syntax_db["platform_support"]["ublock_origin"]["rule_format"]["adblock_basic_domain_rule"],
                "domains": sorted(self.convertible_domains["ubo"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_UBO_ALLOW,
                "domain_format": self.parser.syntax_db["platform_support"]["ublock_origin"]["rule_format"]["adblock_basic_exception_rule"],
                "domains": sorted(self.convertible_domains["ubo"]["allow"])
            }
        }

        for target, cfg in ubo_cfg.items():
            if not cfg["domains"]:
                logger.warning(f"UBO{target}无有效域名 → 跳过")
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                f.write(f"! uBlock Origin {target}规则（自动转换）\n")
                f.write(f"! 生成时间：{self._get_current_time()}\n")
                f.write(f"! 规则数量：{len(cfg['domains'])}条\n\n")
                for domain in cfg["domains"]:
                    rule = cfg["domain_format"].format(domain=domain.rstrip('^'))
                    f.write(f"{rule}\n")
            logger.info(f"UBO{target}产物：{cfg['path']}（{len(cfg['domains'])}条）")

    def _generate_pihole_product(self) -> None:
        """生成Pi-hole规则（纯域名格式）"""
        pihole_path = self.config.OUTPUT_DIR / self.config.OUTPUT_PIHOLE
        domains = sorted(self.convertible_domains["pihole"]["block"])
        if not domains:
            logger.warning("Pi-hole无有效拦截域名 → 跳过")
            return

        with open(pihole_path, "w", encoding="utf-8") as f:
            f.write(f"# Pi-hole拦截规则（自动转换）\n")
            f.write(f"# 生成时间：{self._get_current_time()}\n")
            f.write(f"# 规则数量：{len(domains)}条\n\n")
            for domain in domains:
                f.write(f"{domain}\n")
        logger.info(f"Pi-hole产物：{pihole_path}（{len(domains)}条）")

    def _generate_hosts_product(self) -> None:
        """生成Hosts规则（IP+域名格式）"""
        hosts_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_HOSTS,
                "ip": self.config.HOSTS_BLOCK_IP,
                "domains": sorted(self.convertible_domains["hosts"]["block"])
            }
            # 可选：添加Hosts放行规则
            # "allow": {
            #     "path": self.config.OUTPUT_DIR / "allow_hosts.txt",
            #     "ip": self.config.HOSTS_ALLOW_IP,
            #     "domains": sorted(self.convertible_domains["hosts"]["allow"])
            # }
        }

        for target, cfg in hosts_cfg.items():
            if not cfg["domains"]:
                logger.warning(f"Hosts{target}无有效域名 → 跳过")
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                f.write(f"# Hosts {target}规则（自动转换）\n")
                f.write(f"# 生成时间：{self._get_current_time()}\n")
                f.write(f"# 规则数量：{len(cfg['domains'])}条\n\n")
                for domain in cfg["domains"]:
                    f.write(f"{cfg['ip']} {domain}\n")
            logger.info(f"Hosts{target}产物：{cfg['path']}（{len(cfg['domains'])}条）")

    def _generate_surge_product(self) -> None:
        """生成Surge规则（无payload，与Clash格式兼容）"""
        surge_cfg = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_SURGE_BLOCK,
                "header": f"#DOMAIN-SET,adblock_surge_block,REJECT",  # Surge标准头
                "domains": sorted(self.convertible_domains["surge"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_SURGE_ALLOW,
                "header": f"#DOMAIN-SET,adblock_surge_allow,DIRECT",
                "domains": sorted(self.convertible_domains["surge"]["allow"])
            }
        }

        for target, cfg in surge_cfg.items():
            if not cfg["domains"]:
                logger.warning(f"Surge{target}无有效域名 → 跳过")
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                f.write(f"{cfg['header']}\n")  # 无payload字段，直接列域名
                for domain in cfg["domains"]:
                    f.write(f"+.{domain.lstrip('*.')}\n")
            logger.info(f"Surge{target}产物：{cfg['path']}（{len(cfg['domains'])}条）")

    def _generate_clash_product(self) -> None:
        """保留原有Clash规则生成逻辑"""
        clash_config = {
            "block": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_CLASH_BLOCK,
                "action_header": "#RULE-SET,adblock_clash_block,REJECT",
                "domains": sorted(self.convertible_domains["clash"]["block"])
            },
            "allow": {
                "path": self.config.OUTPUT_DIR / self.config.OUTPUT_CLASH_ALLOW,
                "action_header": "#RULE-SET,adblock_clash_allow,DIRECT",
                "domains": sorted(self.convertible_domains["clash"]["allow"])
            }
        }

        for target, cfg in clash_config.items():
            if not cfg["domains"]:
                logger.warning(f"Clash{target}无有效域名 → 跳过")
                continue
            with open(cfg["path"], "w", encoding="utf-8") as f:
                f.write(f"{cfg['action_header']}\n")
                f.write("payload:\n")
                for domain in cfg["domains"]:
                    f.write(f"  - '+.{domain.lstrip('*.')}'\n")
            logger.info(f"Clash{target}产物：{cfg['path']}（{len(cfg['domains'])}条）")

    def _generate_mihomo_product(self) -> None:
        """保留原有Mihomo规则生成逻辑"""
        if not self.config.ENABLE_MIHOMO:
            logger.info("未启用Mihomo编译 → 跳过")
            return
        if not self.config.MIHOMO_BIN.exists():
            logger.error(f"Mihomo工具缺失：{self.config.MIHOMO_BIN} → 跳过")
            return

        white_domain_set = self.convertible_domains["clash"]["allow"]
        filtered_block_domains = [d for d in self.convertible_domains["clash"]["block"] if d not in white_domain_set]
        if not filtered_block_domains:
            logger.warning("白名单过滤后无有效拦截域名 → 跳过Mihomo编译")
            return

        temp_yaml = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write("payload:\n")
                for domain in sorted(filtered_block_domains):
                    f.write(f"  - '{domain.lstrip('*.')}'\n")
                temp_yaml = f.name

            output_mrs = self.config.OUTPUT_DIR / self.config.OUTPUT_MIHOMO
            cmd = [str(self.config.MIHOMO_BIN), "convert-ruleset", "domain", "yaml", temp_yaml, str(output_mrs)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                raise Exception(f"编译错误：{result.stderr.strip()}")

            sha256 = hashlib.sha256()
            with open(output_mrs, "rb") as f:
                sha256.update(f.read())
            logger.info(f"Mihomo产物：{output_mrs}（{len(filtered_block_domains)}条，SHA256：{sha256.hexdigest()}）")
        except Exception as e:
            logger.error(f"Mihomo编译失败：{str(e)}")
        finally:
            if temp_yaml and os.path.exists(temp_yaml):
                os.unlink(temp_yaml)

    def _get_current_time(self) -> str:
        """获取当前时间（用于规则注释）"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_products(self) -> None:
        logger.info("\n第三步：生成多平台规则产物")
        logger.info("="*60)
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 生成新增平台产物
        self._generate_adblock_plus_product()
        self._generate_ubo_product()
        self._generate_pihole_product()
        self._generate_hosts_product()
        self._generate_surge_product()

        # 保留原有产物生成
        self._generate_clash_product()
        self._generate_mihomo_product()

        logger.info("="*60)
        logger.info("所有多平台产物生成完成！")

    def run_full_flow(self) -> None:
        try:
            self.process_adguard_rules()
            self.print_adguard_black_white_stats()
            self.generate_products()
        except KeyboardInterrupt:
            logger.info("\n流程被手动中断")
            sys.exit(0)
        except Exception as e:
            logger.error(f"\n流程失败：{str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    config = ConvertConfig()
    converter = RuleConverter(config)
    converter.run_full_flow()
