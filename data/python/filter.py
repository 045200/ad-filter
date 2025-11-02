#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional, Pattern, Tuple, Any
from dataclasses import dataclass, field
import logging
from collections import defaultdict

try:
    from adblockparser import AdblockRules
    ADBLOCKPARSER_AVAILABLE = True
except ImportError:
    ADBLOCKPARSER_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("adblockparser not available, please install: pip install adblockparser")

try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@dataclass
class ConvertConfig:
    """配置类 - 简化版本"""
    BASE_DIR: Path = Path(os.getenv("RULE_CONVERT_BASE", Path.cwd()))
    
    # 输入文件
    INPUT_BLOCK: Path = BASE_DIR / "adblock_adg.txt"
    INPUT_ALLOW: Path = BASE_DIR / "allow_adg.txt"
    OUTPUT_DIR: Path = BASE_DIR
    
    # Mihomo工具路径
    MIHOMO_BIN: Path = BASE_DIR / "data" / "mihomo-tool"

    # 输出文件配置
    OUTPUT_FILES = {
        "clash_block": "adblock_clash.yaml",
        "clash_allow": "allow_clash.yaml", 
        "mihomo": "adb.mrs",
        "pihole": "adblock_pihole.list",
        "hosts": "hosts.txt",
        "surge_block": "adblock_surge.yaml",
        "surge_allow": "allow_surge.yaml"
    }

    # 规则集名称
    RULESET_NAMES = {
        "surge_block": "AdBlock",
        "surge_allow": "AllowList", 
        "clash_block": "AdBlock", 
        "clash_allow": "AllowList"
    }

    # Hosts配置
    HOSTS_BLOCK_IP: str = "0.0.0.0"
    HOSTS_ALLOW_IP: str = "127.0.0.1"

    # 性能配置
    BATCH_SIZE: int = 1000
    USE_BLOOM: bool = BLOOM_AVAILABLE
    ENABLE_MIHOMO: bool = True


class RuleParser:
    """规则解析器 - 简化版本"""
    
    # 支持的规则类型
    DOMAIN_RULE_TYPES = {"domain_rule", "exception_rule", "wildcard_domain", "pihole_domain"}
    CONVERTIBLE_TYPES = {"domain_rule", "exception_rule", "wildcard_domain", "pihole_domain", "hosts_rule"}
    UNSUPPORTED_TYPES = {"comment", "empty_rule", "unknown_rule"}
    
    # 不支持的修饰符
    UNSUPPORTED_MODIFIERS = {'client', 'dnstype', 'dnsrewrite'}

    def __init__(self):
        self.patterns = self._compile_patterns()
        self.rule_cache: Dict[str, str] = {}
        self.domain_cache: Dict[str, str] = {}
        self.modifier_cache: Dict[str, Dict[str, str]] = {}

    def _compile_patterns(self) -> Dict[str, Pattern]:
        """编译正则表达式模式"""
        patterns = {
            # 基础规则类型
            "comment": re.compile(r'^!'),
            "empty_rule": re.compile(r'^\s*$'),
            "exception_rule": re.compile(r'^@@\|\|([^\^$]+)\^'),
            "domain_rule": re.compile(r'^\|\|([^\^$]+)\^'),
            "wildcard_domain": re.compile(r'^\*\.([^\^$]+)'),
            "regex_rule": re.compile(r'^/(.*)/$'),
            "hosts_rule": re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^\s#]+)'),
            "pihole_domain": re.compile(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$'),
            
            # 修饰符
            "modifier_domain": re.compile(r"domain=([^\s,]+)", re.IGNORECASE),
            "modifier_client": re.compile(r"client=([^\s,]+)", re.IGNORECASE),
            "modifier_dnstype": re.compile(r"dnstype=([^\s,]+)", re.IGNORECASE),
            "modifier_dnsrewrite": re.compile(r"dnsrewrite=([^\s,]+)", re.IGNORECASE),
            "modifier_important": re.compile(r"important", re.IGNORECASE),
            "modifier_badfilter": re.compile(r"badfilter", re.IGNORECASE),
        }
        return patterns

    def get_rule_type(self, rule: str) -> str:
        """识别规则类型"""
        if not rule or rule.strip() == "":
            return "empty_rule"

        if rule in self.rule_cache:
            return self.rule_cache[rule]

        # 按优先级检查规则类型
        for rule_type, pattern in self.patterns.items():
            if rule_type in {"modifier_domain", "modifier_client", "modifier_dnstype", 
                           "modifier_dnsrewrite", "modifier_important", "modifier_badfilter"}:
                continue
                
            if pattern.match(rule):
                self.rule_cache[rule] = rule_type
                return rule_type

        self.rule_cache[rule] = "unknown_rule"
        return "unknown_rule"

    def extract_domain(self, rule: str, rule_type: str) -> Optional[str]:
        """从规则中提取域名"""
        if rule_type not in self.CONVERTIBLE_TYPES:
            return None

        cache_key = (rule, rule_type)
        if cache_key in self.domain_cache:
            return self.domain_cache[cache_key]

        domain = None

        try:
            if rule_type in ["domain_rule", "exception_rule"]:
                match = self.patterns[rule_type].search(rule)
                if match:
                    domain = match.group(1)
            elif rule_type == "wildcard_domain":
                match = self.patterns[rule_type].search(rule)
                if match:
                    domain = match.group(1)
            elif rule_type == "hosts_rule":
                match = self.patterns[rule_type].search(rule)
                if match:
                    domain = match.group(2)
            elif rule_type == "pihole_domain":
                domain = rule.strip()

            # 域名清洗
            if domain:
                domain = self._clean_domain(domain)

        except Exception as e:
            logger.debug(f"域名提取失败 {rule_type}: {rule} - {e}")
            return None

        self.domain_cache[cache_key] = domain
        return domain

    def _clean_domain(self, domain: str) -> str:
        """清洗和规范化域名"""
        if not domain:
            return domain

        domain = domain.lower().strip()
        
        # 移除常见前缀后缀
        domain = re.sub(r'^\|+\*?\.?', '', domain)
        domain = re.sub(r'\^.*$', '', domain)
        domain = re.sub(r'\$.*$', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        
        # 基本验证
        if not re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', domain):
            return ""
            
        return domain

    def extract_modifiers(self, rule: str) -> Dict[str, str]:
        """提取规则修饰符"""
        if rule in self.modifier_cache:
            return self.modifier_cache[rule]

        modifiers = {}
        if '$' in rule:
            modifier_part = rule.split('$', 1)[1]
            for mod_name in ['domain', 'client', 'dnstype', 'dnsrewrite', 'important', 'badfilter']:
                pattern = self.patterns[f"modifier_{mod_name}"]
                match = pattern.search(modifier_part)
                if match:
                    if match.lastindex and match.group(1):
                        modifiers[mod_name] = match.group(1)
                    else:
                        modifiers[mod_name] = "true"

        self.modifier_cache[rule] = modifiers
        return modifiers

    def has_unsupported_modifiers(self, modifiers: Dict[str, str]) -> bool:
        """检查是否包含不支持的修饰符"""
        return any(mod in modifiers for mod in self.UNSUPPORTED_MODIFIERS)

    def is_convertible(self, rule_type: str) -> bool:
        """检查规则是否可转换"""
        return rule_type in self.CONVERTIBLE_TYPES

    def is_domain_rule(self, rule_type: str) -> bool:
        """检查是否是域名规则"""
        return rule_type in self.DOMAIN_RULE_TYPES


class RuleConverter:
    """规则转换器 - 主逻辑"""
    
    def __init__(self, config: ConvertConfig):
        self.config = config
        self.parser = RuleParser()
        
        # 统计数据
        self.stats = {
            "total_rules": 0,
            "convertible_rules": 0,
            "converted_rules": 0,
            "skipped_rules": 0
        }
        
        # 转换结果
        self.domains = {
            "block": set(),
            "allow": set()
        }
        
        # 问题记录
        self.issues = {
            "invalid_domains": [],
            "unsupported_modifiers": [],
            "validation_failures": []
        }

    def process_files(self) -> None:
        """处理输入文件"""
        logger.info("=" * 50)
        logger.info("开始处理规则文件")
        logger.info("=" * 50)

        for is_allow, file_path in [(False, self.config.INPUT_BLOCK), (True, self.config.INPUT_ALLOW)]:
            if not file_path.exists():
                logger.warning(f"文件不存在: {file_path} → 跳过")
                continue
                
            self._process_file(file_path, is_allow)

    def _process_file(self, file_path: Path, is_allow: bool) -> None:
        """处理单个文件"""
        file_type = "白名单" if is_allow else "黑名单"
        logger.info(f"处理{file_type}文件: {file_path.name}")
        
        line_count = 0
        convertible_count = 0

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    line_count += 1
                    self.stats["total_rules"] += 1

                    rule_type = self.parser.get_rule_type(line)
                    
                    if self.parser.is_convertible(rule_type):
                        convertible_count += 1
                        self._process_convertible_rule(line, rule_type, is_allow)

                    if line_count % self.config.BATCH_SIZE == 0:
                        logger.debug(f"已处理 {line_count} 行，可转换 {convertible_count} 条")

            logger.info(f"{file_type}处理完成: {line_count}行，可转换{convertible_count}条")

        except Exception as e:
            logger.error(f"处理文件失败 {file_path}: {e}")

    def _process_convertible_rule(self, rule: str, rule_type: str, is_allow: bool) -> None:
        """处理可转换规则"""
        # 检查修饰符
        modifiers = self.parser.extract_modifiers(rule)
        if self.parser.has_unsupported_modifiers(modifiers):
            self.issues["unsupported_modifiers"].append(rule)
            return

        # 提取域名
        domain = self.parser.extract_domain(rule, rule_type)
        if not domain:
            self.issues["invalid_domains"].append(rule)
            return

        # 添加到对应集合
        target = "allow" if is_allow else "block"
        self.domains[target].add(domain)
        self.stats["converted_rules"] += 1

    def generate_report(self) -> None:
        """生成转换报告"""
        logger.info("\n" + "=" * 50)
        logger.info("转换统计报告")
        logger.info("=" * 50)
        
        logger.info(f"总规则数: {self.stats['total_rules']}")
        logger.info(f"成功转换: {self.stats['converted_rules']}")
        
        block_count = len(self.domains['block'])
        allow_count = len(self.domains['allow'])
        logger.info(f"拦截域名: {block_count}个")
        logger.info(f"放行域名: {allow_count}个")
        
        # 问题统计
        total_issues = sum(len(issue_list) for issue_list in self.issues.values())
        if total_issues > 0:
            logger.info(f"发现问题: {total_issues}个")
            for issue_type, issue_list in self.issues.items():
                if issue_list:
                    logger.info(f"  - {issue_type}: {len(issue_list)}个")

    def _write_domain_file(self, file_path: Path, domains: List[str], header: str = "") -> None:
        """写入域名文件通用方法"""
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                if header:
                    f.write(f"{header}\n\n")
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")

    def generate_pihole(self) -> None:
        """生成Pi-hole规则"""
        if not self.domains['block']:
            logger.warning("Pi-hole: 无拦截域名可转换")
            return
            
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES['pihole']
        domains = [d for d in self.domains['block'] if not d.startswith('/')]
        
        self._write_domain_file(
            output_path, 
            domains,
            "# Pi-hole规则 - 由AdGuard规则转换生成\n# 专注于DNS层广告拦截"
        )
        logger.info(f"Pi-hole规则生成: {len(domains)}条")

    def generate_hosts(self) -> None:
        """生成Hosts规则"""
        if not self.domains['block']:
            logger.warning("Hosts: 无拦截域名可转换")
            return
            
        output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES['hosts']
        domains = [d for d in self.domains['block'] if not d.startswith('/')]
        hosts_entries = [f"{self.config.HOSTS_BLOCK_IP} {domain}" for domain in domains]
        
        self._write_domain_file(
            output_path,
            hosts_entries,
            "# Hosts规则 - 由AdGuard规则转换生成\n# 用于系统级广告拦截"
        )
        logger.info(f"Hosts规则生成: {len(domains)}条")

    def generate_surge(self) -> None:
        """生成Surge规则"""
        for target in ['block', 'allow']:
            if not self.domains[target]:
                logger.warning(f"Surge {target}: 无域名可转换")
                continue
                
            output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[f'surge_{target}']
            domains = [d for d in self.domains[target] if not d.startswith('/')]
            policy = "REJECT" if target == "block" else "DIRECT"
            ruleset_name = self.config.RULESET_NAMES[f"surge_{target}"]
            
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(f"#DOMAIN-SET,{ruleset_name},{policy}\n")
                    for domain in sorted(domains):
                        f.write(f".{domain}\n")
                logger.info(f"Surge {target}规则生成: {len(domains)}条")
            except Exception as e:
                logger.error(f"生成Surge {target}规则失败: {e}")

    def generate_clash(self) -> None:
        """生成Clash规则"""
        for target in ['block', 'allow']:
            if not self.domains[target]:
                logger.warning(f"Clash {target}: 无域名可转换")
                continue
                
            output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[f'clash_{target}']
            domains = [d for d in self.domains[target] if not d.startswith('/')]
            policy = "REJECT" if target == "block" else "DIRECT"
            ruleset_name = self.config.RULESET_NAMES[f"clash_{target}"]
            
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(f"#RULE-SET,{ruleset_name},{policy}\n")
                    f.write("payload:\n")
                    for domain in sorted(domains):
                        f.write(f"  - '+.{domain}'\n")
                logger.info(f"Clash {target}规则生成: {len(domains)}条")
            except Exception as e:
                logger.error(f"生成Clash {target}规则失败: {e}")

    def generate_mihomo(self) -> None:
        """生成Mihomo二进制规则集"""
        if not self.config.ENABLE_MIHOMO or not self.config.MIHOMO_BIN.exists():
            logger.warning("Mihomo编译被禁用或mihomo-tool不存在")
            return

        # 过滤白名单域名
        final_domains = [
            domain for domain in self.domains['block'] 
            if domain not in self.domains['allow'] and not domain.startswith('/')
        ]
        
        if not final_domains:
            logger.warning("Mihomo: 过滤后无可转换域名")
            return

        temp_yaml = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write("# Mihomo规则集\npayload:\n")
                for domain in sorted(final_domains):
                    f.write(f"  - '+.{domain}'\n")
                temp_yaml = f.name

            output_path = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES['mihomo']
            cmd = [str(self.config.MIHOMO_BIN), "convert-ruleset", "domain", "yaml", temp_yaml, str(output_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # 计算哈希
                sha256 = hashlib.sha256()
                with open(output_path, "rb") as f:
                    sha256.update(f.read())
                logger.info(f"Mihomo规则集生成: {len(final_domains)}条, SHA256: {sha256.hexdigest()[:16]}...")
            else:
                logger.error(f"Mihomo编译失败: {result.stderr}")

        except Exception as e:
            logger.error(f"Mihomo处理失败: {e}")
        finally:
            if temp_yaml and os.path.exists(temp_yaml):
                os.unlink(temp_yaml)

    def generate_all(self) -> None:
        """生成所有格式规则"""
        logger.info("\n" + "=" * 50)
        logger.info("生成多平台规则")
        logger.info("=" * 50)

        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        generators = [
            ("Pi-hole", self.generate_pihole),
            ("Hosts", self.generate_hosts),
            ("Surge", self.generate_surge),
            ("Clash", self.generate_clash),
            ("Mihomo", self.generate_mihomo)
        ]

        for name, generator in generators:
            try:
                generator()
            except Exception as e:
                logger.error(f"{name}生成失败: {e}")

        logger.info("=" * 50)
        logger.info("所有规则生成完成！")

    def run(self) -> None:
        """运行完整转换流程"""
        try:
            self.process_files()
            self.generate_report()
            self.generate_all()
        except KeyboardInterrupt:
            logger.info("用户中断转换流程")
            sys.exit(0)
        except Exception as e:
            logger.error(f"转换流程失败: {e}")
            sys.exit(1)


if __name__ == "__main__":
    config = ConvertConfig()
    converter = RuleConverter(config)
    converter.run()