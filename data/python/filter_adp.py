#!/usr/bin/env python3
"""
统一规则转换平台 - 基于语法数据库的多目标输出系统
功能：从AdGuard规则同时生成Clash、Surge、Pi-hole、uBlock Origin、Hosts等规则
作者：AI助手
日期：2025-09-01
版本：4.3
改进内容：
1. 移除所有不必要的文件头，只保留Clash的payload头
2. 布隆过滤器+哈希表双重去重机制
3. 增强正则表达式处理能力
4. 改进修饰符解析逻辑
5. 修正Pi-hole例外规则语法
6. 增加Hosts格式输出支持（仅黑名单）
7. 增强错误处理和日志记录
"""

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
    SYNTAX_DB_FILE: Path = BASE_DIR / "unified_rules_db.json"
    
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
            # 注意: hosts文件没有白名单概念
        },
        "mihomo_source": {
            "block": "adblock_clash.yaml",  # 使用Clash规则作为Mihomo源
            "allow": "allow_clash.yaml"
        },
        "mihomo_output": {
            "block": "adblock.mrs",
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
        """预编译所有正则表达式模式 - 增强版"""
        compiled = {}
        patterns = self.syntax_db.get("syntax_patterns", {})
        
        for name, pattern_str in patterns.items():
            try:
                # 使用原始字符串处理更复杂的正则表达式
                clean_pattern = pattern_str.encode().decode('unicode_escape')
                compiled[name] = re.compile(clean_pattern)
            except (re.error, UnicodeDecodeError) as e:
                logger.warning(f"无法编译模式 {name}: {e}")
                # 添加回退到简单模式
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
            match = pattern.match(rule_content)
            if match:
                result["pattern_type"] = pattern_name
                result["type"] = self.syntax_db["rule_types"].get(pattern_name, "unknown")
                result["is_valid"] = result["type"] not in ["invalid", "comment"]
                
                # 提取规则内容
                if match.lastindex and match.lastindex >= 1:
                    result["content"] = match.group(1)
                break
        
        # 增强修饰符提取
        if "$" in rule_content:
            # 分割规则内容和修饰符部分
            base_part, modifiers_part = rule_content.split("$", 1)
            result["content"] = base_part.strip()
            
            # 解析逗号分隔的修饰符
            modifiers = []
            for mod in modifiers_part.split(","):
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
        if rule_type in platform_config.get("unsupported_rule_types", []):
            return False
        
        # 检查修饰符支持
        unsupported_mods = platform_config.get("unsupported_modifiers", [])
        if any(mod[0] in unsupported_mods for mod in rule_info["modifiers"]):
            return False
        
        # 特殊处理：hosts平台不支持例外规则
        if platform == "hosts" and rule_info["is_exception"]:
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
        is_exception = rule_info["is_exception"]
        
        # 确定动作
        action = "DIRECT" if is_exception else "REJECT"
        
        # 应用平台特定转换规则
        if rule_type in rule_format:
            format_str = rule_format[rule_type]
            return format_str.format(domain=content, pattern=content, action=action)
        
        # 默认转换逻辑
        if platform == "clash" or platform == "surge":
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
                # 修正例外语法
                return f"@@{content}" if is_exception else content
            elif rule_type == "hosts_rule":
                # 处理hosts格式规则
                if "0.0.0.0" in rule_info["original"]:
                    return rule_info["original"]  # 保持原样
                else:
                    return f"0.0.0.0 {content}"
        
        elif platform == "hosts":
            if rule_type == "domain_rule":
                # 将域名规则转换为hosts格式：0.0.0.0 domain
                return f"0.0.0.0 {content}"
            elif rule_type == "hosts_rule":
                # 如果已经是hosts格式，直接返回
                return rule_info["original"]
        
        # uBlock Origin和AdBlock Plus保持原格式，但过滤不支持的修饰符
        elif platform in ["ublock_origin", "adblock_plus"]:
            # 移除不支持的修饰符
            original_rule = rule_info["original"]
            unsupported_mods = platform_config.get("unsupported_modifiers", [])
            
            for mod in unsupported_mods:
                if f"${mod}" in original_rule:
                    # 移除整个修饰符部分
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
        # 确保输出目录存在
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # 初始化平台规则存储
        platform_rules = {}
        for platform in self.parser.platform_support.keys():
            platform_rules[platform] = {
                "block": [],
                "allow": []
            }
        
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
                    # 跳过hosts平台的白名单（不存在）
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
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    batch.append(line)
                    
                    if len(batch) >= self.config.BATCH_PROCESSING_SIZE:
                        self.process_batch(batch, platform_rules, rule_class)
                        batch = []
                
                # 处理剩余内容
                if batch:
                    self.process_batch(batch, platform_rules, rule_class)
                    
        except Exception as e:
            logger.error(f"处理文件 {file_path} 时出错: {e}")
    
    def process_batch(self, batch: List[str], platform_rules: Dict, rule_class: str):
        """处理批量规则 - 使用布隆过滤器+哈希表双重去重"""
        for rule in batch:
            self.stats["total_processed"] += 1
            
            # 双重去重检查
            if self.config.ENABLE_DEDUPLICATION:
                # 布隆过滤器初筛（快速但可能有假阳性）
                if self.bloom_filter is not None and rule in self.bloom_filter:
                    # 哈希表精筛（精确但较慢）
                    if rule in self.seen_rules:
                        self.stats["duplicates"] += 1
                        continue
                
                # 添加到去重集合
                if self.bloom_filter is not None:
                    self.bloom_filter.add(rule)
                self.seen_rules.add(rule)
            
            # 解析规则
            parsed = self.parser.parse_rule(rule)
            if not parsed["is_valid"]:
                continue
            
            # 为每个平台转换规则
            for platform in self.parser.platform_support.keys():
                # 跳过hosts平台的白名单处理
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
    
    def save_results(self, platform_rules: Dict):
        """保存所有平台的规则 - 只保留Clash的payload头"""
        logger.info("保存多平台规则文件...")
        
        # 保存各平台规则
        for platform, rules in platform_rules.items():
            for rule_type in ["block", "allow"]:
                # 跳过hosts平台的白名单（不存在）
                if platform == "hosts" and rule_type == "allow":
                    continue
                    
                if rules[rule_type]:
                    output_file = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES[platform][rule_type]
                    
                    # 只对Clash平台添加payload头
                    if platform == "clash":
                        content = ["payload:"]
                        content.extend(rules[rule_type])
                    else:
                        # 其他平台直接输出规则，不添加任何头
                        content = rules[rule_type]
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write("\n".join(content))
                    
                    logger.info(f"已保存 {platform} {rule_type} 规则: {output_file} ({len(rules[rule_type])} 条)")
        
        # 编译Mihomo规则集（如果需要）
        if self.config.ENABLE_MIHOMO_COMPILATION and "mihomo" in self.parser.platform_support:
            self.compile_mihomo_rules()
    
    def compile_mihomo_rules(self):
        """编译Mihomo规则集"""
        if not self.config.MIHOMO_TOOL_PATH.exists():
            logger.warning("Mihomo工具不存在，跳过编译")
            return
        
        logger.info("编译Mihomo规则集...")
        
        try:
            # 编译黑名单
            clash_block = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["block"]
            mihomo_block = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["block"]
            
            cmd = [
                str(self.config.MIHOMO_TOOL_PATH),
                "convert-ruleset",
                "domain",
                "yaml",
                str(clash_block),
                str(mihomo_block)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                logger.info(f"Mihomo黑名单编译成功: {mihomo_block}")
            else:
                logger.error(f"Mihomo黑名单编译失败: {result.stderr}")
            
            # 编译白名单
            clash_allow = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_source"]["allow"]
            mihomo_allow = self.config.OUTPUT_DIR / self.config.OUTPUT_FILES["mihomo_output"]["allow"]
            
            cmd = [
                str(self.config.MIHOMO_TOOL_PATH),
                "convert-ruleset",
                "domain",
                "yaml",
                str(clash_allow),
                str(mihomo_allow)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.returncode == 0:
                logger.info(f"Mihomo白名单编译成功: {mihomo_allow}")
            else:
                logger.error(f"Mihomo白名单编译失败: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Mihomo编译异常: {e}")
    
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
            if platform != "hosts":  # hosts没有白名单
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
        sys.exit(1)


if __name__ == "__main__":
    main()