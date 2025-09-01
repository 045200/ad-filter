#!/usr/bin/env python3
"""
AdGuard规则合并去重脚本（恢复原始布隆过滤器版）
功能：保留原ScalableBloomFilter，整合DNS校验、分块读取等优化
"""

import os
import re
import json
import logging
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional, Any, Union, Generator
from dataclasses import dataclass, field
from threading import Lock
from functools import lru_cache
from datetime import datetime

# -------------------------- 恢复原始布隆过滤器依赖（原脚本使用的库） --------------------------
try:
    from pybloom_live import ScalableBloomFilter
except ImportError:
    logging.error("未找到pybloom_live库！请先安装：pip install pybloom_live")
    sys.exit(1)

# -------------------------- 原脚本核心配置（完全保留） --------------------------
@dataclass
class AdGuardConfig:
    INPUT_DIR: Path = Path(os.getenv('INPUT_DIR', './data/filter'))
    OUTPUT_DIR: Path = Path(os.getenv('OUTPUT_DIR', './'))
    ADBLOCK_PATTERNS: List[str] = field(default_factory=lambda: ['*.txt', '*.filter'])
    OUTPUT_BLOCK: str = 'adblock_adg.txt'
    OUTPUT_ALLOW: str = 'allow_adg.txt'
    SYNTAX_DB_FILE: str = "adblock_syntax_db.json"

    # 原脚本环境变量适配（完全保留）
    GITHUB_ACTIONS: bool = os.getenv('GITHUB_ACTIONS', 'false').lower() == 'true'
    GITHUB_REPOSITORY: str = os.getenv('GITHUB_REPOSITORY', 'unknown/repository')
    GITHUB_SHA: str = os.getenv('GITHUB_SHA', 'unknown')
    GITHUB_REF: str = os.getenv('GITHUB_REF', 'unknown')
    GITHUB_WORKFLOW: str = os.getenv('GITHUB_WORKFLOW', 'unknown')

    # 原脚本布隆过滤器参数（完全保留）
    BLOOM_INIT_CAP: int = int(os.getenv('BLOOM_INIT_CAP', '1000000'))
    BLOOM_ERROR_RATE: float = float(os.getenv('BLOOM_ERROR_RATE', '0.0001'))

    # 其他参数（保留原定义+新增优化参数）
    MAX_RULE_LENGTH: int = int(os.getenv('MAX_RULE_LENGTH', '2000'))
    MIN_RULE_LENGTH: int = int(os.getenv('MIN_RULE_LENGTH', '3'))
    CHUNK_SIZE: int = int(os.getenv('CHUNK_SIZE', '1048576'))  # 新增分块读取
    VALID_DNS_TYPES: Set[str] = field(default_factory=lambda: {"A", "AAAA", "CNAME", "TXT", "MX", "SRV"})  # 新增DNS校验
    VALID_DNS_RCODES: Set[str] = field(default_factory=lambda: {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"})
    ADGUARD_HOME_UNSUPPORTED: Set[str] = field(default_factory=lambda: {"element_hiding", "scriptlet", "extended_css"})  # 新增平台过滤
    MAX_RULES_PER_FILE: int = int(os.getenv('MAX_RULES_PER_FILE', '50000'))
    DOWNLOAD_TIMEOUT: int = int(os.getenv('DOWNLOAD_TIMEOUT', '30'))

# -------------------------- 日志初始化（保留原配置） --------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler('adguard_rule_merger.log', encoding='utf-8')]
)
logger = logging.getLogger(__name__)

# -------------------------- 辅助函数（保留整合优化） --------------------------
@lru_cache(maxsize=4096)
def validate_domain(domain: str) -> bool:
    return re.match(r"^[a-zA-Z0-9.-\*]+$", domain) is not None

def parse_dns_rewrite(rewrite_str: str) -> Dict:
    parts = rewrite_str.split(";")
    return {"rcode": parts[0] if len(parts) > 0 else "NOERROR", "rr_type": parts[1] if len(parts) > 1 else "A", "content": parts[2] if len(parts) > 2 else ""}

# -------------------------- 语法数据库（保留整合优化） --------------------------
class AdGuardSyntaxDatabase:
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_patterns = {}
        self.rule_types = {}
        self.modifiers = {}
        self.normalization_rules = {}
        self.load_syntax_database()

    def load_syntax_database(self):
        script_dir = Path(__file__).parent
        db_path = script_dir / self.config.SYNTAX_DB_FILE
        if db_path.exists():
            self._load_from_file(db_path, "脚本目录")
            return
        db_path = self.config.INPUT_DIR / self.config.SYNTAX_DB_FILE
        if db_path.exists():
            self._load_from_file(db_path, "输入目录")
            return
        logger.warning("未找到语法数据库，使用默认规则")
        self._build_default_syntax()
        self.save_syntax_database(script_dir / self.config.SYNTAX_DB_FILE)

    def _load_from_file(self, db_path: Path, source: str):
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                db_data = json.load(f)
                self.syntax_patterns = db_data.get('syntax_patterns', {})
                self.rule_types = db_data.get('rule_types', {})
                self.modifiers = db_data.get('modifiers', {})
                self.normalization_rules = db_data.get('normalization_rules', {})
            logger.info(f"从{source}加载语法数据库: {len(self.syntax_patterns)} 个模式")
        except Exception as e:
            logger.error(f"加载{source}语法数据库失败: {e}")
            self._build_default_syntax()

    def _build_default_syntax(self):
        self.syntax_patterns = {
            'domain_rule': r'^\|\|([^\^]+)\^',
            'url_rule': r'^\|([^\|]+)\|',
            'element_hiding': r'^([^#]+)##([^#]+)',
            'exception_rule': r'^@@',
            'regex_rule': r'^/(.+)/$',
            'comment': r'^!',
            'options': r'\$(.+)$',
            'adguard_specific': r'^#\$#',
            'html_filtering': r'^#@?#',
            'scriptlet': r'^#%#',
            'extension': r'^#\?#',
            'dns_rewrite': r'\$dnsrewrite=([^,;]+(?:;[^,;]+)*)',  # 新增DNS模式
            'dnstype': r'\$dnstype=([^,]+)',
            'client': r'\$client=([^,]+)'
        }
        self.rule_types = {
            'domain_rule': 'block',
            'url_rule': 'block',
            'element_hiding': 'block',
            'exception_rule': 'allow',
            'regex_rule': 'block',
            'comment': 'invalid',
            'options': 'modifier',
            'adguard_specific': 'block',
            'html_filtering': 'block',
            'scriptlet': 'block',
            'extension': 'block',
            'dns_rewrite': 'block',
            'dnstype': 'modifier',
            'client': 'modifier'
        }
        self.modifiers = {
            'domain': r'domain=([^\s,]+)',
            'script': r'script',
            'image': r'image',
            'stylesheet': r'stylesheet',
            'object': r'object',
            'xmlhttprequest': r'xmlhttprequest',
            'subdocument': r'subdocument',
            'document': r'document',
            'elemhide': r'elemhide',
            'other': r'other',
            'third-party': r'third-party',
            'match-case': r'match-case',
            'collapse': r'collapse',
            'donottrack': r'donottrack',
            'websocket': r'websocket',
            'webrtc': r'webrtc',
            'content': r'content',
            'popup': r'popup',
            'app': r'app',
            'network': r'network',
            'dnsrewrite': r'dnsrewrite',
            'dnstype': r'dnstype',
            'client': r'client'
        }
        self.normalization_rules = {'sort_modifiers': True, 'lowercase_domain': True}

    def save_syntax_database(self, db_path: Path):
        db_data = {
            'syntax_patterns': self.syntax_patterns,
            'rule_types': self.rule_types,
            'modifiers': self.modifiers,
            'normalization_rules': self.normalization_rules,
            'version': '3.0',
            'description': 'AdGuard规则数据库'
        }
        with open(db_path, 'w', encoding='utf-8') as f:
            json.dump(db_data, f, ensure_ascii=False, indent=2)
        logger.info(f"语法数据库已保存到: {db_path}")

# -------------------------- 核心合并器（恢复原始布隆过滤器） --------------------------
class AdGuardMerger:
    def __init__(self, config: AdGuardConfig):
        self.config = config
        self.syntax_db = AdGuardSyntaxDatabase(config)

        # -------------------------- 恢复原始布隆过滤器（ScalableBloomFilter） --------------------------
        self.block_data = self._init_data_container()
        self.allow_data = self._init_data_container()
        self.global_stats = {"total_files": 0, "block_files": 0, "allow_files": 0}

    def _init_data_container(self) -> Dict:
        """恢复原脚本的ScalableBloomFilter，保留其他容器结构"""
        return {
            # 恢复原始布隆过滤器：pybloom_live.ScalableBloomFilter
            "bloom": ScalableBloomFilter(
                initial_capacity=self.config.BLOOM_INIT_CAP,
                error_rate=self.config.BLOOM_ERROR_RATE,
                mode=ScalableBloomFilter.SMALL_SET_GROWTH  # 原脚本默认模式
            ),
            "seen": set(),
            "seen_lock": Lock(),
            "rules": [],
            "stats": {"processed": 0, "valid": 0, "duplicate": 0, "invalid": 0}
        }

    # 以下方法（github_log、规则解析、分块读取等）完全保留整合优化，仅修改布隆过滤器调用
    def github_log(self, level: str, message: str):
        if self.config.GITHUB_ACTIONS:
            level_map = {'warning': 'warning', 'error': 'error', 'notice': 'notice', 'debug': 'debug'}
            print(f"::{level_map.get(level, 'notice')} ::{message}")
        else:
            getattr(logger, level)(message)

    def analyze_rule_syntax(self, rule: str) -> Dict[str, Any]:
        result = {'type': 'unknown', 'pattern_type': 'unknown', 'modifiers': [], 'dns_rewrite': None, 'is_valid': False, 'normalized': rule.strip()}
        if rule.startswith('!'):
            result['type'] = 'comment'
            return result
        rule = rule.strip()
        if not rule:
            result['type'] = 'empty'
            return result
        if len(rule) < self.config.MIN_RULE_LENGTH or len(rule) > self.config.MAX_RULE_LENGTH:
            result['type'] = 'invalid_length'
            return result
        for pattern_name, pattern in self.syntax_db.syntax_patterns.items():
            try:
                match = re.match(pattern, rule)
                if match:
                    result['pattern_type'] = pattern_name
                    result['type'] = self.syntax_db.rule_types.get(pattern_name, 'unknown')
                    if pattern_name == 'dns_rewrite':
                        result['dns_rewrite'] = match.group(1)
                    break
            except re.error:
                self.github_log('warning', f"正则错误: {pattern_name} - {pattern}")
                continue
        if '$' in rule:
            parts = rule.split('$', 1)
            result['normalized'] = parts[0].strip()
            modifiers_str = parts[1].strip()
            for mod_name, mod_pattern in self.syntax_db.modifiers.items():
                try:
                    if re.search(mod_pattern, modifiers_str):
                        result['modifiers'].append(mod_name)
                except re.error:
                    self.github_log('warning', f"修饰符正则错误: {mod_name} - {mod_pattern}")
                    continue
            if self.syntax_db.normalization_rules.get('sort_modifiers', True):
                result['modifiers'].sort()
        if rule.startswith('@@'):
            result['type'] = 'allow'
            result['is_valid'] = True
        return result

    def normalize_rule(self, rule: str) -> Optional[str]:
        analysis = self.analyze_rule_syntax(rule)
        if not analysis['is_valid']:
            return None
        normalized = analysis['normalized']
        if self.syntax_db.normalization_rules.get('lowercase_domain', True):
            if analysis['pattern_type'] in ['domain_rule', 'element_hiding', 'exception_rule']:
                try:
                    if analysis['pattern_type'] == 'domain_rule':
                        match = re.match(r'^\|\|([^\^]+)\^', normalized)
                        if match:
                            domain = match.group(1).lower()
                            normalized = f'||{domain}^'
                    elif analysis['pattern_type'] == 'element_hiding':
                        match = re.match(r'^([^#]+)##([^#]+)', normalized)
                        if match:
                            domain = match.group(1).lower()
                            selector = match.group(2).strip()
                            normalized = f'{domain}##{selector}'
                except re.error:
                    pass
        modifiers = analysis['modifiers']
        if modifiers:
            normalized += f"${','.join(modifiers)}"
        if analysis['dns_rewrite']:
            normalized += f"$dnsrewrite={analysis['dns_rewrite']}" if '$' not in normalized else f",dnsrewrite={analysis['dns_rewrite']}"
        return normalized

    # -------------------------- 调整布隆过滤器调用（适配ScalableBloomFilter的API） --------------------------
    def _is_duplicate(self, normalized_rule: str, data_container: Dict) -> bool:
        """原始布隆过滤器调用：ScalableBloomFilter用`__contains__`判断，无需自定义`might_contain`"""
        # 1. 布隆快速排除
        if normalized_rule not in data_container["bloom"]:
            return False
        # 2. 哈希表精确确认
        with data_container["seen_lock"]:
            return normalized_rule in data_container["seen"]

    def _validate_rule(self, analysis: Dict) -> bool:
        if analysis['pattern_type'] in ['domain_rule', 'element_hiding']:
            domain_match = re.search(r'^\|\|([^\^]+)\^' if analysis['pattern_type'] == 'domain_rule' else r'^([^#]+)##', analysis['normalized'])
            if domain_match and not validate_domain(domain_match.group(1)):
                logger.warning(f"无效域名: {domain_match.group(1)}")
                return False
        if analysis['dns_rewrite']:
            dns_data = parse_dns_rewrite(analysis['dns_rewrite'])
            if dns_data['rcode'] not in self.config.VALID_DNS_RCODES:
                logger.warning(f"无效DNS响应码: {dns_data['rcode']}")
                return False
            if dns_data['rr_type'] not in self.config.VALID_DNS_TYPES:
                logger.warning(f"无效DNS类型: {dns_data['rr_type']}")
                return False
        return True

    def _read_chunks(self, file_path: Path) -> Generator[str, None, None]:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            while chunk := f.read(self.config.CHUNK_SIZE):
                yield chunk

    def process_single_group(self, files: List[Path], data_container: dict, group_name: str) -> None:
        logger.info(f"\n=== 开始处理 {group_name} 组文件（共 {len(files)} 个）===")
        for file_path in files:
            try:
                for chunk in self._read_chunks(file_path):
                    for rule in chunk.splitlines():
                        data_container["stats"]["processed"] += 1
                        rule_stripped = rule.strip()
                        if not rule_stripped or rule_stripped.startswith("!"):
                            continue
                        analysis = self.analyze_rule_syntax(rule_stripped)
                        if not analysis['is_valid']:
                            data_container["stats"]["invalid"] += 1
                            continue
                        normalized_rule = self.normalize_rule(rule_stripped)
                        if not normalized_rule:
                            data_container["stats"]["invalid"] += 1
                            continue
                        if not self._validate_rule(analysis):
                            data_container["stats"]["invalid"] += 1
                            continue
                        if self._is_duplicate(normalized_rule, data_container):
                            data_container["stats"]["duplicate"] += 1
                            continue
                        # 原始布隆过滤器的add方法
                        data_container["bloom"].add(normalized_rule)
                        with data_container["seen_lock"]:
                            data_container["seen"].add(normalized_rule)
                        data_container["rules"].append(normalized_rule)
                        data_container["stats"]["valid"] += 1
                logger.info(f"处理完成: {file_path}")
            except Exception as e:
                self.github_log('error', f"处理文件 {file_path} 失败: {str(e)}")
        stats = data_container["stats"]
        logger.info(f"\n=== {group_name} 组统计 ===")
        logger.info(f"总处理: {stats['processed']} | 有效: {stats['valid']} | 重复: {stats['duplicate']} | 无效: {stats['invalid']}")

    def merge_and_deduplicate(self):
        logger.info("=== 开始AdGuard规则合并去重 ===")
        block_files, allow_files = self._get_files_by_prefix()
        self.global_stats = {"total_files": len(block_files) + len(allow_files), "block_files": len(block_files), "allow_files": len(allow_files)}
        logger.info(f"文件分类: 黑名单{len(block_files)}个 | 白名单{len(allow_files)}个 | 总计{self.global_stats['total_files']}个")
        if block_files:
            self.process_single_group(block_files, self.block_data, "黑名单")
        else:
            self.github_log('warning', "未找到黑名单文件（adblock前缀）")
        if allow_files:
            self.process_single_group(allow_files, self.allow_data, "白名单")
        else:
            self.github_log('warning', "未找到白名单文件（allow前缀）")

    def _get_files_by_prefix(self) -> Tuple[List[Path], List[Path]]:
        block_files = []
        allow_files = []
        if not self.config.INPUT_DIR.exists():
            self.config.INPUT_DIR.mkdir(parents=True, exist_ok=True)
            self.github_log('warning', f"输入目录不存在，已创建: {self.config.INPUT_DIR}")
        for pattern in self.config.ADBLOCK_PATTERNS:
            for file_path in self.config.INPUT_DIR.rglob(pattern):
                if not file_path.is_file():
                    continue
                if file_path.name.lower().startswith("adblock"):
                    block_files.append(file_path)
                elif file_path.name.lower().startswith("allow"):
                    allow_files.append(file_path)
        return block_files, allow_files

    def save_rules(self, platform: str = "adguard"):
        self.config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"\n=== 保存规则（输出目录: {self.config.OUTPUT_DIR}）===")
        block_rules = self._filter_platform_rules(self.block_data["rules"], platform)
        block_path = self.config.OUTPUT_DIR / self.config.OUTPUT_BLOCK
        with open(block_path, 'w', encoding='utf-8') as f:
            f.write(f"# AdGuard合并规则（{platform}）\n# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n# 规则数: {len(block_rules)}\n")
            f.write('\n'.join(sorted(block_rules)))
        logger.info(f"黑名单保存: {block_path}（{len(block_rules)}条）")
        allow_rules = self._filter_platform_rules(self.allow_data["rules"], platform)
        allow_path = self.config.OUTPUT_DIR / self.config.OUTPUT_ALLOW
        with open(allow_path, 'w', encoding='utf-8') as f:
            f.write(f"# AdGuard合并规则（{platform}）\n# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n# 规则数: {len(allow_rules)}\n")
            f.write('\n'.join(sorted(allow_rules)))
        logger.info(f"白名单保存: {allow_path}（{len(allow_rules)}条）")
        if self.config.GITHUB_ACTIONS:
            self._generate_github_summary(platform)

    def _filter_platform_rules(self, rules: List[str], platform: str) -> List[str]:
        if platform == "adguardhome":
            unsupported = self.config.ADGUARD_HOME_UNSUPPORTED
            return [r for r in rules if not any(rt in r for rt in unsupported)]
        return rules

    def _generate_github_summary(self, platform: str):
        summary = f"""## AdGuard规则处理结果（{platform}）
**处理时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**仓库**: {self.config.GITHUB_REPOSITORY}
**提交**: {self.config.GITHUB_SHA[:7]}
**分支**: {self.config.GITHUB_REF}

### 文件统计
- 总文件数: {self.global_stats['total_files']}
- 黑名单文件: {self.global_stats['block_files']}
- 白名单文件: {self.global_stats['allow_files']}

### 黑名单规则
- 总处理: {self.block_data['stats']['processed']} | 有效: {len(self.block_data['rules'])} | 最终输出: {len(self._filter_platform_rules(self.block_data['rules'], platform))}
- 重复: {self.block_data['stats']['duplicate']} | 无效: {self.block_data['stats']['invalid']}

### 白名单规则
- 总处理: {self.allow_data['stats']['processed']} | 有效: {len(self.allow_data['rules'])} | 最终输出: {len(self._filter_platform_rules(self.allow_data['rules'], platform))}
- 重复: {self.allow_data['stats']['duplicate']} | 无效: {self.allow_data['stats']['invalid']}

**输出文件**:
- 黑名单: {self.config.OUTPUT_BLOCK}
- 白名单: {self.config.OUTPUT_ALLOW}
        """
        with open(os.getenv('GITHUB_STEP_SUMMARY', ''), 'a') as f:
            f.write(summary)

# -------------------------- 主函数（完全保留原使用习惯） --------------------------
if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(description="AdGuard规则合并去重工具（恢复原始布隆过滤器）")
    parser.add_argument("-p", "--platform", default="adguard", choices=["adguard", "adguardhome"], help="目标平台（adguard/adguardhome）")
    args = parser.parse_args()
    config = AdGuardConfig()
    if config.GITHUB_ACTIONS:
        logger.info(f"运行环境: GitHub Actions - {config.GITHUB_WORKFLOW}")
        logger.info(f"仓库: {config.GITHUB_REPOSITORY} | 提交: {config.GITHUB_SHA[:7]} | 分支: {config.GITHUB_REF}")
    merger = AdGuardMerger(config)
    merger.merge_and_deduplicate()
    merger.save_rules(platform=args.platform)
    logger.info("=== 所有流程完成 ===")
