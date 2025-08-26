#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import subprocess
import yaml
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor


# ==================== 常量定义（恢复Clash黑白名单+独立Surge语法） ====================
# 1. Clash Rule-Set核心（纯Clash语法，恢复黑白名单双配置）
CLASH_BLOCK_HEADER = "#RULE-SET,ad-filter,REJECT"  # Clash黑名单头
CLASH_ALLOW_HEADER = "#RULE-SET,ad-filter,DIRECT"  # Clash白名单头（已恢复）
CLASH_VALID_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}
PRIORITY = {"whitelist": 90, "ad-filter": 100}  # 恢复白名单更高优先级

# 2. Surge混合语法（独立定义，不影响Clash）
SURGE_CONF_HEADER = "# Surge 混合语法广告拦截规则（AdGuard Home转换）\n# 语法：规则类型 规则值 动作（REJECT=拦截，DIRECT=放行）\n# 独立文件，不与Clash混淆\n"
SURGE_ACTION_MAP = {"REJECT": "REJECT", "DIRECT": "DIRECT"}
SURGE_RULE_TPL = "{rule_type} {value} {action}"

# 3. AdGuard规则正则（共用，但转换逻辑独立）
ADG_DOMAIN_SUFFIX = re.compile(r'^(?:@@)?\|\|([a-z0-9.-]+\.[a.[]{2,})\^?$', re.IGNORECASE)
ADG_DOMAIN_PLAIN = re.compile(r'^(?:@@)?([a-z0-9.-]+\.[a.[]{2,})$', re.IGNORECASE)
ADG_IP = re.compile(r'^0\.0\.0\.0\s+([a-z0-9.-]+\.[a.[]{2,})$', re.IGNORECASE)
ADG_REGEX = re.compile(r'^(?:@@)?\/([^\/]+?)\/$', re.IGNORECASE)


# ==================== 配置管理（恢复Clash白名单路径+独立Surge路径） ====================
class Config:
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    WORKSPACE = Path(GITHUB_WORKSPACE).resolve()

    # 恢复Clash黑白名单输入（AdGuard源文件）
    INPUT_BLOCK = WORKSPACE / os.getenv("INPUT_BLOCK", "adblock_adg.txt")  # 黑名单源
    INPUT_ALLOW = WORKSPACE / os.getenv("INPUT_ALLOW", "allow_adg.txt")    # 白名单源（已恢复）

    # 恢复Clash黑白名单YAML（纯Clash语法，无混合）
    CLASH_BLOCK_YAML = WORKSPACE / os.getenv("CLASH_BLOCK_YAML", "adblock_clash_block.yaml")  # 黑名单YAML
    CLASH_ALLOW_YAML = WORKSPACE / os.getenv("CLASH_ALLOW_YAML", "adblock_clash_allow.yaml")  # 白名单YAML（已恢复）

    # Mihomo编译（仅保留黑名单MRS，白名单MRS已删除，符合你最初需求）
    OUTPUT_MIHOMO_BLOCK = WORKSPACE / os.getenv("OUTPUT_MIHOMO_BLOCK", "adb.mrs")

    # 独立Surge输出（不影响Clash文件）
    OUTPUT_SURGE_CONF = WORKSPACE / os.getenv("OUTPUT_SURGE_CONF", "adblock_surge.conf")

    # Mihomo编译器配置（不变）
    MIHOMO_TOOL = WORKSPACE / os.getenv("MIHOMO_TOOL", "./data/mihomo-tool")
    MIHOMO_TOOL_SHA256 = os.getenv("MIHOMO_TOOL_SHA256", "")
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")

    def validate_path(self, path: Path, desc: str, is_input: bool = True) -> None:
        """恢复白名单路径验证"""
        if is_input and not path.exists():
            raise FileNotFoundError(f"【{desc}】文件不存在：{path}")
        if is_input and path.is_dir():
            raise IsADirectoryError(f"【{desc}】是目录，需提供文件：{path}")
        if not is_input:
            path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def valid_config(self) -> None:
        """恢复Clash白名单配置校验"""
        # 恢复Clash黑白名单输入校验
        self.validate_path(self.INPUT_BLOCK, "AdGuard黑名单规则", is_input=True)
        self.validate_path(self.INPUT_ALLOW, "AdGuard白名单规则", is_input=True)  # 恢复白名单校验
        # 恢复Clash黑白名单YAML输出校验
        self.validate_path(self.CLASH_BLOCK_YAML, "Clash黑名单YAML", is_input=False)
        self.validate_path(self.CLASH_ALLOW_YAML, "Clash白名单YAML", is_input=False)  # 恢复白名单YAML校验
        # Mihomo与Surge输出校验
        self.validate_path(self.OUTPUT_MIHOMO_BLOCK, "Mihomo黑名单MRS", is_input=False)
        self.validate_path(self.OUTPUT_SURGE_CONF, "Surge规则文件", is_input=False)
        # Mihomo编译器校验（不变）
        self.validate_path(self.MIHOMO_TOOL, "Mihomo编译器", is_input=True)
        if not os.access(self.MIHOMO_TOOL, os.X_OK):
            raise PermissionError(f"Mihomo编译器无执行权限：{self.MIHOMO_TOOL}（需 chmod +x）")
        if self.MIHOMO_TOOL_SHA256 and calculate_file_hash(self.MIHOMO_TOOL) != self.MIHOMO_TOOL_SHA256:
            raise ValueError(f"Mihomo哈希不匹配！预期：{self.MIHOMO_TOOL_SHA256[:16]}... 实际：{calculate_file_hash(self.MIHOMO_TOOL)[:16]}...")


# ==================== 日志配置（不变） ====================
def setup_logger() -> logging.Logger:
    logger = logging.getLogger("Clash(黑白名单)+Surge")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"))
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ==================== 核心工具函数（恢复Clash白名单转换+独立Surge转换） ====================
def load_adg_rules(adg_file: Path) -> List[str]:
    """恢复：加载AdGuard规则（黑白名单共用，跳过注释）"""
    rules = []
    with adg_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", "/*")):
                continue
            rules.append(line)
    logger.info(f"加载AdGuard规则：{adg_file.name} → 有效规则{len(rules)}条")
    return rules


def adg_to_clash_rule(adg_rule: str, is_allow: bool) -> Optional[str]:
    """恢复：AdGuard→纯Clash Rule-Set规则（区分黑白名单，无任何混合语法）"""
    # 白名单强制DIRECT，黑名单按@@判断（恢复原逻辑）
    action = "DIRECT" if is_allow or adg_rule.startswith("@@") else "REJECT"
    clean_rule = adg_rule[2:] if adg_rule.startswith("@@") else adg_rule

    # 纯Clash语法，不混入任何Surge格式
    if match := ADG_DOMAIN_SUFFIX.match(clean_rule):
        return f"DOMAIN-SUFFIX,{match.group(1).lower()},{action}"
    elif match := ADG_DOMAIN_PLAIN.match(clean_rule):
        return f"DOMAIN,{match.group(1).lower()},{action}"
    elif match := ADG_IP.match(clean_rule):
        return f"IP-CIDR,{match.group(1).lower()}/32,{action}"
    elif match := ADG_REGEX.match(clean_rule):
        return f"DOMAIN-KEYWORD,{match.group(1).lower()},{action}"
    else:
        logger.debug(f"跳过非Clash规则：{adg_rule}")
        return None


def generate_clash_yaml(config: Config, is_allow: bool) -> Path:
    """恢复：生成纯Clash语法YAML（区分黑白名单，无混合）"""
    # 恢复黑白名单文件区分
    adg_file = config.INPUT_ALLOW if is_allow else config.INPUT_BLOCK
    yaml_path = config.CLASH_ALLOW_YAML if is_allow else config.CLASH_BLOCK_YAML
    yaml_header = CLASH_ALLOW_HEADER if is_allow else CLASH_BLOCK_HEADER

    # 恢复Clash规则转换逻辑
    adg_rules = load_adg_rules(adg_file)
    clash_rules = [r for r in (adg_to_clash_rule(line, is_allow) for line in adg_rules) if r]
    if not clash_rules:
        raise ValueError(f"无有效规则生成Clash {'白名单' if is_allow else '黑名单'}YAML：{adg_file.name}")

    # 写入纯Clash语法YAML（无任何Surge内容）
    with yaml_path.open("w", encoding="utf-8") as f:
        f.write(f"{yaml_header}\n")
        yaml.dump(
            {"payload": clash_rules},
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )

    logger.info(f"生成纯Clash{'白名单' if is_allow else '黑名单'}YAML：{yaml_path.name} → 规则{len(clash_rules)}条")
    return yaml_path


def adg_to_surge_rule(adg_rule: str, is_allow: bool) -> Optional[str]:
    """新增：AdGuard→纯Surge混合语法（独立逻辑，不影响Clash）"""
    action = SURGE_ACTION_MAP["DIRECT"] if is_allow or adg_rule.startswith("@@") else SURGE_ACTION_MAP["REJECT"]
    clean_rule = adg_rule[2:] if adg_rule.startswith("@@") else adg_rule

    # 纯Surge语法，与Clash完全区分
    if match := ADG_DOMAIN_SUFFIX.match(clean_rule):
        return SURGE_RULE_TPL.format(rule_type="DOMAIN-SUFFIX", value=match.group(1).lower(), action=action)
    elif match := ADG_DOMAIN_PLAIN.match(clean_rule):
        return SURGE_RULE_TPL.format(rule_type="DOMAIN", value=match.group(1).lower(), action=action)
    elif match := ADG_IP.match(clean_rule):
        return SURGE_RULE_TPL.format(rule_type="IP-CIDR", value=f"{match.group(1).lower()}/32", action=action)
    elif match := ADG_REGEX.match(clean_rule):
        return SURGE_RULE_TPL.format(rule_type="DOMAIN-KEYWORD", value=match.group(1).lower(), action=action)
    else:
        logger.debug(f"跳过非Surge规则：{adg_rule}")
        return None


def generate_surge_conf(config: Config) -> Path:
    """新增：生成纯Surge规则文件（独立文件，不与Clash混淆）"""
    # 合并AdGuard黑白名单规则，按动作分类
    allow_rules = load_adg_rules(config.INPUT_ALLOW)
    block_rules = load_adg_rules(config.INPUT_BLOCK)
    # 转换为Surge语法（区分黑白名单动作）
    surge_allow = [r for r in (adg_to_surge_rule(line, is_allow=True) for line in allow_rules) if r]
    surge_block = [r for r in (adg_to_surge_rule(line, is_allow=False) for line in block_rules) if r]
    total_surge = surge_allow + surge_block

    if not total_surge:
        raise ValueError("无有效规则生成Surge配置文件")

    # 写入纯Surge文件（无任何Clash内容）
    with config.OUTPUT_SURGE_CONF.open("w", encoding="utf-8") as f:
        f.write(SURGE_CONF_HEADER)
        f.write("\n# === 白名单（DIRECT 放行）===\n")
        for rule in surge_allow:
            f.write(f"{rule}\n")
        f.write("\n# === 黑名单（REJECT 拦截）===\n")
        for rule in surge_block:
            f.write(f"{rule}\n")

    logger.info(f"生成纯Surge规则文件：{config.OUTPUT_SURGE_CONF.name} → 总规则{len(total_surge)}条（放行{len(surge_allow)}条/拦截{len(surge_block)}条）")
    return config.OUTPUT_SURGE_CONF


def clash_to_mihomo_block_mrs(config: Config, clash_yaml: Path) -> None:
    """不变：仅用Mihomo编译Clash黑名单YAML为MRS（白名单MRS不编译，符合需求）"""
    cmd = [
        str(config.MIHOMO_TOOL),
        "convert-ruleset",
        config.RULE_TYPE,
        "yaml",  # 明确输入为纯Clash格式
        str(clash_yaml),
        str(config.OUTPUT_MIHOMO_BLOCK),
        "--priority", str(PRIORITY["ad-filter"])
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=True)
        if not config.OUTPUT_MIHOMO_BLOCK.exists() or config.OUTPUT_MIHOMO_BLOCK.stat().st_size == 0:
            raise RuntimeError("Mihomo黑名单MRS生成失败")
        size_kb = config.OUTPUT_MIHOMO_BLOCK.stat().st_size / 1024
        logger.info(f"编译Mihomo黑名单MRS成功：{config.OUTPUT_MIHOMO_BLOCK.name} | 大小{size_kb:.2f}KB | 优先级{PRIORITY['ad-filter']}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Mihomo编译失败：{' '.join(cmd)}\n错误：{e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"MRS异常：{str(e)}")
        sys.exit(1)


def calculate_file_hash(file_path: Path) -> str:
    """不变：文件哈希计算"""
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ==================== 主流程（恢复Clash黑白名单+独立Surge，并行处理） ====================
def main() -> int:
    try:
        # 1. 配置校验（含Clash白名单）
        config = Config()
        config.valid_config
        logger.info("=" * 60)
        logger.info("功能：1.Clash黑白名单YAML生成（纯Clash语法） 2.Mihomo黑名单MRS编译 3.Surge规则生成（独立）")
        logger.info(f"工作目录：{config.WORKSPACE}")
        logger.info(f"Clash白名单YAML：{config.CLASH_ALLOW_YAML.name} | Clash黑名单YAML：{config.CLASH_BLOCK_YAML.name}")
        logger.info(f"Surge独立文件：{config.OUTPUT_SURGE_CONF.name} | Mihomo输出：{config.OUTPUT_MIHOMO_BLOCK.name}")
        logger.info("=" * 60)

        # 2. 并行处理3个核心任务（互不干扰）
        with ThreadPoolExecutor(max_workers=3) as executor:
            # 任务1：生成Clash白名单YAML（纯Clash语法）
            executor.submit(lambda: generate_clash_yaml(config, is_allow=True))
            # 任务2：生成Clash黑名单YAML → 编译为Mihomo MRS（纯Clash输入）
            executor.submit(lambda: clash_to_mihomo_block_mrs(config, generate_clash_yaml(config, is_allow=False)))
            # 任务3：生成独立Surge规则文件（纯Surge语法）
            executor.submit(lambda: generate_surge_conf(config))

        # 3. 最终结果（明确各文件语法类型，无混合）
        logger.info("=" * 60)
        logger.info("全部流程完成！各文件说明（语法纯净，无混合）：")
        logger.info(f"1. [纯Clash] 白名单YAML：{config.CLASH_ALLOW_YAML}（SHA256：{calculate_file_hash(config.CLASH_ALLOW_YAML)[:16]}...）")
        logger.info(f"2. [纯Clash] 黑名单YAML：{config.CLASH_BLOCK_YAML}（SHA256：{calculate_file_hash(config.CLASH_BLOCK_YAML)[:16]}...）")
        logger.info(f"3. [Mihomo]  黑名单MRS：{config.OUTPUT_MIHOMO_BLOCK}（SHA256：{calculate_file_hash(config.OUTPUT_MIHOMO_BLOCK)[:16]}...）")
        logger.info(f"4. [纯Surge] 规则文件：{config.OUTPUT_SURGE_CONF}（SHA256：{calculate_file_hash(config.OUTPUT_SURGE_CONF)[:16]}...）")
        logger.info("=" * 60)
        return 0

    except (FileNotFoundError, PermissionError, ValueError) as e:
        logger.error(f"配置/文件错误：{str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序异常：{str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
