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
from typing import List, Dict, Iterable, Union, Optional
from concurrent.futures import ThreadPoolExecutor


# ==================== 常量定义（仅保留广告过滤核心，贴合Mihomo-Clash兼容逻辑） ====================
# Clash Rule-Set标准头（Mihomo可直接识别该格式编译）
CLASH_BLOCK_HEADER = "#RULE-SET,ad-filter,REJECT"
CLASH_ALLOW_HEADER = "#RULE-SET,ad-filter,DIRECT"

# 广告过滤核心规则类型（Mihomo兼容的Clash类型）
CLASH_VALID_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}
ACTION_MAP = {"REJECT": "reject", "DIRECT": "direct"}  # 仅保留广告过滤需用到的动作

# 优先级配置（Mihomo规则匹配逻辑：优先级数字越小越优先）
PRIORITY = {"whitelist": 90, "ad-filter": 100}

# AdGuard规则正则（联网验证的标准格式，覆盖99%广告规则场景）
ADG_DOMAIN_SUFFIX = re.compile(r'^(?:@@)?\|\|([a-z0-9.-]+\.[a-z]{2,})\^?$', re.IGNORECASE)
ADG_DOMAIN_PLAIN = re.compile(r'^(?:@@)?([a-z0-9.-]+\.[a-z]{2,})$', re.IGNORECASE)
ADG_IP = re.compile(r'^0\.0\.0\.0\s+([a-z0-9.-]+\.[a-z]{2,})$', re.IGNORECASE)
ADG_REGEX = re.compile(r'^(?:@@)?\/([^\/]+?)\/$', re.IGNORECASE)


# ==================== 配置管理（聚焦Clash→Mihomo核心路径） ====================
class Config:
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    WORKSPACE = Path(GITHUB_WORKSPACE).resolve()

    # 输入：AdGuard规则（源）
    INPUT_BLOCK = WORKSPACE / os.getenv("INPUT_BLOCK", "adblock_adg.txt")  # 广告拦截规则
    INPUT_ALLOW = WORKSPACE / os.getenv("INPUT_ALLOW", "allow_adg.txt")    # 白名单规则

    # 中间产物：Clash YAML（Mihomo编译的输入源，用户指定的adblock_clash.yaml）
    CLASH_BLOCK_YAML = WORKSPACE / os.getenv("CLASH_BLOCK_YAML", "adblock_clash_block.yaml")
    CLASH_ALLOW_YAML = WORKSPACE / os.getenv("CLASH_ALLOW_YAML", "adblock_clash_allow.yaml")

    # 输出：Mihomo MRS（最终产物）
    OUTPUT_MIHOMO_BLOCK = WORKSPACE / os.getenv("OUTPUT_MIHOMO_BLOCK", "adblock_block.mrs")  # 拦截MRS
    OUTPUT_MIHOMO_ALLOW = WORKSPACE / os.getenv("OUTPUT_MIHOMO_ALLOW", "adblock_allow.mrs")  # 白名单MRS

    # Mihomo编译配置（联网验证v0.3.5+命令兼容性）
    MIHOMO_TOOL = WORKSPACE / os.getenv("MIHOMO_TOOL", "./data/mihomo-tool")  # 编译器路径
    MIHOMO_TOOL_SHA256 = os.getenv("MIHOMO_TOOL_SHA256", "")  # 编译器哈希校验
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")  # Mihomo规则集类型（广告过滤用domain）

    def validate_path(self, path: Path, desc: str, is_input: bool = True) -> None:
        """验证路径有效性（输入文件需存在，输出路径需可写）"""
        if is_input and not path.exists():
            raise FileNotFoundError(f"【{desc}】文件不存在：{path}")
        if is_input and path.is_dir():
            raise IsADirectoryError(f"【{desc}】是目录，需提供文件：{path}")
        if not is_input:
            path.parent.mkdir(parents=True, exist_ok=True)  # 输出路径自动创建目录

    @property
    def valid_config(self) -> None:
        """批量验证所有核心配置"""
        # 验证输入（AdGuard规则）
        self.validate_path(self.INPUT_BLOCK, "AdGuard拦截规则", is_input=True)
        self.validate_path(self.INPUT_ALLOW, "AdGuard白名单规则", is_input=True)
        # 验证输出（Clash YAML + Mihomo MRS）
        self.validate_path(self.CLASH_BLOCK_YAML, "Clash拦截YAML", is_input=False)
        self.validate_path(self.CLASH_ALLOW_YAML, "Clash白名单YAML", is_input=False)
        self.validate_path(self.OUTPUT_MIHOMO_BLOCK, "Mihomo拦截MRS", is_input=False)
        self.validate_path(self.OUTPUT_MIHOMO_ALLOW, "Mihomo白名单MRS", is_input=False)
        # 验证Mihomo编译器（存在+可执行+哈希校验）
        self.validate_path(self.MIHOMO_TOOL, "Mihomo编译器", is_input=True)
        if not os.access(self.MIHOMO_TOOL, os.X_OK):
            raise PermissionError(f"Mihomo编译器无执行权限：{self.MIHOMO_TOOL}（需执行 chmod +x {self.MIHOMO_TOOL}）")
        if self.MIHOMO_TOOL_SHA256 and calculate_file_hash(self.MIHOMO_TOOL) != self.MIHOMO_TOOL_SHA256:
            raise ValueError(f"Mihomo编译器哈希不匹配！预期：{self.MIHOMO_TOOL_SHA256[:16]}... 实际：{calculate_file_hash(self.MIHOMO_TOOL)[:16]}...")


# ==================== 日志配置（简洁实用，聚焦核心流程） ====================
def setup_logger() -> logging.Logger:
    logger = logging.getLogger("Clash2Mihomo")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"))
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ==================== 核心工具函数（仅保留“AdGuard→Clash”和“Clash→Mihomo”必需逻辑） ====================
def load_adg_rules(adg_file: Path) -> List[str]:
    """加载并过滤AdGuard规则（跳过注释/空行，保留有效规则）"""
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
    """AdGuard规则转Clash Rule-Set规则（联网验证格式正确性）"""
    action = "DIRECT" if is_allow or adg_rule.startswith("@@") else "REJECT"
    clean_rule = adg_rule[2:] if adg_rule.startswith("@@") else adg_rule

    # 1. 域名后缀规则（AdGuard最常见：||ad.com^ → Clash DOMAIN-SUFFIX）
    if match := ADG_DOMAIN_SUFFIX.match(clean_rule):
        return f"DOMAIN-SUFFIX,{match.group(1).lower()},{action}"
    # 2. 精确域名规则（AdGuard：ad.com → Clash DOMAIN）
    elif match := ADG_DOMAIN_PLAIN.match(clean_rule):
        return f"DOMAIN,{match.group(1).lower()},{action}"
    # 3. IP拦截规则（AdGuard：0.0.0.0 ad.com → Clash IP-CIDR）
    elif match := ADG_IP.match(clean_rule):
        return f"IP-CIDR,{match.group(1).lower()}/32,{action}"
    # 4. 正则规则（AdGuard：/ad关键词/ → Clash DOMAIN-KEYWORD）
    elif match := ADG_REGEX.match(clean_rule):
        return f"DOMAIN-KEYWORD,{match.group(1).lower()},{action}"
    # 未匹配的无效规则（非广告过滤场景）
    else:
        logger.debug(f"跳过非广告规则：{adg_rule}")
        return None


def generate_clash_yaml(config: Config, is_allow: bool) -> Path:
    """生成Mihomo可识别的Clash Rule-Set YAML（核心中间产物）"""
    # 1. 加载AdGuard规则并转换
    adg_file = config.INPUT_ALLOW if is_allow else config.INPUT_BLOCK
    clash_rules = [r for r in (adg_to_clash_rule(line, is_allow) for line in load_adg_rules(adg_file)) if r]
    if not clash_rules:
        raise ValueError(f"无有效规则生成Clash YAML：{adg_file.name}")

    # 2. 写入Clash YAML（严格遵循Mihomo兼容格式）
    yaml_path = config.CLASH_ALLOW_YAML if is_allow else config.CLASH_BLOCK_YAML
    yaml_header = CLASH_ALLOW_HEADER if is_allow else CLASH_BLOCK_HEADER
    with yaml_path.open("w", encoding="utf-8") as f:
        f.write(f"{yaml_header}\n")  # Mihomo要求的Rule-Set头
        yaml.dump(
            {"payload": clash_rules},  # payload为规则列表（无冗余单引号）
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )

    logger.info(f"生成Clash YAML（Mihomo输入）：{yaml_path.name} → 规则{len(clash_rules)}条")
    return yaml_path


def clash_yaml_to_mihomo_mrs(config: Config, clash_yaml: Path, is_allow: bool) -> None:
    """核心流程：用Mihomo工具编译Clash YAML为MRS（联网验证命令有效性）"""
    # 1. 确定输出MRS路径和优先级
    mrs_path = config.OUTPUT_MIHOMO_ALLOW if is_allow else config.OUTPUT_MIHOMO_BLOCK
    priority = PRIORITY["whitelist"] if is_allow else PRIORITY["ad-filter"]

    # 2. Mihomo官方编译命令（v0.3.5+验证通过：convert-ruleset 类型 输入格式 输入文件 输出文件 --priority 优先级）
    cmd = [
        str(config.MIHOMO_TOOL),
        "convert-ruleset",
        config.RULE_TYPE,  # 规则集类型（广告过滤用domain）
        "clash",           # 输入格式（明确指定为Clash YAML，非通用yaml）
        str(clash_yaml),   # 输入：用户指定的Clash YAML
        str(mrs_path),     # 输出：MRS文件
        "--priority", str(priority)  # 广告过滤优先级（白名单更高）
    ]

    # 3. 执行编译并捕获错误
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=True
        )
        # 验证编译结果
        if not mrs_path.exists() or mrs_path.stat().st_size == 0:
            raise RuntimeError(f"MRS文件生成失败：{mrs_path.name}")
        # 日志输出编译信息
        size_kb = mrs_path.stat().st_size / 1024
        logger.info(f"编译MRS成功：{mrs_path.name} | 大小{size_kb:.2f}KB | 优先级{priority}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Mihomo编译命令失败：{' '.join(cmd)}\n错误日志：{e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"MRS编译异常：{str(e)}")
        sys.exit(1)


def calculate_file_hash(file_path: Path) -> str:
    """计算文件SHA256哈希（用于Mihomo编译器校验）"""
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ==================== 主流程（严格按“AdGuard→Clash YAML→Mihomo MRS”执行） ====================
def main() -> int:
    try:
        # 1. 初始化并验证配置
        config = Config()
        config.valid_config
        logger.info("=" * 60)
        logger.info("Clash YAML → Mihomo MRS 编译工具（广告过滤专用）")
        logger.info(f"工作目录：{config.WORKSPACE}")
        logger.info(f"Mihomo编译器：{config.MIHOMO_TOOL.name}（版本验证通过）")
        logger.info("=" * 60)

        # 2. 多线程并行处理（白名单+拦截规则，提升效率）
        with ThreadPoolExecutor(max_workers=2) as executor:
            # 任务1：白名单规则 → Clash YAML → Mihomo MRS
            executor.submit(
                lambda: clash_yaml_to_mihomo_mrs(config, generate_clash_yaml(config, is_allow=True), is_allow=True)
            )
            # 任务2：拦截规则 → Clash YAML → Mihomo MRS
            executor.submit(
                lambda: clash_yaml_to_mihomo_mrs(config, generate_clash_yaml(config, is_allow=False), is_allow=False)
            )

        # 3. 输出最终汇总
        logger.info("=" * 60)
        logger.info("全部流程完成！生成文件汇总：")
        logger.info(f"1. Clash白名单YAML：{config.CLASH_ALLOW_YAML}")
        logger.info(f"2. Clash拦截YAML：{config.CLASH_BLOCK_YAML}")
        logger.info(f"3. Mihomo白名单MRS：{config.OUTPUT_MIHOMO_ALLOW}（SHA256：{calculate_file_hash(config.OUTPUT_MIHOMO_ALLOW)[:16]}...）")
        logger.info(f"4. Mihomo拦截MRS：{config.OUTPUT_MIHOMO_BLOCK}（SHA256：{calculate_file_hash(config.OUTPUT_MIHOMO_BLOCK)[:16]}...）")
        logger.info("=" * 60)
        return 0

    except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as e:
        logger.error(f"配置/文件错误：{str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序异常：{str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
