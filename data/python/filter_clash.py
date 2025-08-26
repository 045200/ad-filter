#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import uuid
import tempfile
import subprocess
import yaml
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Iterable, Any, Union
from concurrent.futures import ThreadPoolExecutor


# ==================== 常量定义 ====================
CLASH_BLOCK_HEADER = "#RULE-SET,ad-filter,REJECT"
CLASH_ALLOW_HEADER = "#RULE-SET,ad-filter,DIRECT"

CLASH_TO_MIHOMO_TYPE = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain-suffix",
    "DOMAIN-KEYWORD": "domain-keyword",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip-cidr6",
    "GEOIP": "geoip",
    "SRC-IP-CIDR": "src-ip-cidr",
    "SRC-PORT": "src-port",
    "DST-PORT": "dst-port",
    "PROCESS-NAME": "process-name",
    "PROCESS-PATH": "process-path"
}
ACTION_MAP = {
    "REJECT": "reject",
    "DIRECT": "direct",
    "PROXY": "proxy"
}

DEFAULT_PRIORITY = 100
WHITELIST_PRIORITY = DEFAULT_PRIORITY - 10

DOMAIN_PATTERN = re.compile(
    r'^\|\|([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$',
    re.IGNORECASE | re.ASCII
)
IP_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', re.ASCII)
REGEX_PATTERN = re.compile(r'^\/([^\/]+?)\/$')


# ==================== 配置管理 ====================
class Config:
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    # 输入输出路径
    INPUT_BLOCK = os.getenv("INPUT_BLOCK", "adblock_adg.txt")
    INPUT_ALLOW = os.getenv("INPUT_ALLOW", "allow_adg.txt")
    OUTPUT_CLASH_BLOCK = os.getenv("OUTPUT_CLASH_BLOCK", "adblock_clash_block.yaml")
    OUTPUT_CLASH_ALLOW = os.getenv("OUTPUT_CLASH_ALLOW", "adblock_clash_allow.yaml")
    OUTPUT_SURGE = os.getenv("OUTPUT_SURGE", "adblock_surge.conf")
    OUTPUT_MIHOMO = os.getenv("OUTPUT_MIHOMO", "adb.mrs")

    # Mihomo配置
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")
    MIHOMO_COMPILER_SHA256 = os.getenv("MIHOMO_COMPILER_SHA256", "")

    @property
    def workspace(self) -> Path:
        return Path(self.GITHUB_WORKSPACE).resolve()

    def _validate_file(self, path: Path, desc: str) -> Path:
        if not path.exists():
            raise FileNotFoundError(f"{desc}文件不存在：{path}")
        if path.is_dir():
            raise IsADirectoryError(f"{desc}路径是目录，需提供文件：{path}")
        return path

    @property
    def block_file(self) -> Path:
        return self._validate_file(self.workspace / self.INPUT_BLOCK, "拦截规则")

    @property
    def allow_file(self) -> Path:
        return self._validate_file(self.workspace / self.INPUT_ALLOW, "白名单规则")

    @property
    def clash_block_output(self) -> Path:
        path = self.workspace / self.OUTPUT_CLASH_BLOCK
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def clash_allow_output(self) -> Path:
        path = self.workspace / self.OUTPUT_CLASH_ALLOW
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def surge_output(self) -> Path:
        path = self.workspace / self.OUTPUT_SURGE
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def mihomo_output(self) -> Path:
        path = self.workspace / self.OUTPUT_MIHOMO
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def mihomo_compiler(self) -> Path:
        path = Path(self.COMPILER_PATH)
        path = path if path.is_absolute() else self.workspace / path
        self._validate_file(path, "Mihomo编译工具")
        
        # 增加哈希校验（如果配置了校验值）
        if self.MIHOMO_COMPILER_SHA256:
            actual_hash = calculate_file_hash(path)
            if actual_hash != self.MIHOMO_COMPILER_SHA256:
                raise ValueError(f"Mihomo工具哈希校验失败：{path} (预期: {self.MIHOMO_COMPILER_SHA256[:16]}..., 实际: {actual_hash[:16]}...)")
        
        if not os.access(path, os.X_OK):
            raise PermissionError(f"Mihomo工具无执行权限：{path}（需执行 chmod +x {path}）")
        return path


# ==================== 日志系统 ====================
class RequestContextFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = uuid.uuid4().hex[:8]
        return True

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AdblockConverter")
    logger.setLevel(logging.INFO)
    logger.addFilter(RequestContextFilter())

    formatter = logging.Formatter(
        "[%(asctime)s] [%(request_id)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ==================== 核心工具函数 ====================
def load_rules(file_path: Path) -> Iterable[str]:
    try:
        with file_path.open("r", encoding="utf-8", errors="strict") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith(("!", "#")):
                    continue
                yield line
    except UnicodeDecodeError as e:
        logger.error(f"文件编码错误（仅支持UTF-8）：{file_path}，行{line_num}：{e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"读取文件失败：{file_path}，原因：{str(e)}")
        sys.exit(1)

def convert_adg_to_rule(rule_line: str, is_allow: bool, target_format: str) -> List[Union[str, Dict]]:
    converted = []
    is_exception = rule_line.startswith("@@")
    clean_rule = rule_line[2:] if is_exception else rule_line
    action = "DIRECT" if (is_allow or is_exception) else "REJECT"

    # 1. 域名规则
    if domain_match := DOMAIN_PATTERN.match(clean_rule):
        domain = clean_rule.strip("||^")
        if target_format == "clash":
            converted.append(f"+.{domain}")
        elif target_format == "surge":
            converted.append(f"DOMAIN-SUFFIX,{domain},{action}")
        elif target_format == "mihomo":
            converted.append({
                "type": "domain-suffix",
                "value": domain,
                "action": ACTION_MAP[action],
                "priority": WHITELIST_PRIORITY if is_allow else DEFAULT_PRIORITY
            })
        return converted

    # 2. IP规则
    if ip_match := IP_PATTERN.match(clean_rule):
        ip = ip_match.group(1)
        cidr_ip = f"{ip}/32"
        base_rule = f"IP-CIDR,{cidr_ip},{action}"
        if target_format in ("clash", "surge"):
            converted.append(base_rule)
        elif target_format == "mihomo":
            converted.append({
                "type": "ip-cidr",
                "value": cidr_ip,
                "action": ACTION_MAP[action],
                "priority": DEFAULT_PRIORITY
            })
        return converted

    # 3. 正则规则
    if regex_match := REGEX_PATTERN.match(clean_rule):
        keyword = regex_match.group(1)
        base_rule = f"DOMAIN-KEYWORD,{keyword},{action}"
        if target_format in ("clash", "surge"):
            converted.append(base_rule)
        elif target_format == "mihomo":
            converted.append({
                "type": "domain-keyword",
                "value": keyword,
                "action": ACTION_MAP[action],
                "priority": DEFAULT_PRIORITY
            })
        return converted

    # 未匹配规则
    logger.warning(f"跳过不支持的规则：{rule_line}", extra={"request_id": logger.handlers[0].filter.request_id})
    return converted

def process_rules(file_path: Path, is_allow: bool, target_format: str) -> List[Union[str, Dict]]:
    rules = []
    seen = set()

    for rule_line in load_rules(file_path):
        for converted_rule in convert_adg_to_rule(rule_line, is_allow, target_format):
            if isinstance(converted_rule, str):
                rule_key = converted_rule
            else:
                rule_key = f"{converted_rule['type']}_{converted_rule['value']}_{converted_rule['action']}"

            if rule_key not in seen:
                seen.add(rule_key)
                rules.append(converted_rule)

    logger.info(f"处理完成：{file_path.name}，有效规则{len(rules)}条（去重后）")
    return rules


# ==================== 格式生成函数 ====================
def generate_clash_output_from_rules(config: Config, rules: List[str], is_allow: bool) -> None:
    output_path = config.clash_allow_output if is_allow else config.clash_block_output
    header = CLASH_ALLOW_HEADER if is_allow else CLASH_BLOCK_HEADER

    with output_path.open("w", encoding="utf-8") as f:
        f.write(f"{header}\n")
        yaml.dump(
            {"payload": [f"- '{rule}'" for rule in rules]},
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )
    logger.info(f"Clash{'白名单' if is_allow else '拦截'}规则已写入：{output_path}（{len(rules)}条）")

def generate_surge_output_from_rules(config: Config, rules: List[str]) -> None:
    with config.surge_output.open("w", encoding="utf-8") as f:
        f.write("[Rule]\n")
        f.write("\n".join(rules))
        f.write("\nFINAL,DIRECT\n")
    logger.info(f"Surge规则已写入：{config.surge_output}（{len(rules)}条）")

def generate_mihomo_output_from_rules(config: Config, rules: List[Dict]) -> None:
    sorted_rules = sorted(rules, key=lambda x: x["priority"])
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=True, encoding="utf-8") as temp_yaml:
        yaml.dump({"rules": sorted_rules}, temp_yaml, sort_keys=False, allow_unicode=True)
        temp_yaml.flush()

        cmd = [
            str(config.mihomo_compiler),
            "convert-ruleset",
            config.RULE_TYPE,
            "yaml",
            temp_yaml.name,
            str(config.mihomo_output)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True
            )
            size_kb = config.mihomo_output.stat().st_size / 1024
            logger.info(f"MRS编译成功：{config.mihomo_output}（大小：{size_kb:.2f} KB）")
        except subprocess.CalledProcessError as e:
            logger.error(f"MRS编译失败：{e.stderr}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"MRS编译异常：{str(e)}")
            sys.exit(1)


# ==================== 辅助功能 ====================
def calculate_file_hash(file_path: Path) -> str:
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def write_github_output(config: Config, counts: Dict[str, int]) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return

    outputs = {
        "clash_block_path": str(config.clash_block_output),
        "clash_allow_path": str(config.clash_allow_output),
        "surge_path": str(config.surge_output),
        "mrs_path": str(config.mihomo_output),
        "mrs_sha256": calculate_file_hash(config.mihomo_output),
        "clash_block_count": str(counts["clash_block_count"]),
        "clash_allow_count": str(counts["clash_allow_count"]),
        "surge_count": str(counts["surge_count"]),
        "mihomo_count": str(counts["mihomo_count"])
    }

    with open(github_output, "a", encoding="utf-8") as f:
        for key, value in outputs.items():
            f.write(f"{key}={value.replace('\\n', '\\\\n')}\n")
    logger.info("GitHub Action输出变量已写入")


# ==================== 主流程 ====================
def main() -> int:
    try:
        config = Config()
        logger.info("=" * 60)
        logger.info("AdGuard规则转换工具启动（适配Clash/Surge/Mihomo最新版）")
        logger.info(f"工作目录：{config.workspace}")
        logger.info("=" * 60)

        # 先处理并缓存所有规则
        logger.info("开始处理规则文件...")
        allow_rules_clash = process_rules(config.allow_file, True, "clash")
        block_rules_clash = process_rules(config.block_file, False, "clash")
        allow_rules_surge = process_rules(config.allow_file, True, "surge")
        block_rules_surge = process_rules(config.block_file, False, "surge")
        allow_rules_mihomo = process_rules(config.allow_file, True, "mihomo")
        block_rules_mihomo = process_rules(config.block_file, False, "mihomo")
        
        # 多线程并行生成输出
        with ThreadPoolExecutor(max_workers=3) as executor:
            # 提交Clash白名单、拦截规则任务
            executor.submit(generate_clash_output_from_rules, config, allow_rules_clash, True)
            executor.submit(generate_clash_output_from_rules, config, block_rules_clash, False)
            # 提交Surge和Mihomo任务
            executor.submit(generate_surge_output_from_rules, config, allow_rules_surge + block_rules_surge)
            executor.submit(generate_mihomo_output_from_rules, config, allow_rules_mihomo + block_rules_mihomo)

        # 等待所有线程完成后，输出汇总信息
        logger.info("=" * 60)
        logger.info("规则转换完成汇总：")
        logger.info(f"- Clash白名单：{config.clash_allow_output}（{len(allow_rules_clash)}条）")
        logger.info(f"- Clash拦截：{config.clash_block_output}（{len(block_rules_clash)}条）")
        logger.info(f"- Surge：{config.surge_output}（{len(allow_rules_surge) + len(block_rules_surge)}条）")
        logger.info(f"- Mihomo MRS：{config.mihomo_output}（SHA256：{calculate_file_hash(config.mihomo_output)[:16]}...）")
        logger.info("=" * 60)

        # 写入GitHub Action输出
        write_github_output(config, {
            "clash_block_count": len(block_rules_clash),
            "clash_allow_count": len(allow_rules_clash),
            "surge_count": len(allow_rules_surge) + len(block_rules_surge),
            "mihomo_count": len(allow_rules_mihomo) + len(block_rules_mihomo)
        })
        return 0

    except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as e:
        logger.error(f"配置/文件错误：{str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序异常：{str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())