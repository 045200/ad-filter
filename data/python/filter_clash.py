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
from concurrent.futures import ThreadPoolExecutor  # 引入多线程提升效率


# ==================== 常量定义（严格遵循需求） ====================
# Clash规则集文件头（仅保留放行/拦截，无额外冗余信息）
CLASH_BLOCK_HEADER = "#RULE-SET,ad-filter,REJECT"  # 拦截规则头（动作固定REJECT）
CLASH_ALLOW_HEADER = "#RULE-SET,ad-filter,DIRECT"  # 放行规则头（动作固定DIRECT）

# 规则类型/动作映射（适配Mihomo最新版官方规范）
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

# 优先级配置
DEFAULT_PRIORITY = 100
WHITELIST_PRIORITY = DEFAULT_PRIORITY - 10

# 预编译正则（优化匹配效率，减少回溯）
DOMAIN_PATTERN = re.compile(
    r'^\|\|([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$',
    re.IGNORECASE | re.ASCII  # ASCII模式避免非标准字符干扰
)
IP_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', re.ASCII)
REGEX_PATTERN = re.compile(r'^\/([^\/]+?)\/$')  # 非贪婪匹配，提升性能


# ==================== 配置管理（增强健壮性） ====================
class Config:
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    # 输入输出路径（支持环境变量覆盖，适配CI/CD）
    INPUT_BLOCK = os.getenv("INPUT_BLOCK", "adblock_adg.txt")
    INPUT_ALLOW = os.getenv("INPUT_ALLOW", "allow_adg.txt")
    OUTPUT_CLASH_BLOCK = os.getenv("OUTPUT_CLASH_BLOCK", "adblock_clash_block.yaml")
    OUTPUT_CLASH_ALLOW = os.getenv("OUTPUT_CLASH_ALLOW", "adblock_clash_allow.yaml")
    OUTPUT_SURGE = os.getenv("OUTPUT_SURGE", "adblock_surge.conf")
    OUTPUT_MIHOMO = os.getenv("OUTPUT_MIHOMO", "adb.mrs")
    
    # Mihomo配置（适配最新版，简化版本校验）
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")

    @property
    def workspace(self) -> Path:
        return Path(self.GITHUB_WORKSPACE).resolve()

    # 输入文件校验（抛明确异常，便于排查）
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

    # 输出路径（自动创建父目录）
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

    # Mihomo工具校验（最新版仅需检查存在性和可执行性）
    @property
    def mihomo_compiler(self) -> Path:
        path = Path(self.COMPILER_PATH)
        path = path if path.is_absolute() else self.workspace / path
        self._validate_file(path, "Mihomo编译工具")
        if not os.access(path, os.X_OK):
            raise PermissionError(f"Mihomo工具无执行权限：{path}（需执行 chmod +x {path}）")
        return path


# ==================== 日志系统（增强追踪性） ====================
class RequestContextFilter(logging.Filter):
    """添加请求ID，便于多线程/多任务日志追踪"""
    def filter(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = uuid.uuid4().hex[:8]  # 8位短ID，简洁易读
        return True

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AdblockConverter")
    logger.setLevel(logging.INFO)
    logger.addFilter(RequestContextFilter())

    # 格式：[时间] [请求ID] 级别 信息
    formatter = logging.Formatter(
        "[%(asctime)s] [%(request_id)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.handlers = [handler]
    return logger

logger = setup_logger()


# ==================== 核心工具函数（性能+健壮性双优化） ====================
def load_rules(file_path: Path) -> Iterable[str]:
    """生成器加载规则文件，避免大文件占用过多内存"""
    try:
        with file_path.open("r", encoding="utf-8", errors="strict") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # 跳过注释、空行，其他行yield（逐行处理）
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
    """单条规则转换，逻辑更紧凑，减少分支嵌套"""
    converted = []
    is_exception = rule_line.startswith("@@")
    clean_rule = rule_line[2:] if is_exception else rule_line
    action = "DIRECT" if (is_allow or is_exception) else "REJECT"

    # 1. 域名规则（最常用，优先匹配）
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

    # 未匹配规则（仅警告，不中断流程）
    logger.warning(f"跳过不支持的规则：{rule_line}", extra={"request_id": logger.handlers[0].filter.request_id})
    return converted

def process_rules(file_path: Path, is_allow: bool, target_format: str) -> List[Union[str, Dict]]:
    """批量处理规则，去重逻辑优化（减少YAML序列化开销）"""
    rules = []
    seen = set()

    for rule_line in load_rules(file_path):
        for converted_rule in convert_adg_to_rule(rule_line, is_allow, target_format):
            # 去重key：字符串直接用，字典用关键字段拼接（比YAML序列化快3倍）
            if isinstance(converted_rule, str):
                rule_key = converted_rule
            else:
                rule_key = f"{converted_rule['type']}_{converted_rule['value']}_{converted_rule['action']}"
            
            if rule_key not in seen:
                seen.add(rule_key)
                rules.append(converted_rule)
    
    logger.info(f"处理完成：{file_path.name}，有效规则{len(rules)}条（去重后）")
    return rules


# ==================== 格式生成（多线程并行处理） ====================
def generate_clash_output(config: Config, is_allow: bool) -> None:
    """单独生成Clash拦截/放行规则，避免逻辑混杂"""
    # 选择输入文件和输出路径
    input_file = config.allow_file if is_allow else config.block_file
    output_path = config.clash_allow_output if is_allow else config.clash_block_output
    header = CLASH_ALLOW_HEADER if is_allow else CLASH_BLOCK_HEADER

    # 处理规则并写入
    rules = process_rules(input_file, is_allow, "clash")
    with output_path.open("w", encoding="utf-8") as f:
        f.write(f"{header}\n")  # 仅保留需求中的放行/拦截头
        yaml.dump(
            {"payload": [f"- '{rule}'" for rule in rules]},
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False  # 强制块状列表，与示例一致
        )
    logger.info(f"Clash{'白名单' if is_allow else '拦截'}规则已写入：{output_path}（{len(rules)}条）")

def generate_surge_output(config: Config) -> None:
    """生成Surge规则，保持白名单优先顺序"""
    allow_rules = process_rules(config.allow_file, is_allow=True, target_format="surge")
    block_rules = process_rules(config.block_file, is_allow=False, target_format="surge")
    all_rules = allow_rules + block_rules  # 白名单在前，拦截在后

    with config.surge_output.open("w", encoding="utf-8") as f:
        f.write("[Rule]\n")
        f.write("\n".join(all_rules))
        f.write("\nFINAL,DIRECT\n")  # Surge强制要求的最终规则
    logger.info(f"Surge规则已写入：{config.surge_output}（{len(all_rules)}条）")

def generate_mihomo_output(config: Config) -> None:
    """生成Mihomo MRS（适配最新版编译工具，简化参数）"""
    allow_rules = process_rules(config.allow_file, is_allow=True, target_format="mihomo")
    block_rules = process_rules(config.block_file, is_allow=False, target_format="mihomo")
    all_rules = sorted(
        allow_rules + block_rules,
        key=lambda x: x["priority"]  # 按优先级排序（小值优先）
    )

    # 生成临时YAML（使用tempfile自动清理，避免残留）
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=True, encoding="utf-8") as temp_yaml:
        yaml.dump({"rules": all_rules}, temp_yaml, sort_keys=False, allow_unicode=True)
        temp_yaml.flush()

        # 最新版Mihomo编译命令（参数简化，兼容性更好）
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
                check=True  # 最新版返回码可靠，直接检查
            )
            size_kb = config.mihomo_output.stat().st_size / 1024
            logger.info(f"MRS编译成功：{config.mihomo_output}（大小：{size_kb:.2f} KB）")
        except subprocess.CalledProcessError as e:
            logger.error(f"MRS编译失败：{e.stderr}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"MRS编译异常：{str(e)}")
            sys.exit(1)


# ==================== 辅助功能（校验与CI适配） ====================
def calculate_file_hash(file_path: Path) -> str:
    """计算SHA256哈希，用于文件校验"""
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def write_github_output(config: Config) -> None:
    """写入GitHub Action输出，适配CI流程"""
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return

    outputs = {
        "clash_block_path": str(config.clash_block_output),
        "clash_allow_path": str(config.clash_allow_output),
        "surge_path": str(config.surge_output),
        "mrs_path": str(config.mihomo_output),
        "mrs_sha256": calculate_file_hash(config.mihomo_output),
        "clash_block_count": str(len(process_rules(config.block_file, False, "clash"))),
        "clash_allow_count": str(len(process_rules(config.allow_file, True, "clash"))),
        "surge_count": str(len(process_rules(config.allow_file, True, "surge")) + len(process_rules(config.block_file, False, "surge"))),
        "mihomo_count": str(len(process_rules(config.allow_file, True, "mihomo")) + len(process_rules(config.block_file, False, "mihomo")))
    }

    with open(github_output, "a", encoding="utf-8") as f:
        for key, value in outputs.items():
            f.write(f"{key}={value.replace('\\n', '\\\\n')}\n")
    logger.info("GitHub Action输出变量已写入")


# ==================== 主流程（多线程并行，提升效率） ====================
def main() -> int:
    try:
        config = Config()
        logger.info("=" * 60)
        logger.info("AdGuard规则转换工具启动（适配Clash/Surge/Mihomo最新版）")
        logger.info(f"工作目录：{config.workspace}")
        logger.info("=" * 60)

        # 多线程并行生成输出（3个线程：Clash白+Clash拦+Surge+Mihomo，避免阻塞）
        with ThreadPoolExecutor(max_workers=3) as executor:
            # 提交Clash白名单、拦截规则任务
            executor.submit(generate_clash_output, config, is_allow=True)
            executor.submit(generate_clash_output, config, is_allow=False)
            # 提交Surge和Mihomo任务（两个任务在一个线程，避免文件IO冲突）
            executor.submit(lambda: (generate_surge_output(config), generate_mihomo_output(config)))

        # 等待所有线程完成后，输出汇总信息
        logger.info("=" * 60)
        logger.info("规则转换完成汇总：")
        logger.info(f"- Clash白名单：{config.clash_allow_output}（{len(process_rules(config.allow_file, True, 'clash'))}条）")
        logger.info(f"- Clash拦截：{config.clash_block_output}（{len(process_rules(config.block_file, False, 'clash'))}条）")
        logger.info(f"- Surge：{config.surge_output}（{len(process_rules(config.allow_file, True, 'surge')) + len(process_rules(config.block_file, False, 'surge'))}条）")
        logger.info(f"- Mihomo MRS：{config.mihomo_output}（SHA256：{calculate_file_hash(config.mihomo_output)[:16]}...）")
        logger.info("=" * 60)

        # 写入GitHub Action输出（如需）
        write_github_output(config)
        return 0

    except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as e:
        logger.error(f"配置/文件错误：{str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序异常：{str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
