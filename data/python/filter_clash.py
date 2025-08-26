#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import tempfile
import subprocess
import yaml
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# ==================== 常量定义 ====================
# Clash -> Mihomo 规则类型映射（官方标准）
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

# 动作映射（Surge/Clash -> Mihomo 官方标准）
ACTION_MAP = {
    "REJECT": "reject",    # 拦截
    "DIRECT": "direct",    # 直连（白名单）
    "PROXY": "proxy"       # 代理（预留）
}

# 默认规则优先级（数值越小优先级越高）
DEFAULT_PRIORITY = 100
WHITELIST_PRIORITY = DEFAULT_PRIORITY - 10  # 白名单优先级更高

# 规则匹配正则（适配AdGuard格式）
DOMAIN_PATTERN = re.compile(r'^\|\|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\^?$', re.IGNORECASE)
IP_PATTERN = re.compile(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
REGEX_PATTERN = re.compile(r'^\/([^\/]+)\/$')  # 简单正则规则（如 /ad/）


# ==================== 配置管理 ====================
class Config:
    """统一配置管理（支持环境变量覆盖，适配GitHub Action）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    
    # 输入文件（AdGuard格式）
    INPUT_BLOCK = os.getenv("INPUT_BLOCK", "adblock_adg.txt")  # 拦截规则
    INPUT_ALLOW = os.getenv("INPUT_ALLOW", "allow_adg.txt")    # 白名单规则
    
    # 输出文件（多格式）
    OUTPUT_CLASH = os.getenv("OUTPUT_CLASH", "adblock_clash.yaml")  # Clash规则
    OUTPUT_SURGE = os.getenv("OUTPUT_SURGE", "adblock_surge.conf")  # Surge规则
    OUTPUT_MIHOMO = os.getenv("OUTPUT_MIHOMO", "adb.mrs")            # Mihomo MRS规则
    
    # Mihomo编译配置
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")  # Mihomo工具路径
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")                     # 规则集类型（Mihomo要求）

    @property
    def workspace(self) -> Path:
        return Path(self.GITHUB_WORKSPACE).resolve()

    # 输入文件校验
    @property
    def block_file(self) -> Path:
        path = self.workspace / self.INPUT_BLOCK
        if not path.exists():
            raise FileNotFoundError(f"拦截规则文件不存在: {path}")
        return path

    @property
    def allow_file(self) -> Path:
        path = self.workspace / self.INPUT_ALLOW
        if not path.exists():
            raise FileNotFoundError(f"白名单规则文件不存在: {path}")
        return path

    # 输出文件路径
    @property
    def clash_output(self) -> Path:
        return self.workspace / self.OUTPUT_CLASH

    @property
    def surge_output(self) -> Path:
        return self.workspace / self.OUTPUT_SURGE

    @property
    def mihomo_output(self) -> Path:
        path = self.workspace / self.OUTPUT_MIHOMO
        path.parent.mkdir(parents=True, exist_ok=True)  # 确保目录存在
        return path

    # Mihomo工具校验
    @property
    def mihomo_compiler(self) -> Path:
        path = Path(self.COMPILER_PATH)
        path = path if path.is_absolute() else self.workspace / path
        if not path.exists():
            raise FileNotFoundError(f"Mihomo工具不存在: {path}")
        if not os.access(path, os.X_OK):
            raise PermissionError(f"Mihomo工具无执行权限: {path}")
        return path


# ==================== 日志配置 ====================
def setup_logger() -> logging.Logger:
    """配置GitHub风格日志（区分notice/warning/error）"""
    logger = logging.getLogger("AdblockConverter")
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
            timestamp = datetime.now().strftime('%H:%M:%S')
            level_prefix = {
                logging.INFO: "::notice::",
                logging.WARNING: "::warning::",
                logging.ERROR: "::error::",
                logging.CRITICAL: "::error::"
            }.get(record.levelno, "")
            return f"[{timestamp}] {level_prefix}{record.getMessage()}"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GitHubFormatter())
    logger.handlers = [handler]
    return logger


logger = setup_logger()


# ==================== 规则转换核心逻辑 ====================
def convert_adg_to_rule(rule_line: str, is_allow: bool, target_format: str) -> List[Union[str, Dict]]:
    """
    AdGuard规则转换为目标格式（Clash/Surge/Mihomo）
    :param rule_line: 原始AdGuard规则
    :param is_allow: 是否为白名单规则
    :param target_format: 目标格式（clash/surge/mihomo）
    :return: 转换后的规则列表（字符串/字典）
    """
    converted = []
    rule_line = rule_line.strip()

    # 跳过注释和空行
    if not rule_line or rule_line.startswith(('!', '#')):
        return converted

    # 处理例外规则（AdGuard: @@规则）
    is_exception = rule_line.startswith('@@')
    clean_rule = rule_line[2:] if is_exception else rule_line
    action = "DIRECT" if (is_allow or is_exception) else "REJECT"  # 白名单/例外规则用直连

    # 1. 匹配域名规则（如 ||example.com^）
    domain_match = DOMAIN_PATTERN.match(clean_rule)
    if domain_match:
        domain = clean_rule.strip('||^')  # 提取纯域名
        if target_format == "clash":
            converted.append(f"+.{domain}")  # Clash白名单格式：+.domain.com
        elif target_format == "surge":
            converted.append(f"DOMAIN-SUFFIX,{domain},{action}")  # Surge标准格式
        elif target_format == "mihomo":
            converted.append({
                "type": "domain-suffix",
                "value": domain,
                "action": ACTION_MAP[action],
                "priority": WHITELIST_PRIORITY if is_allow else DEFAULT_PRIORITY
            })
        return converted

    # 2. 匹配IP规则（如 0.0.0.0 example.com）
    ip_match = IP_PATTERN.match(clean_rule)
    if ip_match:
        ip = ip_match.group(1)
        cidr_ip = f"{ip}/32"  # 补全CIDR（IPv4单IP默认/32）
        if target_format == "clash":
            converted.append(f"IP-CIDR,{cidr_ip},{action}")
        elif target_format == "surge":
            converted.append(f"IP-CIDR,{cidr_ip},{action}")
        elif target_format == "mihomo":
            converted.append({
                "type": "ip-cidr",
                "value": cidr_ip,
                "action": ACTION_MAP[action],
                "priority": DEFAULT_PRIORITY
            })
        return converted

    # 3. 匹配正则规则（如 /ad/）
    regex_match = REGEX_PATTERN.match(clean_rule)
    if regex_match:
        keyword = regex_match.group(1)
        if target_format == "clash":
            converted.append(f"DOMAIN-KEYWORD,{keyword},{action}")
        elif target_format == "surge":
            converted.append(f"DOMAIN-KEYWORD,{keyword},{action}")
        elif target_format == "mihomo":
            converted.append({
                "type": "domain-keyword",
                "value": keyword,
                "action": ACTION_MAP[action],
                "priority": DEFAULT_PRIORITY
            })
        return converted

    # 未匹配的规则（日志警告）
    logger.warning(f"不支持的规则格式，跳过：{rule_line}")
    return converted


def process_input_file(input_path: Path, is_allow: bool, target_format: str) -> List[Union[str, Dict]]:
    """处理输入文件，返回去重后的规则列表"""
    rules = []
    seen = set()  # 去重用

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                converted = convert_adg_to_rule(line, is_allow, target_format)
                for rule in converted:
                    # 规则去重（字符串用原值，字典用YAML序列化后的值）
                    rule_key = rule if isinstance(rule, str) else yaml.dump(rule, sort_keys=False)
                    if rule_key not in seen:
                        seen.add(rule_key)
                        rules.append(rule)
        logger.info(f"处理 {input_path.name}：{len(rules)} 条有效规则（去重后）")
    except Exception as e:
        logger.error(f"读取文件 {input_path} 失败：{str(e)}")
        sys.exit(1)

    return rules


# ==================== Mihomo MRS编译 ====================
def generate_mihomo_yaml(rules: List[Dict]) -> str:
    """生成Mihomo标准YAML规则（按优先级排序）"""
    if not rules:
        raise ValueError("无有效Mihomo规则可生成YAML")
    # 按优先级排序（数值小的优先）
    sorted_rules = sorted(rules, key=lambda x: x["priority"])
    return yaml.dump({"rules": sorted_rules}, sort_keys=False, allow_unicode=True)


def compile_mrs(yaml_content: str, config: Config) -> bool:
    """用Mihomo工具编译YAML为MRS二进制规则集"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=True, encoding='utf-8') as temp_yaml:
        temp_yaml.write(yaml_content)
        temp_yaml.flush()

        # 编译命令（严格遵循Mihomo官方工具语法）
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
                timeout=300,  # 5分钟超时
                check=False
            )

            if result.returncode != 0:
                logger.error(f"MRS编译失败（返回码{result.returncode}）：{result.stderr}")
                return False
            if not config.mihomo_output.exists() or config.mihomo_output.stat().st_size == 0:
                logger.error("MRS文件生成后为空或不存在")
                return False

            logger.info(f"MRS编译成功：{config.mihomo_output}（大小：{config.mihomo_output.stat().st_size / 1024:.2f} KB）")
            return True
        except subprocess.TimeoutExpired:
            logger.error("MRS编译超时（超过5分钟）")
            return False
        except Exception as e:
            logger.error(f"MRS编译异常：{str(e)}")
            return False


# ==================== 辅助功能 ====================
def calculate_file_hash(file_path: Path) -> str:
    """计算文件SHA256哈希（用于校验）"""
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def write_github_output(config: Config, rule_counts: Dict[str, int]):
    """写入GitHub Action输出变量（供后续流程使用）"""
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return

    outputs = {
        "clash_path": str(config.clash_output),
        "surge_path": str(config.surge_output),
        "mrs_path": str(config.mihomo_output),
        "mrs_sha256": calculate_file_hash(config.mihomo_output),
        "clash_rule_count": str(rule_counts["clash"]),
        "surge_rule_count": str(rule_counts["surge"]),
        "mihomo_rule_count": str(rule_counts["mihomo"])
    }

    with open(github_output, 'a', encoding='utf-8') as f:
        for key, value in outputs.items():
            f.write(f"{key}={value.replace('\\n', '\\\\n')}\n")
    logger.info("GitHub Action输出变量已写入")


# ==================== 主流程 ====================
def main():
    try:
        # 1. 初始化配置
        config = Config()
        logger.info("=" * 60)
        logger.info("AdGuard规则转换工具启动（支持Clash/Surge/Mihomo）")
        logger.info(f"工作目录：{config.workspace}")
        logger.info("=" * 60)

        # 2. 转换规则（多格式并行处理）
        # 2.1 转换为Clash规则
        clash_block = process_input_file(config.block_file, is_allow=False, target_format="clash")
        clash_allow = process_input_file(config.allow_file, is_allow=True, target_format="clash")
        all_clash = clash_block + clash_allow
        # 写入Clash YAML（符合Clash规则集标准结构）
        with open(config.clash_output, 'w', encoding='utf-8') as f:
            yaml.dump({"payload": all_clash}, f, allow_unicode=True, sort_keys=False)
        logger.info(f"Clash规则已写入：{config.clash_output}（{len(all_clash)} 条）")

        # 2.2 转换为Surge规则
        surge_block = process_input_file(config.block_file, is_allow=False, target_format="surge")
        surge_allow = process_input_file(config.allow_file, is_allow=True, target_format="surge")
        all_surge = surge_allow + surge_block  # 白名单优先（Surge规则按顺序生效）
        # 写入Surge配置（添加FINAL规则，符合Surge语法要求）
        with open(config.surge_output, 'w', encoding='utf-8') as f:
            f.write("[Rule]\n")
            f.write('\n'.join(all_surge))
            f.write("\nFINAL,DIRECT\n")  # Surge必须有FINAL规则
        logger.info(f"Surge规则已写入：{config.surge_output}（{len(all_surge)} 条）")

        # 2.3 转换为Mihomo规则并编译为MRS
        mihomo_block = process_input_file(config.block_file, is_allow=False, target_format="mihomo")
        mihomo_allow = process_input_file(config.allow_file, is_allow=True, target_format="mihomo")
        all_mihomo = mihomo_block + mihomo_allow
        # 生成YAML并编译MRS
        mihomo_yaml = generate_mihomo_yaml(all_mihomo)
        if not compile_mrs(mihomo_yaml, config):
            logger.error("MRS编译失败，程序退出")
            sys.exit(1)

        # 3. 输出统计和校验信息
        rule_counts = {
            "clash": len(all_clash),
            "surge": len(all_surge),
            "mihomo": len(all_mihomo)
        }
        logger.info("=" * 60)
        logger.info("规则转换完成汇总：")
        logger.info(f"- Clash规则：{rule_counts['clash']} 条（{config.clash_output}）")
        logger.info(f"- Surge规则：{rule_counts['surge']} 条（{config.surge_output}）")
        logger.info(f"- Mihomo MRS：{rule_counts['mihomo']} 条（{config.mihomo_output}）")
        logger.info(f"- MRS SHA256：{calculate_file_hash(config.mihomo_output)}")
        logger.info("=" * 60)

        # 4. 写入GitHub Action输出（如需）
        write_github_output(config, rule_counts)
        return 0

    except (FileNotFoundError, PermissionError, ValueError) as e:
        logger.error(f"配置或文件错误：{str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序异常退出：{str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
