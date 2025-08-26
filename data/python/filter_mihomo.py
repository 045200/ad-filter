#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tempfile
import subprocess
import yaml
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Clash规则类型 -> Mihomo规则类型 映射表（核心映射，覆盖主流规则类型）
CLASH_TO_MIHOMO_TYPE = {
    "Domain": "domain",
    "Domain-Suffix": "domain-suffix",
    "Domain-Keyword": "domain-keyword",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip-cidr6",
    "GeoIP": "geoip",
    "Src-IP-CIDR": "src-ip-cidr",
    "Src-Port": "src-port",
    "Dst-Port": "dst-port",
    "Process-Name": "process-name",
    "Process-Path": "process-path"
}

# 默认规则优先级（Mihomo支持1-65535，数值越小优先级越高）
DEFAULT_PRIORITY = 100


class Config:
    """配置管理（输入输出均在仓库根目录）"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")

    @property
    def workspace_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE).resolve()

    @property
    def input_path(self) -> Path:
        path = self.workspace_path / self.INPUT_FILE
        if not path.exists():
            raise FileNotFoundError(f"输入文件不存在: {path}")
        if path.stat().st_size == 0:
            raise ValueError(f"输入文件为空: {path}")
        return path

    @property
    def output_path(self) -> Path:
        path = self.workspace_path / self.OUTPUT_FILE
        # 确保输出目录存在
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def compiler_path(self) -> Path:
        path = Path(self.COMPILER_PATH)
        path = path if path.is_absolute() else self.workspace_path / path
        if not path.exists():
            raise FileNotFoundError(f"Mihomo工具不存在: {path}")
        if not os.access(path, os.X_OK):
            raise PermissionError(f"Mihomo工具无执行权限: {path}")
        return path


def setup_logger():
    """配置GitHub风格日志"""
    logger = logging.getLogger("AdblockConverter")
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
            timestamp = datetime.now().strftime('%H:%M:%S')
            level_map = {
                logging.INFO: "::notice::",
                logging.WARNING: "::warning::",
                logging.ERROR: "::error::",
                logging.CRITICAL: "::error::"
            }
            prefix = level_map.get(record.levelno, "")
            return f"[{timestamp}] {prefix} {record.getMessage()}"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GitHubFormatter())
    logger.handlers = [handler]
    return logger


logger = setup_logger()


def parse_clash_rule(rule_str: str) -> Optional[Dict]:
    """解析单条Clash规则（处理带引号、特殊字符的value）"""
    rule_str = rule_str.strip()
    if not rule_str:
        return None

    # 处理带引号的value（如 "example.com,test",REJECT）
    import re
    # 匹配格式：TYPE,"value含逗号",action 或 TYPE,value不含逗号,action
    pattern = r'^([^,]+),(?:"([^"]+)"|([^,]+)),([^,]+)'
    match = re.match(pattern, rule_str)
    if not match:
        logger.warning(f"跳过无效Clash规则: {rule_str}")
        return None

    rule_type_clash, value_quoted, value_plain, action = match.groups()
    value = value_quoted if value_quoted else value_plain

    # 转换Clash规则类型为Mihomo类型
    rule_type_mihomo = CLASH_TO_MIHOMO_TYPE.get(rule_type_clash.strip())
    if not rule_type_mihomo:
        logger.warning(f"不支持的Clash规则类型: {rule_type_clash}，跳过规则: {rule_str}")
        return None

    return {
        "type": rule_type_mihomo,
        "value": value.strip(),
        "action": action.strip(),
        "priority": DEFAULT_PRIORITY  # 添加默认优先级
    }


def parse_clash_rules(input_path: Path) -> List[Dict]:
    """解析Clash规则文件（含payload节点）"""
    logger.info(f"读取Clash规则文件: {input_path}")
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            # 处理YAML中的注释（yaml.safe_load默认忽略）
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error(f"YAML解析错误: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"读取文件失败: {str(e)}")
        return []

    # 校验payload节点
    if not isinstance(data, dict) or "payload" not in data:
        logger.error("输入文件缺少顶层'payload'节点（Clash规则集标准结构）")
        return []
    if not isinstance(data["payload"], list):
        logger.error("'payload'节点必须是列表类型")
        return []

    # 解析所有有效规则
    rules = []
    for idx, item in enumerate(data["payload"], 1):
        if not isinstance(item, str):
            logger.warning(f"payload第{idx}项非字符串类型，跳过")
            continue
        parsed_rule = parse_clash_rule(item)
        if parsed_rule:
            rules.append(parsed_rule)

    logger.info(f"成功解析 {len(rules)} 条有效Clash规则（总{len(data['payload'])}条）")
    return rules


def generate_mihomo_yaml(rules: List[Dict]) -> str:
    """生成标准Mihomo规则YAML（用yaml.dump避免语法错误）"""
    if not rules:
        return ""
    mihomo_data = {"rules": rules}
    # 生成带缩进的标准YAML，禁用锚点（避免冗余）
    return yaml.dump(mihomo_data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def compile_ruleset(compiler_path: Path, yaml_content: str, output_path: Path) -> bool:
    """使用Mihomo工具编译YAML为MRS二进制规则集"""
    if not yaml_content:
        logger.error("无Mihomo YAML内容可编译")
        return False

    # 使用contextmanager自动管理临时文件（无需手动删除）
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=True, encoding='utf-8') as temp_f:
            temp_f.write(yaml_content)
            temp_f.flush()  # 确保内容写入磁盘

            # 构建编译命令（Mihomo-tool convert-ruleset标准参数）
            cmd = [
                str(compiler_path),
                "convert-ruleset",
                "domain",  # 规则集类型（domain/ip/process等，此处适配广告拦截场景）
                "yaml",    # 输入格式
                temp_f.name,
                str(output_path)
            ]
            logger.info(f"执行编译命令: {' '.join(cmd)}")

            # 执行命令（捕获stdout/stderr便于调试）
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False
            )

            # 校验执行结果
            if result.returncode != 0:
                logger.error(f"编译失败（返回码{result.returncode}）: {result.stderr}")
                logger.debug(f"编译命令stdout: {result.stdout}")
                return False
            if not output_path.exists() or output_path.stat().st_size == 0:
                logger.error("编译成功但输出MRS文件为空或不存在")
                return False

        logger.info("MRS规则集编译成功")
        return True
    except subprocess.TimeoutExpired:
        logger.error("编译超时（超过300秒）")
        return False
    except Exception as e:
        logger.error(f"编译过程异常: {str(e)}")
        return False


def calculate_sha256(file_path: Path) -> str:
    """计算文件SHA256哈希（用于校验）"""
    if not file_path.exists() or not file_path.is_file():
        logger.error(f"计算哈希失败：文件不存在或非普通文件: {file_path}")
        return ""

    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"计算SHA256失败: {str(e)}")
        return ""


def write_github_output(variables: Dict[str, str]):
    """写入GitHub Action输出变量（适配CI/CD场景）"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if not github_output:
        logger.debug("未检测到GITHUB_OUTPUT环境变量，跳过输出写入")
        return

    try:
        with open(github_output, 'a', encoding='utf-8') as f:
            for key, value in variables.items():
                # 处理value中的特殊字符（避免YAML解析问题）
                safe_value = value.replace("\n", "\\n").replace("\r", "\\r")
                f.write(f"{key}={safe_value}\n")
        logger.info(f"成功写入 {len(variables)} 个GitHub Action输出变量")
    except Exception as e:
        logger.warning(f"写入GitHub Output失败: {str(e)}")


def main():
    try:
        # 初始化配置（自动校验输入/输出/编译器）
        config = Config()
        logger.info(f"配置初始化完成：输入={config.input_path}，输出={config.output_path}，编译器={config.compiler_path}")

        # 1. 解析Clash规则
        rules = parse_clash_rules(config.input_path)
        if not rules:
            logger.error("无有效Clash规则可转换，程序退出")
            return 1

        # 2. 生成Mihomo YAML（打印前5条预览）
        yaml_content = generate_mihomo_yaml(rules)
        # 修复：提前计算拆分后的预览内容，避开f-string内用反斜杠
        yaml_preview = yaml_content.split('\n')[0:16]
        logger.debug(f"Mihomo YAML预览（前5条规则）:\n{yaml_preview}")  # 每条规则占4行，5条占20行

        # 3. 编译为MRS规则集
        if not compile_ruleset(config.compiler_path, yaml_content, config.output_path):
            logger.error("MRS规则集编译失败，程序退出")
            return 1

        # 4. 计算输出文件信息
        file_hash = calculate_sha256(config.output_path)
        file_size_kb = config.output_path.stat().st_size / 1024

        # 5. 输出结果日志
        logger.info("=" * 50)
        logger.info(f"转换完成！")
        logger.info(f"输出文件: {config.output_path}")
        logger.info(f"规则数量: {len(rules)} 条")
        logger.info(f"文件大小: {file_size_kb:.2f} KB")
        logger.info(f"SHA256: {file_hash}")
        logger.info("=" * 50)

        # 6. 写入GitHub Action输出（若在CI中运行）
        write_github_output({
            'mrs_path': str(config.output_path),
            'mrs_sha256': file_hash,
            'rule_count': str(len(rules)),
            'mrs_size_kb': f"{file_size_kb:.2f}"
        })

        return 0
    except (FileNotFoundError, PermissionError, ValueError) as e:
        logger.error(f"配置校验失败: {str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序执行异常: {str(e)}", exc_info=True)  # 打印堆栈信息便于调试
        return 1


if __name__ == "__main__":
    sys.exit(main())
