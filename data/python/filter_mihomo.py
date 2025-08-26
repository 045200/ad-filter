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
from typing import List, Dict, Optional, Tuple

# Clash规则类型 -> Mihomo规则类型 映射表
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

# 动作映射
ACTION_MAP = {
    "REJECT": "reject",
    "DIRECT": "direct",
    "PROXY": "proxy"
}

# 默认规则优先级
DEFAULT_PRIORITY = 100


class Config:
    """配置管理"""
    GITHUB_WORKSPACE = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    INPUT_FILE = os.getenv("ADBLOCK_INPUT", "adblock_clash.yaml")
    OUTPUT_FILE = os.getenv("ADBLOCK_OUTPUT", "adb.mrs")
    COMPILER_PATH = os.getenv("COMPILER_PATH", "./data/mihomo-tool")
    RULE_TYPE = os.getenv("RULE_TYPE", "domain")  # 规则集类型

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


def parse_special_rule(rule_str: str) -> Optional[Dict]:
    """解析特殊格式规则（上游脚本生成的+.格式）"""
    rule_str = rule_str.strip()
    
    # 处理上游脚本的特殊格式：+.example.com
    if rule_str.startswith('+.'):
        domain = rule_str[2:]  # 移除+.前缀
        return {
            "type": "domain-suffix",
            "value": domain,
            "action": "direct",  # 上游脚本中+.表示白名单
            "priority": DEFAULT_PRIORITY - 10  # 白名单优先级更高
        }
    
    return None


def parse_clash_rule(rule_str: str) -> Optional[Dict]:
    """解析单条Clash规则"""
    rule_str = rule_str.strip()
    if not rule_str:
        return None

    # 首先尝试解析特殊格式规则（上游脚本生成的+.格式）
    special_rule = parse_special_rule(rule_str)
    if special_rule:
        return special_rule

    # 处理标准Clash规则格式：TYPE,value,action
    parts = rule_str.split(',', 2)
    if len(parts) < 3:
        logger.warning(f"跳过格式不完整的Clash规则: {rule_str}")
        return None

    rule_type_clash, value, action = parts
    rule_type_clash = rule_type_clash.upper().strip()
    value = value.strip()
    action = action.upper().strip()

    # 转换Clash规则类型为Mihomo类型
    rule_type_mihomo = CLASH_TO_MIHOMO_TYPE.get(rule_type_clash)
    if not rule_type_mihomo:
        logger.warning(f"不支持的Clash规则类型: {rule_type_clash}，跳过规则: {rule_str}")
        return None

    # 转换动作为Mihomo格式
    action_mihomo = ACTION_MAP.get(action, action.lower())
    
    # 特殊处理：对于IP-CIDR规则，确保有正确的CIDR表示
    if rule_type_mihomo == "ip-cidr" and '/' not in value:
        logger.warning(f"IP-CIDR规则缺少CIDR后缀，自动添加/32: {rule_str}")
        value += "/32"
    
    return {
        "type": rule_type_mihomo,
        "value": value,
        "action": action_mihomo,
        "priority": DEFAULT_PRIORITY
    }


def parse_clash_rules(input_path: Path) -> Tuple[List[Dict], List[Dict]]:
    """解析Clash规则文件，返回规则列表和错误列表"""
    logger.info(f"读取Clash规则文件: {input_path}")
    rules = []
    errors = []
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            # 处理YAML中的注释
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        error_msg = f"YAML解析错误: {str(e)}"
        logger.error(error_msg)
        errors.append({"type": "yaml_error", "message": error_msg})
        return rules, errors
    except Exception as e:
        error_msg = f"读取文件失败: {str(e)}"
        logger.error(error_msg)
        errors.append({"type": "file_error", "message": error_msg})
        return rules, errors

    # 校验payload节点
    if not isinstance(data, dict) or "payload" not in data:
        error_msg = "输入文件缺少顶层'payload'节点（Clash规则集标准结构）"
        logger.error(error_msg)
        errors.append({"type": "structure_error", "message": error_msg})
        return rules, errors
        
    if not isinstance(data["payload"], list):
        error_msg = "'payload'节点必须是列表类型"
        logger.error(error_msg)
        errors.append({"type": "structure_error", "message": error_msg})
        return rules, errors

    # 解析所有规则
    valid_count = 0
    for idx, item in enumerate(data["payload"], 1):
        if not isinstance(item, str):
            error_msg = f"payload第{idx}项非字符串类型，跳过"
            logger.warning(error_msg)
            errors.append({"type": "item_error", "index": idx, "message": error_msg})
            continue
            
        parsed_rule = parse_clash_rule(item)
        if parsed_rule:
            rules.append(parsed_rule)
            valid_count += 1
        else:
            error_msg = f"无法解析规则: {item}"
            logger.warning(error_msg)
            errors.append({"type": "parse_error", "index": idx, "message": error_msg, "rule": item})

    logger.info(f"成功解析 {valid_count} 条有效Clash规则（总{len(data['payload'])}条）")
    return rules, errors


def generate_mihomo_yaml(rules: List[Dict]) -> str:
    """生成标准Mihomo规则YAML"""
    if not rules:
        return ""
    
    # 按优先级排序（数值越小优先级越高）
    sorted_rules = sorted(rules, key=lambda x: x.get("priority", DEFAULT_PRIORITY))
    
    mihomo_data = {"rules": sorted_rules}
    return yaml.dump(mihomo_data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def compile_ruleset(compiler_path: Path, yaml_content: str, output_path: Path, rule_type: str) -> Tuple[bool, str]:
    """使用Mihomo工具编译YAML为MRS二进制规则集"""
    if not yaml_content:
        error_msg = "无Mihomo YAML内容可编译"
        logger.error(error_msg)
        return False, error_msg

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=True, encoding='utf-8') as temp_f:
            temp_f.write(yaml_content)
            temp_f.flush()

            # 构建编译命令
            cmd = [
                str(compiler_path),
                "convert-ruleset",
                rule_type,  # 使用配置的规则集类型
                "yaml",
                temp_f.name,
                str(output_path)
            ]
            logger.info(f"执行编译命令: {' '.join(cmd)}")

            # 执行命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False
            )

            # 校验执行结果
            if result.returncode != 0:
                error_msg = f"编译失败（返回码{result.returncode}）: {result.stderr}"
                logger.error(error_msg)
                logger.debug(f"编译命令stdout: {result.stdout}")
                return False, error_msg
                
            if not output_path.exists() or output_path.stat().st_size == 0:
                error_msg = "编译成功但输出MRS文件为空或不存在"
                logger.error(error_msg)
                return False, error_msg

        logger.info("MRS规则集编译成功")
        return True, ""
    except subprocess.TimeoutExpired:
        error_msg = "编译超时（超过300秒）"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"编译过程异常: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def calculate_sha256(file_path: Path) -> str:
    """计算文件SHA256哈希"""
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
    """写入GitHub Action输出变量"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if not github_output:
        logger.debug("未检测到GITHUB_OUTPUT环境变量，跳过输出写入")
        return

    try:
        with open(github_output, 'a', encoding='utf-8') as f:
            for key, value in variables.items():
                safe_value = value.replace("\n", "\\n").replace("\r", "\\r")
                f.write(f"{key}={safe_value}\n")
        logger.info(f"成功写入 {len(variables)} 个GitHub Action输出变量")
    except Exception as e:
        logger.warning(f"写入GitHub Output失败: {str(e)}")


def write_error_report(errors: List[Dict], output_path: Path):
    """写入错误报告"""
    if not errors:
        return
        
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# 规则转换错误报告\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"错误总数: {len(errors)}\n\n")
            
            # 按错误类型分组
            error_groups = {}
            for error in errors:
                error_type = error.get("type", "unknown")
                if error_type not in error_groups:
                    error_groups[error_type] = []
                error_groups[error_type].append(error)
            
            # 输出每种错误的统计和详情
            for error_type, group_errors in error_groups.items():
                f.write(f"## {error_type} 错误 ({len(group_errors)} 条)\n\n")
                
                for error in group_errors[:10]:  # 每种类型最多显示10条详情
                    f.write(f"- {error.get('message', '无详细信息')}")
                    if 'rule' in error:
                        f.write(f" (规则: {error['rule']})")
                    f.write("\n")
                
                if len(group_errors) > 10:
                    f.write(f"- ... 还有 {len(group_errors) - 10} 条类似错误\n")
                
                f.write("\n")
                
        logger.info(f"错误报告已写入: {output_path}")
    except Exception as e:
        logger.error(f"写入错误报告失败: {str(e)}")


def main():
    try:
        # 初始化配置
        config = Config()
        logger.info(f"配置初始化完成：输入={config.input_path}，输出={config.output_path}，编译器={config.compiler_path}")

        # 1. 解析Clash规则
        rules, errors = parse_clash_rules(config.input_path)
        
        # 写入错误报告
        error_report_path = config.workspace_path / "conversion_errors.md"
        write_error_report(errors, error_report_path)
        
        if not rules:
            logger.error("无有效Clash规则可转换，程序退出")
            return 1

        # 2. 生成Mihomo YAML
        yaml_content = generate_mihomo_yaml(rules)
        if not yaml_content:
            logger.error("生成Mihomo YAML内容失败")
            return 1
            
        # 记录前几条规则作为预览
        preview_lines = yaml_content.split('\n')[:10]
        logger.info(f"Mihomo YAML预览（前10行）:\n" + "\n".join(preview_lines))

        # 3. 编译为MRS规则集
        success, error_msg = compile_ruleset(config.compiler_path, yaml_content, config.output_path, config.RULE_TYPE)
        if not success:
            logger.error(f"MRS规则集编译失败: {error_msg}")
            return 1

        # 4. 计算输出文件信息
        file_hash = calculate_sha256(config.output_path)
        file_size_kb = config.output_path.stat().st_size / 1024

        # 5. 输出结果日志
        logger.info("=" * 50)
        logger.info(f"转换完成！")
        logger.info(f"输出文件: {config.output_path}")
        logger.info(f"规则数量: {len(rules)} 条")
        logger.info(f"错误数量: {len(errors)} 条")
        logger.info(f"文件大小: {file_size_kb:.2f} KB")
        logger.info(f"SHA256: {file_hash}")
        logger.info("=" * 50)

        # 6. 写入GitHub Action输出
        write_github_output({
            'mrs_path': str(config.output_path),
            'mrs_sha256': file_hash,
            'rule_count': str(len(rules)),
            'error_count': str(len(errors)),
            'mrs_size_kb': f"{file_size_kb:.2f}"
        })

        return 0
    except (FileNotFoundError, PermissionError, ValueError) as e:
        logger.error(f"配置校验失败: {str(e)}")
        return 1
    except Exception as e:
        logger.error(f"程序执行异常: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())