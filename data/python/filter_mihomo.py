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
        return path

    @property
    def output_path(self) -> Path:
        return self.workspace_path / self.OUTPUT_FILE

    @property
    def compiler_path(self) -> Path:
        path = Path(self.COMPILER_PATH)
        return path if path.is_absolute() else self.workspace_path / self.COMPILER_PATH

def setup_logger():
    """配置GitHub风格日志"""
    logger = logging.getLogger("AdblockConverter")
    logger.setLevel(logging.INFO)

    class GitHubFormatter(logging.Formatter):
        def format(self, record):
            timestamp = datetime.now().strftime('%H:%M:%S')
            if record.levelno == logging.INFO:
                return f"[{timestamp}] ::notice:: {record.getMessage()}"
            elif record.levelno == logging.WARNING:
                return f"[{timestamp}] ::warning:: {record.getMessage()}"
            elif record.levelno == logging.ERROR:
                return f"[{timestamp}] ::error:: {record.getMessage()}"
            return f"[{timestamp}] {record.getMessage()}"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GitHubFormatter())
    logger.handlers = [handler]
    return logger

logger = setup_logger()

def parse_clash_rules(input_path: Path):
    """解析第一个脚本生成的Clash规则文件"""
    logger.info(f"读取Clash规则文件: {input_path}")
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'payload' not in data:
            logger.error("输入文件缺少'payload'节点")
            return []
        
        rules = []
        for rule in data['payload']:
            if not isinstance(rule, str):
                continue
                
            # 解析Clash格式规则: TYPE,value,action
            parts = rule.split(',')
            if len(parts) < 3:
                continue
                
            rule_type = parts[0].strip()
            value = parts[1].strip()
            action = parts[2].strip()
            
            # 转换为Mihomo兼容格式
            rules.append({
                'type': rule_type,
                'value': value,
                'action': action
            })
        
        logger.info(f"成功解析 {len(rules)} 条Clash规则")
        return rules
    except Exception as e:
        logger.error(f"解析Clash规则失败: {str(e)}")
        return []

def generate_mihomo_yaml(rules: list):
    """生成Mihomo工具所需的YAML格式"""
    yaml_content = ["rules:"]
    
    for rule in rules:
        yaml_content.append(f"  - type: {rule['type']}")
        yaml_content.append(f"    value: {rule['value']}")
        yaml_content.append(f"    action: {rule['action']}")
    
    return '\n'.join(yaml_content)

def compile_ruleset(compiler_path: Path, yaml_content: str, output_path: Path):
    """使用Mihomo工具编译规则集"""
    temp_file = None
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            f.write(yaml_content)
            temp_file = f.name
        
        # 执行编译命令
        cmd = [
            str(compiler_path),
            "convert-ruleset",
            "domain",
            "yaml",
            temp_file,
            str(output_path)
        ]
        
        logger.info(f"执行编译命令: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            logger.error(f"编译失败: {result.stderr}")
            return False
            
        if not output_path.exists() or output_path.stat().st_size == 0:
            logger.error("编译成功但输出文件为空")
            return False
            
        return True
        
    except subprocess.TimeoutExpired:
        logger.error("编译超时")
        return False
    except Exception as e:
        logger.error(f"编译过程异常: {str(e)}")
        return False
    finally:
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)

def calculate_sha256(file_path: Path):
    """计算文件SHA256哈希"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"计算SHA256失败: {str(e)}")
        return ""

def write_github_output(variables: dict):
    """写入GitHub Action输出变量"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if not github_output:
        return
        
    try:
        with open(github_output, 'a') as f:
            for key, value in variables.items():
                f.write(f"{key}={value}\n")
    except Exception as e:
        logger.warning(f"写入GitHub输出失败: {str(e)}")

def main():
    try:
        config = Config()
        
        # 验证编译器存在
        if not config.compiler_path.exists():
            logger.error(f"Mihomo工具不存在: {config.compiler_path}")
            return 1
            
        if not os.access(config.compiler_path, os.X_OK):
            logger.error(f"Mihomo工具无执行权限: {config.compiler_path}")
            return 1
        
        # 解析Clash规则
        rules = parse_clash_rules(config.input_path)
        if not rules:
            logger.error("无有效规则可处理")
            return 1
            
        # 生成Mihomo格式YAML
        yaml_content = generate_mihomo_yaml(rules)
        
        # 编译规则集
        if not compile_ruleset(config.compiler_path, yaml_content, config.output_path):
            return 1
            
        # 计算输出文件哈希
        file_hash = calculate_sha256(config.output_path)
        file_size = config.output_path.stat().st_size / 1024
        
        logger.info(f"编译成功! 输出文件: {config.output_path}")
        logger.info(f"文件大小: {file_size:.2f}KB, SHA256: {file_hash}")
        
        # 写入GitHub Action输出
        write_github_output({
            'mrs_path': str(config.output_path),
            'mrs_sha256': file_hash,
            'rule_count': str(len(rules)),
            'mrs_size_kb': f"{file_size:.2f}"
        })
        
        return 0
        
    except Exception as e:
        logger.error(f"程序执行失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())