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

    def __init__(self):
        self._validate_compiler()

    def _validate_compiler(self) -> None:
        """验证编译器路径有效性"""
        compiler_path = self.compiler_abs_path
        if not compiler_path.exists():
            logger.critical(f"编译器不存在: {compiler_path}")
            sys.exit(1)
        if not os.access(compiler_path, os.X_OK):
            logger.critical(f"编译器无执行权限: {compiler_path}")
            sys.exit(1)

    @property
    def input_path(self) -> Path:
        path = Path(self.GITHUB_WORKSPACE) / self.INPUT_FILE
        if not path.exists():
            logger.critical(f"输入文件不存在: {path}")
            sys.exit(1)
        return path

    @property
    def output_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.OUTPUT_FILE

    @property
    def compiler_abs_path(self) -> Path:
        return Path(self.GITHUB_WORKSPACE) / self.COMPILER_PATH if not os.path.isabs(self.COMPILER_PATH) else Path(self.COMPILER_PATH)


def setup_logger():
    """配置GitHub风格日志"""
    logger = logging.getLogger("AdblockConverterDirect")
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


class AdblockConverter:
    """规则转换器（专门处理第一个脚本的输出格式）"""
    def __init__(self, config: Config):
        self.config = config
        self.stats = {
            'total_rules': 0,
            'mrs_sha256': ''
        }

    def parse_input(self) -> list:
        """解析第一个脚本生成的规则文件"""
        logger.info(f"读取输入文件: {self.config.input_path}")

        try:
            with self.config.input_path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'payload' not in data:
                logger.error("输入文件缺少'payload'节点")
                return []

            rules = []
            for rule in data['payload']:
                if isinstance(rule, str):
                    # 处理字符串格式的规则 (DOMAIN-SUFFIX,example.com,REJECT)
                    parts = rule.split(',')
                    if len(parts) >= 3:  # 强制要求策略字段
                        rule_type = parts[0].strip().upper()
                        value = parts[1].strip()
                        action = parts[2].strip().upper()
                    else:
                        logger.warning(f"无效规则格式: {rule}")
                        continue

                    # 处理Clash特殊语法（负号处理）
                    new_type, new_value = self._convert_clash_syntax(rule_type, value)
                    rules.append({
                        'type': new_type,
                        'value': new_value,
                        'action': action
                    })
                    self.stats['total_rules'] += 1

                elif isinstance(rule, dict):
                    # 处理字典格式的规则
                    rule_type = rule.get('type', '').upper()
                    value = rule.get('value', '').strip()
                    action = rule.get('action', 'REJECT').upper()

                    if not rule_type or not value:
                        logger.warning(f"无效规则格式: {rule}")
                        continue

                    new_type, new_value = self._convert_clash_syntax(rule_type, value)
                    rules.append({
                        'type': new_type,
                        'value': new_value,
                        'action': action
                    })
                    self.stats['total_rules'] += 1

            logger.info(f"成功解析 {self.stats['total_rules']} 条规则")
            return rules
        except yaml.YAMLError as e:
            logger.error(f"输入文件YAML格式错误: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"读取输入文件失败: {str(e)}")
            return []

    def _convert_clash_syntax(self, rule_type: str, value: str) -> tuple:
        """转换Clash特殊语法为Mihomo兼容格式"""
        if rule_type in ['DOMAIN-KEYWORD', 'DOMAIN-SUFFIX'] and value.startswith('-'):
            # 转换负号规则为排除类型
            new_type = f"{rule_type}-EXCLUDE"
            new_value = value[1:]
        else:
            new_type = rule_type
            new_value = value

        return new_type, new_value

    def generate_compile_yaml(self, rules: list) -> str:
        """生成用于编译的YAML内容"""
        if not rules:
            return ""

        yaml_lines = ["rules:"]  # Mihomo要求的根节点为rules
        for rule in rules:
            yaml_lines.append(f"  - type: {rule['type']}")
            yaml_lines.append(f"    value: {rule['value']}")
            yaml_lines.append(f"    action: {rule['action']}")

        return '\n'.join(yaml_lines)

    def compute_sha256(self, file_path: Path) -> str:
        """计算文件的SHA256校验和"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"计算SHA256校验和失败: {str(e)}")
            return ""

    def compile_to_mrs(self, yaml_content: str) -> bool:
        """编译为MRS格式"""
        if not yaml_content:
            with self.config.output_path.open('w', encoding='utf-8') as f:
                f.write("")
            logger.warning("无有效规则，生成空MRS文件")
            return True

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
                f.write(yaml_content)
                temp_file = f.name

            # 修正后的Mihomo命令参数（根据联网核实）
            result = subprocess.run(
                [
                    str(self.config.compiler_abs_path),
                    "convert",  # 替换为正确的子命令
                    "-i", temp_file,
                    "-o", str(self.config.output_path),
                    "-t", "domain"  # 指定规则类型
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                text=True
            )

            if result.returncode != 0:
                logger.error(
                    f"编译失败(返回码{result.returncode}):\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}"
                )
                return False

            if not self.config.output_path.exists() or self.config.output_path.stat().st_size == 0:
                logger.error("编译成功但输出文件为空")
                return False

            self.stats['mrs_sha256'] = self.compute_sha256(self.config.output_path)
            if not self.stats['mrs_sha256']:
                logger.error("无法计算MRS文件的SHA256校验和")
                return False

            logger.info(
                f"MRS生成成功: {self.config.output_path} "
                f"({self.config.output_path.stat().st_size / 1024:.1f}KB), "
                f"SHA256: {self.stats['mrs_sha256']}"
            )
            return True
        except subprocess.TimeoutExpired:
            logger.error("编译超时（>300秒）")
            return False
        except Exception as e:
            logger.error(f"编译异常: {str(e)}")
            return False
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass

    def run(self) -> int:
        """执行转换流程"""
        rules = self.parse_input()
        if not rules:
            logger.error("无规则可处理，终止流程")
            return 1

        yaml_content = self.generate_compile_yaml(rules)
        if not self.compile_to_mrs(yaml_content):
            return 1

        # 输出GitHub Action变量
        github_output = os.getenv('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"mrs_path={self.config.output_path}\n")
                f.write(f"final_rule_count={len(rules)}\n")
                f.write(f"mrs_sha256={self.stats['mrs_sha256']}\n")

        logger.info("转换流程完成")
        return 0


def main():
    try:
        config = Config()
        return AdblockConverter(config).run()
    except Exception as e:
        logger.critical(f"运行失败: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
