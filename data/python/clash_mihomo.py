#!/usr/bin/env python3
"""
Clash广告规则转换工具增强版
功能：
1. 支持多平台广告规则语法(AdBlock/EasyList/AdGuard/uBO/ABP)
2. 基于RFC标准的DNS域名验证
3. 自动分类优化规则
4. 生成兼容Clash的规则集
"""

import argparse
import atexit
import gzip
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import List, Set, Tuple, Optional

# ==================== 全局配置 ====================
DEFAULT_BEHAVIOR = "domain"
MIHOMO_RELEASE_URL = "https://github.com/MetaCubeX/mihomo/releases/latest/download/"
DEFAULT_HEADER = """#TITLE=Optimized AdBlock Rules
#VER={date}
#URL=https://github.com/your-repo/ad-rules
#RULE-SET,AdBlock,REJECT
payload:
"""
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent.parent

class Logger:
    @staticmethod
    def info(msg: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: {msg}")

    @staticmethod
    def error(msg: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {str(msg)}", file=sys.stderr)

    @staticmethod
    def debug(msg: str) -> None:
        if os.getenv("DEBUG"):
            print(f"[{datetime.now().strftime('%H:%M:%S')}] DEBUG: {msg}")

class DNSValidator:
    """基于RFC标准的DNS验证工具类"""
    
    # RFC 1034/1035/2181 合规检查
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        if not domain or len(domain) > 253:
            return False
        
        # 检查标签序列
        labels = domain.split('.')
        if not all(DNSValidator._is_valid_label(label) for label in labels):
            return False
            
        # 顶级域名不能是全数字
        if labels[-1].isdigit():
            return False
            
        return True

    @staticmethod
    def _is_valid_label(label: str) -> bool:
        if not label or len(label) > 63:
            return False
        # 标签必须匹配：字母开头结尾，中间允许字母数字连字符
        return bool(re.match(r'^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$', label))

    @staticmethod
    def is_valid_ipcidr(cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

class RuleConverter:
    """支持多平台语法的规则转换核心"""
    
    def __init__(self):
        self.seen_domains = set()
        self.seen_ips = set()
        self.invalid_count = 0

    def _normalize_domain(self, domain: str) -> Optional[str]:
        """标准化域名处理并验证"""
        domain = domain.lower().strip('.*-_')
        
        # 提取主域名部分
        if '://' in domain:
            domain = domain.split('://')[1]
        domain = re.split(r'[/\?\:]', domain)[0]
        
        # 验证DNS合规性
        if not DNSValidator.is_valid_domain(domain):
            self.invalid_count += 1
            Logger.debug(f"无效域名: {domain}")
            return None
            
        return domain

    def _parse_rule(self, line: str) -> Optional[Tuple[str, str]]:
        """解析单条规则返回(类型, 值)"""
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return None

        # 跳过白名单
        if line.startswith('@@'):
            return None

        # 1. 处理AdGuard风格 (||example.com^)
        if line.startswith('||') and line.endswith('^'):
            domain = self._normalize_domain(line[2:-1])
            return ('DOMAIN-SUFFIX', domain) if domain else None

        # 2. 处理URL规则 (*://example.com/*)
        if '://' in line:
            domain = self._normalize_domain(line.split('/')[2])
            return ('DOMAIN-SUFFIX', domain) if domain else None

        # 3. 处理HOSTS格式 (0.0.0.0 example.com)
        if match := re.match(r'^(?:\d+\.\d+\.\d+\.\d+|::)\s+([\w.-]+)', line):
            domain = self._normalize_domain(match.group(1))
            return ('DOMAIN', domain) if domain else None

        # 4. 处理IP-CIDR (192.168.1.0/24)
        if DNSValidator.is_valid_ipcidr(line):
            return ('IP-CIDR', line)

        # 5. 处理通配符 (*.example.com)
        if line.startswith('*.'):
            domain = self._normalize_domain(line[2:])
            return ('DOMAIN-SUFFIX', domain) if domain else None

        # 6. 处理纯域名 (example.com)
        if '.' in line and not any(c in line for c in '*?^/'):
            domain = self._normalize_domain(line)
            return ('DOMAIN', domain) if domain else None

        # 7. 处理关键词 (adserver)
        if re.match(r'^[\w\-]+$', line):
            return ('DOMAIN-KEYWORD', line.lower())

        return None

    def convert_file(self, input_path: Path) -> List[str]:
        """转换整个规则文件"""
        if not input_path.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_path}")

        rules = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if result := self._parse_rule(line):
                    rule_type, value = result
                    # 去重检查
                    if (rule_type, value) not in self.seen_domains:
                        rules.append(f"{rule_type},{value}")
                        self.seen_domains.add((rule_type, value))

        if not rules:
            raise ValueError("未生成有效规则")
            
        Logger.info(
            f"转换完成: 有效规则 {len(rules)}条, "
            f"跳过无效 {self.invalid_count}条"
        )
        return sorted(rules)  # 按字母排序便于阅读

class MihomoCompiler:
    """mihomo-tool 编译器封装"""
    
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.tool_path = work_dir / "mihomo-tool"
        self._setup_tool()

    def _setup_tool(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.tool_path.exists():
            self._download_tool()
        
        self.tool_path.chmod(0o755)
        self._verify_tool()

    def _download_tool(self) -> None:
        try:
            # 获取最新版本
            version_url = f"{MIHOMO_RELEASE_URL}version.txt"
            urllib.request.urlretrieve(version_url, self.work_dir/"version.txt")

            with open(self.work_dir/"version.txt", 'r') as f:
                version = f.read().strip()

            # 下载工具
            tool_name = f"mihomo-linux-amd64-{version}"
            tool_gz = self.work_dir / f"{tool_name}.gz"

            Logger.info(f"下载 mihomo-tool v{version}...")
            urllib.request.urlretrieve(f"{MIHOMO_RELEASE_URL}{tool_name}.gz", tool_gz)

            # 解压
            with gzip.open(tool_gz, 'rb') as f_in:
                with open(self.tool_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # 清理
            tool_gz.unlink()
            (self.work_dir/"version.txt").unlink()

        except Exception as e:
            raise RuntimeError(f"工具下载失败: {str(e)}")

    def _verify_tool(self) -> None:
        try:
            result = subprocess.run(
                [str(self.tool_path), "-v"],
                check=True,
                capture_output=True,
                text=True
            )
            Logger.info(f"工具版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"工具验证失败: {e.stderr}")

    def compile_ruleset(self, yaml_path: Path, output_path: Path, behavior: str) -> bool:
        """编译YAML为.mrs"""
        cmd = [
            str(self.tool_path),
            "convert-ruleset",
            behavior,
            "yaml",
            str(yaml_path),
            str(output_path)
        ]

        try:
            subprocess.run(cmd, check=True, timeout=60)
            return True
        except subprocess.TimeoutExpired:
            Logger.error("编译超时")
            return False
        except subprocess.CalledProcessError as e:
            Logger.error(f"编译失败: {e.stderr}")
            return False

def generate_yaml(rules: List[str], output_path: Path) -> bool:
    """生成YAML规则文件"""
    try:
        yaml_content = DEFAULT_HEADER.format(date=datetime.now().strftime('%Y%m%d%H%M%S'))
        yaml_content += "\n".join(f"  - '{rule}'" for rule in rules)
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        Logger.info(f"生成YAML规则: {len(rules)}条")
        return True
    except Exception as e:
        Logger.error(f"YAML生成失败: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="广告规则转换工具增强版")
    parser.add_argument(
        "--input",
        type=str,
        default="adblock.txt",
        help="输入文件路径（默认: adblock.txt）"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="adblock.mrs",
        help="输出文件路径（默认: adblock.mrs）"
    )
    parser.add_argument(
        "--behavior",
        choices=["domain", "classical"],
        default=DEFAULT_BEHAVIOR,
        help="规则行为模式（默认: domain）"
    )
    args = parser.parse_args()

    # 设置临时目录
    work_dir = Path(tempfile.mkdtemp(prefix="clash_"))
    atexit.register(lambda: shutil.rmtree(work_dir, ignore_errors=True))

    try:
        input_path = ROOT_DIR / args.input
        output_path = ROOT_DIR / args.output
        yaml_file = work_dir / "rules.yaml"

        Logger.info(f"开始处理: {input_path}")
        
        # 1. 转换规则
        converter = RuleConverter()
        rules = converter.convert_file(input_path)
        
        # 2. 生成YAML
        if not generate_yaml(rules, yaml_file):
            return 1

        # 3. 编译为MRS
        compiler = MihomoCompiler(work_dir)
        if compiler.compile_ruleset(yaml_file, output_path, args.behavior):
            Logger.info(f"✅ 成功生成: {output_path}")
            return 0

        return 1

    except Exception as e:
        Logger.error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())