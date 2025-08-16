#!/usr/bin/env python3
import os
import re
import sys
import hashlib
import urllib.request
import urllib.error
import time
from pathlib import Path
from datetime import datetime
import tempfile
import subprocess
import shutil
from multiprocessing import Pool, cpu_count
from functools import partial
import atexit

# ==================== 全局配置 ====================
STRICT_MODE = True                # 严格模式开关
VALIDATE_OUTPUT = True            # 输出文件二次验证开关
ADBLOCK_MODE = True               # 广告规则优化
GITHUB_CI = os.getenv('GITHUB_ACTIONS') == 'true'
DEBUG_MODE = os.getenv('DEBUG') == '1'  # 调试模式开关

# 创建临时工作目录
WORK_DIR = Path(tempfile.mkdtemp(prefix="mihomo_adblock_"))

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

log(f"临时工作目录已创建: {WORK_DIR}")

class RuleValidator:
    """Mihomo兼容的广告规则验证器"""
    MIHOMO_SUPPORTED = {
        'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
        'IP-CIDR', 'IP-CIDR6'
    }

    UNSUPPORTED_PATTERNS = [
        r'##[^#\s\[]',            # 元素隐藏
        r'#\?#',                  # 扩展CSS
        r'\$\$',                  # 脚本规则
        r'\$[^,\s]+=',            # 复杂修饰符
        r'\/.+\/',                # 正则表达式
        r'\$(important|badfilter)' # 特殊标记
    ]

    @classmethod
    def pre_validate(cls, line, strict=True):
        """预处理验证"""
        line = line.strip()
        if not line or line.startswith(('!', '#')):
            return False

        if strict:
            for pattern in cls.UNSUPPORTED_PATTERNS:
                if re.search(pattern, line):
                    return False

        return any([
            re.match(r'^\|\|[\w.-]+\^$', line),
            re.match(r'^\|\|\*\.[\w.-]+\^$', line),
            re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$', line),
            re.match(r'^block:\/\/[\d.:]+$', line),
            re.match(r'^\$[a-z-]+$', line),
            re.match(r'^@@\|\|[\w.-]+\^$', line)
        ])

    @classmethod
    def post_validate(cls, mrs_file, tool_path):
        """输出文件验证"""
        try:
            result = subprocess.run(
                [str(tool_path), "validate", str(mrs_file)],
                capture_output=True,
                text=True,
                check=True
            )
            if "validation passed" not in result.stdout.lower():
                raise ValueError(result.stderr)
            return True
        except subprocess.CalledProcessError as e:
            error(f"验证失败: {e.stderr.strip()}")
            return False
        except Exception as e:
            error(f"验证异常: {str(e)}")
            return False

def get_config_paths():
    """根据仓库结构配置路径（脚本在/data/python/，输入输出在根目录）"""
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent.parent  # 假设脚本在 /data/python/
    
    # 验证目录结构
    required_files = [
        repo_root / "adblock.txt",
        repo_root / "allow.txt"
    ]
    for file in required_files:
        if not file.exists():
            raise FileNotFoundError(f"未找到输入文件: {file}")

    return {
        "input_files": {
            "block": repo_root / "adblock.txt",
            "allow": repo_root / "allow.txt"
        },
        "temp_files": {
            "merged": WORK_DIR / "merged.tmp",
            "validated": WORK_DIR / "validated.tmp"
        },
        "output": repo_root / "adb.mrs",
        "tool_dir": WORK_DIR / "tools"
    }

def cleanup():
    """清理临时工作目录"""
    if DEBUG_MODE or GITHUB_CI:
        log(f"调试模式保留临时目录: {WORK_DIR}")
        return

    try:
        if WORK_DIR.exists():
            shutil.rmtree(WORK_DIR)
            log("临时目录已清理")
    except Exception as e:
        error(f"清理失败: {str(e)}")

def convert_rule(line, is_allow=False):
    """规则转换核心"""
    if not RuleValidator.pre_validate(line, STRICT_MODE):
        return None

    policy = "DIRECT" if is_allow else "REJECT"
    line = line.strip()

    try:
        if line.startswith("||") and line.endswith("^"):
            domain = line[2:-1]
            if domain.startswith("*."):
                return f"DOMAIN-SUFFIX,{domain[2:]},{policy}"
            return f"DOMAIN,{domain},{policy}"

        if match := re.match(r'^(?:\d+\.\d+\.\d+\.\d+|\:\:)\s+([\w.-]+)', line):
            return f"DOMAIN,{match.group(1)},{policy}"

        if match := re.match(r'^block:\/\/([\d.:]+)', line):
            return f"IP-CIDR6,{match.group(1)}/128,{policy}" if ':' in match.group(1) \
                   else f"IP-CIDR,{match.group(1)}/32,{policy}"

        if match := re.match(r'^\$([a-z-]+)$', line):
            return f"DOMAIN-KEYWORD,{match.group(1)},{policy}"

        if line.startswith("@@"):
            return convert_rule(line[2:], True)

    except Exception as e:
        error(f"转换异常: {line} ({str(e)})")
    return None

def process_rules(input_path, output_path, is_allow=False):
    """处理规则文件"""
    temp_path = output_path.with_suffix('.tmp')
    existing = set()

    try:
        if output_path.exists():
            with open(output_path, 'r', encoding='utf-8') as f:
                existing.update(hashlib.md5(line.encode()).hexdigest() for line in f)

        content = _read_file_with_fallback(input_path)
        if not content:
            return False

        with open(temp_path, 'w', encoding='utf-8') as f_out:
            for line in content:
                if converted := convert_rule(line.strip(), is_allow):
                    digest = hashlib.md5(converted.encode()).hexdigest()
                    if digest not in existing:
                        f_out.write(converted + '\n')
                        existing.add(digest)

        temp_path.replace(output_path)
        return True
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        error(f"处理失败: {str(e)}")
        return False

def _read_file_with_fallback(filepath):
    """多编码读取文件"""
    encodings = ['utf-8', 'gbk', 'latin-1']
    for enc in encodings:
        try:
            with open(filepath, 'r', encoding=enc) as f:
                return f.readlines()
        except UnicodeDecodeError:
            continue
    error(f"文件解码失败: {filepath}")
    return None

def _ensure_mihomo_tool(tool_dir):
    """获取Mihomo工具"""
    tool_dir.mkdir(parents=True, exist_ok=True)
    tool_path = tool_dir / "mihomo-tool"
    
    if tool_path.exists():
        try:
            ver = subprocess.run([str(tool_path), "--version"], 
                               capture_output=True, text=True)
            if "mihomo" in ver.stdout.lower():
                return tool_path
        except Exception:
            pass
    
    url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/mihomo-tool-linux-amd64"
    for _ in range(3):
        try:
            urllib.request.urlretrieve(url, str(tool_path))
            tool_path.chmod(0o755)
            return tool_path
        except Exception as e:
            time.sleep(2)
    error("工具下载失败")
    return None

def _generate_mrs(input_file, output_file, tool_path):
    """生成MRS文件"""
    temp_output = output_file.with_suffix('.tmp')
    
    try:
        cmd = [
            str(tool_path),
            "rule-set",
            "--strict" if STRICT_MODE else "--loose",
            "--output", str(temp_output),
            str(input_file)
        ]
        subprocess.run(cmd, check=True)
        temp_output.replace(output_file)
        return True
    except subprocess.CalledProcessError as e:
        if temp_output.exists():
            temp_output.unlink()
        error(f"生成失败: {e.stderr.decode() if e.stderr else str(e)}")
        return False

def main():
    try:
        # 注册退出清理函数
        atexit.register(cleanup)

        # 获取配置路径
        config = get_config_paths()
        log(f"输入文件位置: {config['input_files']['block']}")
        log(f"输出文件位置: {config['output']}")

        # 1. 准备工具
        log("初始化Mihomo工具...")
        tool_path = _ensure_mihomo_tool(config["tool_dir"])
        if not tool_path:
            raise RuntimeError("工具初始化失败")

        # 2. 处理规则
        log(f"开始处理规则（模式={'strict' if STRICT_MODE else 'loose'}）...")
        if config["input_files"]["allow"].exists():
            log("处理白名单...")
            if not process_rules(config["input_files"]["allow"], 
                               config["temp_files"]["merged"], 
                               True):
                raise RuntimeError("白名单处理失败")

        log("处理黑名单...")
        if not process_rules(config["input_files"]["block"], 
                           config["temp_files"]["merged"], 
                           False):
            raise RuntimeError("黑名单处理失败")

        # 3. 生成MRS
        log("生成规则集文件...")
        if not _generate_mrs(config["temp_files"]["merged"], 
                          config["output"], 
                          tool_path):
            raise RuntimeError("MRS生成失败")

        # 4. 验证
        if VALIDATE_OUTPUT:
            log("执行二次验证...")
            if not RuleValidator.post_validate(config["output"], tool_path):
                raise RuntimeError("验证失败")

        log("处理成功完成！")
        return 0

    except FileNotFoundError as e:
        error(f"路径错误: {str(e)}")
        error("请确保：")
        error("1. 脚本位于 /data/python/ 目录")
        error("2. 输入文件在仓库根目录")
        return 1
    except Exception as e:
        error(f"处理失败: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())