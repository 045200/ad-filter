#!/usr/bin/env python3
"""
AdGuard规则转换工作流 (GitHub Actions 优化版)
• 极速转换 | 资源监控 | 自动校验
• 输入: /ads.yaml (根目录)
• 输出: /data/adb.mrs
• 自动使用预置Mihomo二进制
"""

import os
import sys
import subprocess
import logging
import time
import hashlib
from pathlib import Path

# === 配置区 ===
MIHOMO_BIN = "/data/mihomo-linux-amd64"  # 预置二进制路径
INPUT_FILE = "ads.yaml"                  # 根目录输入文件
OUTPUT_FILE = "adb.mrs"             # 二进制规则输出
TIMEOUT = 180                            # 转换超时时间(秒)
MAX_RETRIES = 2                          # 转换失败重试次数

# === 日志设置 ===
def setup_logger():
    """高性能日志配置"""
    logger = logging.getLogger("mrs-converter")
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)-5s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    
    # 添加颜色支持 (GitHub Actions兼容)
    class ColorFormatter(logging.Formatter):
        LEVEL_COLORS = {
            'INFO': '\033[92m',    # 绿色
            'WARNING': '\033[93m', # 黄色
            'ERROR': '\033[91m',   # 红色
            'CRITICAL': '\033[91m' # 红色
        }
        
        def format(self, record):
            levelname = record.levelname
            if levelname in self.LEVEL_COLORS:
                record.levelname = f"{self.LEVEL_COLORS[levelname]}{levelname}\033[0m"
            return super().format(record)
    
    if os.isatty(sys.stdout.fileno()):
        handler.setFormatter(ColorFormatter(
            '%(asctime)s [%(levelname)-8s] %(message)s',
            datefmt='%H:%M:%S'
        ))
    
    logger.addHandler(handler)
    return logger

log = setup_logger()

# === 路径处理 ===
def get_root_dir() -> Path:
    """智能定位GitHub仓库根目录"""
    # 优先使用GitHub Actions工作区
    if "GITHUB_WORKSPACE" in os.environ:
        return Path(os.environ["GITHUB_WORKSPACE"])
    
    # 次选脚本位置推断
    script_path = Path(__file__).resolve()
    if script_path.parts[-3:-1] == ('data', 'python'):
        return script_path.parent.parent.parent
    
    # 默认当前工作目录
    return Path.cwd()

# === 文件校验 ===
def file_checksum(path: Path) -> str:
    """计算文件SHA256校验和"""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

# === 规则转换核心 ===
def convert_to_mrs(input_path: Path, output_path: Path) -> bool:
    """
    高性能规则转换
    参数参考: https://github.com/MetaCubeX/mihomo/wiki/Command-Line-Arguments#convert-ruleset
    """
    # 确保输出目录存在
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        "domain",           # 输入类型
        "binary",           # 输出二进制格式
        str(input_path),    # 输入文件
        str(output_path)    # 输出文件
    ]

    # 记录输入文件信息
    input_size = input_path.stat().st_size / 1024
    log.info(f"📥 输入文件: {input_path.name} ({input_size:.1f} KB)")
    
    # 转换尝试
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            log.info(f"🔄 转换尝试 #{attempt}/{MAX_RETRIES}")
            start_time = time.time()
            
            # 执行转换命令
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=TIMEOUT
            )
            
            # 计算性能指标
            elapsed = time.time() - start_time
            output_size = output_path.stat().st_size / 1024
            
            # 输出转换结果
            log.info(f"✅ 转换成功! 耗时: {elapsed:.1f}s")
            log.info(f"📤 输出文件: {output_path.name} ({output_size:.1f} KB)")
            
            # 输出转换摘要
            if result.stdout:
                for line in result.stdout.splitlines():
                    if "ruleset converted" in line:
                        log.info(f"⚡ {line.strip()}")
            
            return True

        except subprocess.TimeoutExpired:
            log.error(f"⏱️ 转换超时 (>{TIMEOUT}秒)")
        except subprocess.CalledProcessError as e:
            log.error(f"🚨 转换失败 (code={e.returncode})")
            if e.stdout:
                for line in e.stdout.splitlines():
                    log.error(f"    {line}")
        except Exception as e:
            log.error(f"🔥 意外错误: {str(e)}")
        
        # 重试前等待
        if attempt < MAX_RETRIES:
            wait_time = 2 ** attempt  # 指数退避
            log.info(f"⏳ 等待 {wait_time}秒后重试...")
            time.sleep(wait_time)
    
    return False

# === 主流程 ===
def main() -> int:
    """工作流主控制器"""
    # 获取工作目录
    root_dir = get_root_dir()
    log.info(f"🏠 工作目录: {root_dir}")
    
    # 构建文件路径
    input_path = root_dir / INPUT_FILE
    output_path = root_dir / OUTPUT_FILE
    
    # 验证输入文件
    if not input_path.exists():
        log.error(f"❌ 输入文件不存在: {input_path}")
        return 1
    
    # 验证二进制文件
    if not Path(MIHOMO_BIN).exists():
        log.error(f"❌ 二进制文件不存在: {MIHOMO_BIN}")
        return 1
    if not os.access(MIHOMO_BIN, os.X_OK):
        log.error(f"❌ 二进制文件不可执行: {MIHOMO_BIN}")
        return 1
    
    # 记录输入文件校验和
    input_hash = file_checksum(input_path)
    log.info(f"🔒 输入校验和: SHA256:{input_hash[:12]}...")
    
    # 执行转换
    success = convert_to_mrs(input_path, output_path)
    
    # 验证输出
    if success:
        if output_path.exists():
            log.info(f"🔍 输出验证: 文件已生成 ({output_path.stat().st_size}字节)")
            return 0
        log.error("❌ 转换成功但输出文件不存在")
        return 1
    
    log.error("❌ 所有转换尝试均失败")
    return 1

if __name__ == "__main__":
    start_time = time.time()
    exit_code = main()
    elapsed = time.time() - start_time
    log.info(f"⏱️ 总耗时: {elapsed:.1f}秒")
    sys.exit(exit_code)