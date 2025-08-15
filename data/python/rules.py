import os
import sys
import json
import subprocess
from pathlib import Path

# 路径配置
SCRIPT_DIR = Path(__file__).parent                  # ./data/python/
ROOT_DIR = SCRIPT_DIR.parent.parent.parent          # 根目录
TSURLFILTER_MODULE_PATH = ROOT_DIR / "tsurlfilter" / "packages" / "tsurlfilter"

# 输入输出路径
INPUT_FILE = ROOT_DIR / "adblock.txt"               # 根目录输入
OUTPUT_FILES = {
    'adb': ROOT_DIR / "adb.txt",                   # 根目录输出
    'adw': ROOT_DIR / "adw.txt",
    'dns': ROOT_DIR / "add.txt"
}

def run_node_processor():
    """调用Node.js脚本处理规则"""
    node_script = SCRIPT_DIR / "rule.js"
    
    # 验证Node.js环境
    try:
        subprocess.run(["node", "--version"], check=True)
    except subprocess.CalledProcessError:
        print("❌ Node.js未正确安装", file=sys.stderr)
        sys.exit(1)

    try:
        result = subprocess.run(
            ["node", str(node_script), str(INPUT_FILE)],
            capture_output=True,
            text=True,
            encoding='utf-8',
            env={
                **os.environ,
                "NODE_PATH": str(TSURLFILTER_MODULE_PATH)
            },
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Node.js执行失败:\nSTDERR: {e.stderr}\nSTDOUT: {e.stdout}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}\n原始输出: {result.stdout}", file=sys.stderr)
        sys.exit(1)

def save_outputs(classified_rules: dict):
    """保存分类后的规则到文件"""
    for key, path in OUTPUT_FILES.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(classified_rules.get(key, [])))  # 这里需要两个闭合括号
            print(f"📁 已保存 {key} 规则到 {path}")

def main():
    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"❌ 错误：输入文件不存在 {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    # 检查tsurlfilter模块
    if not (TSURLFILTER_MODULE_PATH / "dist").exists():
        print(f"❌ 错误：tsurlfilter模块未正确编译 {TSURLFILTER_MODULE_PATH}", file=sys.stderr)
        sys.exit(1)

    # 处理规则
    print("⏳ 开始处理规则...")
    classified = run_node_processor()
    save_outputs(classified)

    # 打印统计
    print("\n✅ 规则处理完成")
    print(f"  总规则数: {len(classified['adb'])}")
    print(f"  白名单规则: {len(classified['adw'])}")
    print(f"  DNS规则: {len(classified['dns'])}")

if __name__ == "__main__":
    main()