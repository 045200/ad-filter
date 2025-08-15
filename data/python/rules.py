import os
import sys
import json
import subprocess
from pathlib import Path

# 路径配置
SCRIPT_DIR = Path(__file__).parent                  # ./data/python/
ROOT_DIR = SCRIPT_DIR.parent.parent.parent          # 根目录
TSURLFILTER_PATH = ROOT_DIR / "tsurlfilter"        # tsurlfilter 仓库位置

# 输入输出路径
INPUT_FILE = ROOT_DIR / "adblock.txt"               # 根目录输入
OUTPUT_FILES = {
    'adb': ROOT_DIR / "adb.txt",                   # 根目录输出
    'adw': ROOT_DIR / "adw.txt",
    'dns': ROOT_DIR / "add.txt"
}

def run_node_processor():
    """调用Node.js脚本处理规则（添加NODE_PATH环境变量）"""
    node_script = SCRIPT_DIR / "rule.js"
    
    # 设置NODE_PATH指向tsurlfilter编译后的dist目录
    node_path = str(TSURLFILTER_PATH / "packages" / "tsurlfilter" / "dist")
    
    try:
        result = subprocess.run(
            ["node", str(node_script), str(INPUT_FILE)],
            capture_output=True,
            text=True,
            encoding='utf-8',
            env={
                **os.environ,
                "NODE_PATH": node_path  # 关键：指定模块路径
            },
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Node.js执行失败:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"JSON解析失败:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

def save_outputs(classified_rules: dict):
    """保存分类后的规则到文件"""
    for key, path in OUTPUT_FILES.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(classified_rules.get(key, [])))

def main():
    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"错误：输入文件不存在 {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    # 处理规则
    classified = run_node_processor()
    save_outputs(classified)

    # 打印统计
    print("✅ 规则处理完成")
    print(f"  总规则数: {len(classified['adb'])}")
    print(f"  白名单规则: {len(classified['adw'])}")
    print(f"  DNS规则: {len(classified['dns'])}")

if __name__ == "__main__":
    main()