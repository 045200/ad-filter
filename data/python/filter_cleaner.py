import os
import ast
import sys

def extract_dependencies_from_file(file_path):
    """提取单个.py文件中的依赖模块"""
    dependencies = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            # 解析Python代码的AST语法树
            tree = ast.parse(f.read(), filename=file_path)
        
        # 遍历AST树，查找import语句
        for node in ast.walk(tree):
            # 处理 "import module" 格式
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.add(alias.name.split(".")[0])  # 取顶层模块名（如import a.b → 取a）
            # 处理 "from module import xxx" 格式
            elif isinstance(node, ast.ImportFrom):
                if node.module:  # 排除 "from . import xxx" 这类相对导入
                    dependencies.add(node.module.split(".")[0])
    except Exception as e:
        print(f"⚠️ 解析文件 {file_path} 出错：{str(e)}")
    return dependencies

def get_third_party_deps(all_deps):
    """过滤掉Python标准库，保留第三方依赖"""
    # 获取当前Python环境的标准库模块列表（Python 3.10+ 支持）
    stdlib_modules = set(sys.stdlib_module_names)
    # 手动补充部分常见标准库（避免低版本Python遗漏）
    extra_stdlib = {"os", "sys", "ast", "json", "re", "datetime", "time", "collections", "logging"}
    stdlib_modules.update(extra_stdlib)
    
    # 过滤：只保留不在标准库中的模块
    third_party_deps = [dep for dep in all_deps if dep not in stdlib_modules]
    return sorted(third_party_deps)  # 排序后返回，便于查看

def main():
    # 目标路径（可根据需求修改）
    target_dir = "./data/python/"
    if not os.path.exists(target_dir):
        print(f"❌ 路径 {target_dir} 不存在，请检查路径是否正确")
        return

    # 1. 遍历目标目录下所有.py文件
    all_dependencies = set()
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                file_deps = extract_dependencies_from_file(file_path)
                all_dependencies.update(file_deps)

    # 2. 过滤标准库，获取第三方依赖
    third_party_deps = get_third_party_deps(all_dependencies)
    if not third_party_deps:
        print("✅ 未检测到第三方依赖")
        return

    # 3. 生成pip安装命令
    pip_command = f"pip install {' '.join(third_party_deps)}"
    print("=" * 50)
    print("📦 检测到的第三方依赖：")
    for dep in third_party_deps:
        print(f"  - {dep}")
    print("\n💻 依赖安装命令：")
    print(f"\033[1;32m{pip_command}\033[0m")  # 绿色高亮显示命令
    print("=" * 50)

if __name__ == "__main__":
    main()
