import os
import ast
import sys
import importlib.util
import logging
import subprocess
from pathlib import Path
from typing import Set, List, Dict, Any, Optional, Tuple

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 模块名到包名的映射（处理导入名与安装名不一致的情况）
MODULE_TO_PACKAGE_MAP = {
    "sklearn": "scikit-learn",
    "PIL": "Pillow",
    "dateutil": "python-dateutil",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "django": "django",
    "flask": "flask",
    "requests": "requests",
    "numpy": "numpy",
    "pandas": "pandas",
    "matplotlib": "matplotlib",
    "seaborn": "seaborn",
    "tensorflow": "tensorflow",
    "torch": "torch",
    "keras": "keras",
    "skimage": "scikit-image",
    "plotly": "plotly",
    "bokeh": "bokeh",
    "sqlalchemy": "sqlalchemy",
    "pytest": "pytest",
    "unittest": "",  # 标准库，空字符串表示跳过
    "json": "",      # 标准库
    "os": "",        # 标准库
    "sys": "",       # 标准库
    # 可以继续添加更多映射
}

def is_std_lib_module(module_name: str) -> bool:
    """
    判断一个模块是否属于Python标准库
    
    Args:
        module_name: 模块名
        
    Returns:
        bool: 如果是标准库模块返回True，否则返回False
    """
    # 获取Python标准库模块列表
    stdlib_modules = set(sys.stdlib_module_names)
    
    # 手动补充一些可能不在sys.stdlib_module_names中的常见标准库
    extra_stdlib = {
        "os", "sys", "ast", "json", "re", "datetime", "time", "collections", 
        "logging", "pathlib", "itertools", "functools", "subprocess", "math",
        "random", "statistics", "csv", "xml", "html", "http", "urllib", "socket",
        "ssl", "threading", "multiprocessing", "asyncio", "typing", "enum", "unittest"
    }
    stdlib_modules.update(extra_stdlib)
    
    return module_name in stdlib_modules

def map_module_to_package(module_name: str) -> str:
    """
    将模块名映射到对应的PyPI包名
    
    Args:
        module_name: 模块名
        
    Returns:
        str: PyPI包名，如果无法映射则返回原模块名
    """
    # 检查映射表
    if module_name in MODULE_TO_PACKAGE_MAP:
        mapped_name = MODULE_TO_PACKAGE_MAP[module_name]
        return mapped_name if mapped_name else module_name  # 空字符串表示标准库
    
    # 默认情况下，返回原模块名
    return module_name

def extract_dependencies_from_file(file_path: str) -> Set[str]:
    """
    提取单个.py文件中的依赖模块（顶层模块名）
    
    Args:
        file_path: Python文件路径
        
    Returns:
        Set[str]: 依赖的模块集合
    """
    dependencies = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        # 解析Python代码的AST语法树
        tree = ast.parse(source_code, filename=file_path)
        
        # 遍历AST树，查找import语句
        for node in ast.walk(tree):
            # 处理 "import module" 格式
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # 取顶层模块名（如import a.b → 取a）
                    top_level_module = alias.name.split(".")[0]
                    dependencies.add(top_level_module)
            
            # 处理 "from module import xxx" 格式
            elif isinstance(node, ast.ImportFrom):
                # 排除相对导入（如 from . import module）
                if node.module and node.level == 0:
                    # 取顶层模块名（如from a.b import c → 取a）
                    top_level_module = node.module.split(".")[0]
                    dependencies.add(top_level_module)
                    
    except SyntaxError as e:
        logger.warning(f"⚠️ 文件 {file_path} 存在语法错误，无法解析: {str(e)}")
    except UnicodeDecodeError as e:
        logger.error(f"⚠️ 文件 {file_path} 编码问题: {str(e)}")
        try:
            # 尝试使用其他编码
            with open(file_path, "r", encoding="latin-1") as f:
                source_code = f.read()
            logger.info(f"使用latin-1编码成功读取文件 {file_path}")
        except Exception as retry_e:
            logger.error(f"⚠️ 重试读取文件 {file_path} 失败: {str(retry_e)}")
    except Exception as e:
        logger.error(f"⚠️ 解析文件 {file_path} 出错: {str(e)}")
    
    return dependencies

def get_third_party_deps(all_deps: Set[str]) -> List[str]:
    """
    过滤掉Python标准库，保留第三方依赖
    
    Args:
        all_deps: 所有检测到的依赖模块
        
    Returns:
        List[str]: 第三方依赖列表（已排序）
    """
    # 过滤：只保留不在标准库中的模块
    third_party_deps = [dep for dep in all_deps if not is_std_lib_module(dep)]
    
    # 按字母顺序排序，便于阅读和管理
    return sorted(third_party_deps)

def resolve_package_names(module_names: List[str]) -> List[str]:
    """
    解析模块名到实际的PyPI包名
    
    Args:
        module_names: 模块名列表
        
    Returns:
        List[str]: 解析后的包名列表
    """
    package_names = set()
    
    for module_name in module_names:
        # 跳过标准库模块
        if is_std_lib_module(module_name):
            continue
            
        # 映射模块名到包名
        package_name = map_module_to_package(module_name)
        
        # 如果映射后的包名为空，表示这是标准库模块
        if not package_name:
            continue
            
        package_names.add(package_name)
    
    return sorted(list(package_names))

def find_python_files(directory: str) -> List[str]:
    """
    查找目录中的所有Python文件
    
    Args:
        directory: 要搜索的目录
        
    Returns:
        List[str]: Python文件路径列表
    """
    python_files = []
    directory_path = Path(directory)
    
    if not directory_path.exists():
        logger.error(f"❌ 路径 {directory} 不存在")
        return python_files
    
    # 递归查找所有.py文件
    python_files = [str(path) for path in directory_path.rglob("*.py")]
    logger.info(f"找到 {len(python_files)} 个Python文件")
    
    return python_files

def detect_dynamic_imports(file_path: str) -> Set[str]:
    """
    尝试检测文件中的动态导入（如importlib.import_module）
    
    Args:
        file_path: Python文件路径
        
    Returns:
        Set[str]: 检测到的动态导入模块名
    """
    dynamic_imports = set()
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # 简单的正则匹配来检测常见的动态导入模式
        import re
        
        # 检测 importlib.import_module 调用
        importlib_pattern = r"import_module\(['\"]([^'\"]+)['\"]\)"
        matches = re.findall(importlib_pattern, content)
        for match in matches:
            # 取顶层模块名
            top_level = match.split(".")[0]
            if not is_std_lib_module(top_level):
                dynamic_imports.add(top_level)
        
        # 检测 __import__ 调用
        dunder_import_pattern = r"__import__\(['\"]([^'\"]+)['\"]\)"
        matches = re.findall(dunder_import_pattern, content)
        for match in matches:
            # 取顶层模块名
            top_level = match.split(".")[0]
            if not is_std_lib_module(top_level):
                dynamic_imports.add(top_level)
                
    except Exception as e:
        logger.error(f"检测动态导入时出错: {str(e)}")
    
    return dynamic_imports

def main():
    """主函数"""
    # 目标路径（可根据需求修改）
    target_dir = "./data/python/"
    
    # 1. 查找所有Python文件
    python_files = find_python_files(target_dir)
    if not python_files:
        logger.error("❌ 未找到任何Python文件，程序退出")
        return
    
    # 2. 提取所有依赖
    all_dependencies = set()
    dynamic_imports = set()
    
    for file_path in python_files:
        # 提取静态导入
        file_deps = extract_dependencies_from_file(file_path)
        all_dependencies.update(file_deps)
        
        # 尝试检测动态导入
        dynamic_deps = detect_dynamic_imports(file_path)
        dynamic_imports.update(dynamic_deps)
    
    if not all_dependencies and not dynamic_imports:
        logger.info("✅ 未检测到任何依赖")
        return
    
    logger.info(f"共检测到 {len(all_dependencies)} 个静态导入依赖")
    if dynamic_imports:
        logger.info(f"检测到 {len(dynamic_imports)} 个动态导入依赖")
    
    # 3. 合并静态和动态导入
    all_detected_deps = all_dependencies.union(dynamic_imports)
    
    # 4. 过滤标准库，获取第三方依赖
    third_party_deps = get_third_party_deps(all_detected_deps)
    if not third_party_deps:
        logger.info("✅ 未检测到第三方依赖")
        return
    
    logger.info(f"检测到 {len(third_party_deps)} 个第三方依赖模块")
    
    # 5. 解析模块名到实际的PyPI包名
    package_names = resolve_package_names(third_party_deps)
    logger.info(f"解析为 {len(package_names)} 个PyPI包")
    
    # 6. 输出结果
    print("=" * 60)
    print("📦 检测到的第三方依赖：")
    for dep in package_names:
        print(f"  - {dep}")
    
    # 7. 生成安装命令
    pip_command = f"pip install {' '.join(package_names)}"
    print("\n💻 依赖安装命令：")
    print(f"\033[1;32m{pip_command}\033[0m")  # 绿色高亮显示命令
    
    # 8. 生成requirements.txt文件
    requirements_path = os.path.join(target_dir, "requirements.txt")
    try:
        with open(requirements_path, "w", encoding="utf-8") as f:
            for dep in package_names:
                f.write(f"{dep}\n")
        logger.info(f"✅ 已生成requirements.txt文件: {requirements_path}")
    except Exception as e:
        logger.error(f"❌ 生成requirements.txt文件失败: {str(e)}")
    
    print("\n📝 提示：")
    print("  1. 可使用 'pip install -r requirements.txt' 安装依赖")
    print("  2. 此工具基于静态分析，可能无法检测到所有动态导入的模块")
    print("  3. 建议在虚拟环境中安装依赖")
    print("  4. 某些依赖可能需要特定版本，请根据需要调整")
    
    # 9. 显示可能的映射问题
    if len(third_party_deps) != len(package_names):
        print("\n⚠️  注意：")
        print("  某些模块名已映射到不同的包名：")
        for module in third_party_deps:
            package = map_module_to_package(module)
            if package != module:
                print(f"    {module} → {package}")
    
    print("=" * 60)

if __name__ == "__main__":
    main()