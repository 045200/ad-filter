import subprocess
import datetime
import pytz
from pathlib import Path
import re

def update_readme():
    try:
        # 定义文件路径
        rule_files = {
            'adblock': Path('./adblock.txt'),
            'dns': Path('./dns.txt'),
            'allow': Path('./allow.txt')
        }

        # 验证文件存在
        for name, path in rule_files.items():
            if not path.exists():
                raise FileNotFoundError(f"{path} not found")

        # 提取规则计数
        counts = {}
        for name, path in rule_files.items():
            try:
                # 方法1: 先尝试使用sed提取
                result = subprocess.run(
                    ["sed", "-n", r"s/^! Total count: \([0-9]\+\)$/\1/p", str(path)],
                    capture_output=True, text=True
                )
                count = result.stdout.strip()
                
                # 方法2: 如果sed失败，尝试直接读取文件查找
                if not count.isdigit():
                    with open(path, 'r') as f:
                        content = f.read()
                        match = re.search(r'^! Total count: (\d+)$', content, re.MULTILINE)
                        if match:
                            count = match.group(1)
                        else:
                            raise ValueError(f"无法从 {path} 中提取有效计数")
                
                counts[name] = count
                print(f"✅ 已处理 {path.name} | 规则总数: {counts[name]}")

            except Exception as e:
                raise ValueError(f"处理 {path} 时出错: {str(e)}")

        # 获取北京时间
        beijing_time = (datetime.datetime.now(pytz.timezone('UTC'))
                        .astimezone(pytz.timezone('Asia/Shanghai'))
                        .strftime('%Y-%m-%d %H:%M:%S'))

        # 更新README.md
        readme_path = Path('README.md')
        if not readme_path.exists():
            raise FileNotFoundError("README.md not found")

        with open(readme_path, 'r+', encoding='utf-8') as f:
            content = f.read()

            # 替换内容
            replacements = {
                r'更新时间:.*': f'更新时间: {beijing_time} （北京时间）',
                r'拦截规则数量.*': f'拦截规则数量: {counts["adblock"]}',
                r'DNS拦截规则数量.*': f'DNS拦截规则数量: {counts["dns"]}',
                r'白名单规则数量.*': f'白名单规则数量: {counts["allow"]}'
            }

            for pattern, repl in replacements.items():
                content = re.sub(pattern, repl, content, flags=re.MULTILINE)

            # 写回文件
            f.seek(0)
            f.write(content)
            f.truncate()

        print("✨ 已成功更新README.md中的规则计数和时间")
        return True

    except Exception as e:
        print(f"❌ 更新失败: {str(e)}")
        return False

if __name__ == "__main__":
    print("="*50)
    print(f"📁 仓库根目录: {Path.cwd()}")
    print(f"🔍 正在查找以下文件: {', '.join(['dns.txt', 'adblock.txt', 'allow.txt'])}")
    print("="*50)
    
    if update_readme():
        print("✨ 所有文件处理完成")
    else:
        print("❌ 处理过程中遇到错误")