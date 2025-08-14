import subprocess
import datetime
import pytz
from pathlib import Path

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
            result = subprocess.run(
                ["sed", "-n", f"s/^! Total count: //p", str(path)],
                capture_output=True, text=True, check=True
            )
            counts[name] = result.stdout.strip()
            if not counts[name].isdigit():
                raise ValueError(f"Invalid count in {path}")
        
        # 获取北京时间
        beijing_time = (datetime.datetime.now(pytz.timezone('UTC'))
                        .astimezone(pytz.timezone('Asia/Shanghai'))
                        .strftime('%Y-%m-%d %H:%M:%S'))
        
        # 更新README.md
        readme_path = Path('README.md')
        if not readme_path.exists():
            raise FileNotFoundError("README.md not found")
            
        with open(readme_path, 'r+') as f:
            content = f.read()
            
            # 替换内容
            replacements = {
                '更新时间:.*': f'更新时间: {beijing_time} （北京时间）',
                '拦截规则数量.*': f'拦截规则数量: {counts["adblock"]}',
                'DNS拦截规则数量.*': f'DNS拦截规则数量: {counts["dns"]}',
                '白名单规则数量.*': f'白名单规则数量: {counts["allow"]}'
            }
            
            for pattern, repl in replacements.items():
                content = re.sub(pattern, repl, content)
            
            # 写回文件
            f.seek(0)
            f.write(content)
            f.truncate()
            
        print("已成功更新README.md中的规则计数和时间")
        return True
        
    except Exception as e:
        print(f"更新失败: {str(e)}")
        return False

if __name__ == "__main__":
    import re
    update_readme()