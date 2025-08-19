import re
from pathlib import Path

def filter_hosts_rules(input_path, output_path):
    """
    从DNS规则文件(dns.txt)中提取并转换Hosts格式规则
    
    Args:
        input_path (str/Path): 输入dns.txt文件路径
        output_path (str/Path): 输出hosts.txt文件路径
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # 增强版Hosts规则匹配正则（适配dns.txt格式）
    HOSTS_RULE_PATTERN = re.compile(
        r'^(\|\|([\w.-]+)\^($|[\w,=-]*))|'        # 基础域名规则(含修饰符)
        r'^\|\|([\w.-]+)\^\$dnsrewrite=(\d+\.\d+\.\d+\.\d+)|'  # DNS重写规则
        r'^(\d+\.\d+\.\d+\.\d+)\s+([\w.-]+)$'    # 原生Hosts格式
    )

    if not input_path.exists():
        raise FileNotFoundError(f"DNS规则文件不存在: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            count = 0
            seen = set()
            
            for line in infile:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    continue
                
                match = HOSTS_RULE_PATTERN.match(line)
                if match:
                    # 处理三种匹配情况
                    if match.group(2):  # ||domain.com^ 格式
                        ip = '0.0.0.0'
                        domain = match.group(2)
                    elif match.group(4):  # DNS重写格式
                        ip = match.group(5)
                        domain = match.group(4)
                    else:  # 原生Hosts格式
                        ip = match.group(7)
                        domain = match.group(8)
                    
                    # 标准化输出
                    entry = f"{ip} {domain}".lower()
                    if entry not in seen:
                        seen.add(entry)
                        outfile.write(f"{ip} {domain}\n")
                        count += 1

            print(f"从DNS规则转换 {count} 条Hosts记录")

    except Exception as e:
        print(f"处理失败: {e}")
        raise

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent.parent
    input_file = base_dir / "dns.txt"  # 修改输入为dns.txt
    output_file = base_dir / "hosts.txt"

    output_file.parent.mkdir(exist_ok=True)
    filter_hosts_rules(input_file, output_file)
