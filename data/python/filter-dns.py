import re
from pathlib import Path

def is_valid_blacklist_rule(line):
    """
    检查是否为有效的DNS黑名单规则（AdGuard Home原生支持格式）：
    - AdBlock语法：||domain^、|https://、/ads/
    - Hosts语法：0.0.0.0 domain、127.0.0.1 domain
    - 纯域名：domain.com
    - 排除注释和空行
    """
    line = line.strip()
    
    # 跳过空行和注释（以! # @ / [开头的行）
    if not line or line.startswith(('!', '#', '@', '/', '[', '=====')):
        return False
    
    # 匹配AdBlock规则（||domain^、|https://domain、/ads/）
    if re.match(r'^(\|\|?[\w.-]+\^?|/{2}.*?/|\|https?://)', line):
        return True
    
    # 匹配Hosts规则（0.0.0.0 domain 或 127.0.0.1 domain）
    if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+[\w.-]+', line):
        return True
    
    # 匹配纯域名规则（domain.com）
    if re.match(r'^([\w.-]+)$', line) and '.' in line:  # 简单域名验证
        return True
    
    return False

def filter_dns_blacklist(input_path, output_path):
    """
    生成AdGuard Home兼容的DNS黑名单文件
    保留原始规则格式（不转换Hosts语法）
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8', newline='\n') as outfile:

            count = 0
            for line in infile:
                if is_valid_blacklist_rule(line):
                    outfile.write(line.strip() + '\n')
                    count += 1

            print(f"已提取 {count} 条黑名单规则（保留原始格式）")

    except IOError as e:
        print(f"文件处理错误: {e}")

if __name__ == "__main__":
    # 文件路径配置
    base_dir = Path(__file__).parent.parent.parent  # 指向仓库根目录
    input_file = base_dir / "adblock.txt"  # 混合规则输入文件
    output_file = base_dir / "dns.txt"    # 黑名单输出文件

    # 确保输出目录存在
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    filter_dns_blacklist(input_file, output_file)