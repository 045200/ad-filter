import re
from pathlib import Path

class AdGuardDNSFilter:
    """AdGuard Home DNS黑名单处理器"""
    
    @staticmethod
    def is_valid_rule(line):
        """
        验证规则是否符合AdGuard Home DNS黑名单语法规范
        支持类型：
        1. Adblock语法：||domain^、|https://domain|
        2. Hosts语法：0.0.0.0 domain（含IPv6）
        3. 纯域名：domain.com
        4. 正则表达式：/ads.*\.com/
        5. 修饰符规则：||domain^$dnstype=A
        """
        line = line.strip()
        if not line or line.startswith(('!', '#', '@@', '//')):
            return False
            
        # 官方支持的全部DNS过滤规则模式[citation:3][citation:8]
        patterns = [
            r'^(\|\|[\w.-]+\^|\|https?://[\w.-]+|)',  # Adblock基础语法
            r'^([\w.-]+\.)+[\w-]+$',  # 纯域名规则（必须含点）
            r'^((0\.0\.0\.0|127\.0\.0\.1|::)\s+[\w.-]+)',  # Hosts语法（含IPv6）
            r'^/.*/$',  # 正则表达式规则
            r'^\|\|[\w.-]+\^\$[a-z]+(=.*)?(,.*)?$',  # 修饰符规则
            r'^\|\|[\w.-]+\^\$dnstype=[A-Z]+',  # DNS类型过滤
            r'^\|\|[\w.-]+\^\$client=([\w.-]+|\d+\.\d+\.\d+\.\d+)'  # 客户端过滤
        ]
        return any(re.match(p, line) for p in patterns)

    @staticmethod
    def normalize_rule(rule):
        """规则标准化处理（保留原始格式）"""
        return rule.strip()

def process_dns_blacklist(input_file, output_file):
    """
    处理DNS黑名单文件
    :param input_file: 输入文件路径
    :param output_file: 输出文件路径
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        print(f"错误：输入文件不存在 {input_path}")
        return

    valid_rules = []
    with input_path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if AdGuardDNSFilter.is_valid_rule(line):
                normalized = AdGuardDNSFilter.normalize_rule(line)
                valid_rules.append(normalized)
                print(f"已接受: {normalized}")
            else:
                print(f"已跳过: {line.strip()}")

    # 按规则类型排序（提升查询性能）[citation:3]
    sorted_rules = sorted(valid_rules, key=lambda x: (
        0 if x.startswith('||') else
        1 if x.startswith(('0.0.0.0', '127.0.0.1', '::')) else
        2 if '/' in x else 3
    ))

    with output_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_rules))
        print(f"\n处理完成！有效规则数: {len(sorted_rules)}")
        print(f"输出文件: {output_path}")

if __name__ == "__main__":
    # 文件路径配置（仓库根目录）
    repo_root = Path(__file__).parent.parent
    input_file = repo_root / "adblock.txt"  # 混合规则输入文件
    output_file = repo_root / "dns.txt"     # 黑名单输出文件
    
    # 自动创建输出目录
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    process_dns_blacklist(input_file, output_file)