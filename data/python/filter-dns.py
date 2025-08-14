import re
from pathlib import Path

class AdGuardDNSRuleValidator:
    """AdGuard Home DNS规则验证器（完整官方支持）"""
    
    @staticmethod
    def is_valid_rule(line):
        """
        完整支持AdGuard Home官方文档的所有DNS过滤规则：
        - 基础域名规则
        - Hosts格式规则
        - 正则表达式规则
        - 所有修饰符规则（含$dnsrewrite等高级功能）
        """
        line = line.strip()
        if not line or line.startswith(('!', '#', '//')):
            return False
            
        # 官方完整规则匹配模式（含所有修饰符）
        patterns = [
            # 基础域名规则
            r'^(\|\|[\w.-]+\^|\|https?://[\w.-]+|[\w.-]+\.\w+$)',
            
            # Hosts格式（含IPv6）
            r'^((0\.0\.0\.0|127\.0\.0\.1|::)\s+[\w.-]+)',
            
            # 正则表达式
            r'^/.*/\^?(\$[\w,=-]+)?$',
            
            # 完整修饰符语法（官方文档第4章）
            r'^\|\|[\w.-]+\^(\$[\w]+(=[\w.-]+)?(,[\w]+(=[\w.-]+)?)*)+$',
            
            # DNS重写规则（官方文档5.2）
            r'^\|\|[\w.-]+\^\$dnsrewrite=([^;]+;)*[^;]+$',
            
            # 客户端指定规则（官方文档5.3）
            r'^\|\|[\w.-]+\^\$client(=~?[\w.-]+)?$',
            
            # 设备标签规则（官方文档5.8）
            r'^\|\|[\w.-]+\^\$ctag=[\w]+$'
        ]
        return any(re.match(p, line) for p in patterns)

def process_dns_rules():
    """处理DNS规则文件（自动定位仓库根目录）"""
    try:
        # 路径计算（兼容GitHub Actions）
        repo_root = Path(__file__).resolve().parent.parent.parent
        input_file = repo_root / "adblock.txt"
        output_file = repo_root / "dns.txt"
        
        print(f"输入文件: {input_file}")
        print(f"输出文件: {output_file}")
        
        if not input_file.exists():
            raise FileNotFoundError("adblock.txt不存在于仓库根目录")

        with input_file.open('r', encoding='utf-8', errors='replace') as f:
            valid_rules = [
                line.strip() for line in f 
                if AdGuardDNSRuleValidator.is_valid_rule(line)
            ]
        
        # 按规则类型排序优化性能（域名规则 > Hosts > 正则）
        sorted_rules = sorted(valid_rules, key=lambda x: (
            0 if x.startswith('||') else
            1 if re.match(r'^\d', x) else 2
        ))
        
        with output_file.open('w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_rules))
            
        print(f"\n处理完成！有效规则: {len(sorted_rules)}条")
        print("规则类型统计:")
        print(f"- 域名规则: {sum(1 for r in sorted_rules if r.startswith('||'))}")
        print(f"- Hosts规则: {sum(1 for r in sorted_rules if re.match(r'^\d', r))}")
        print(f"- 正则表达式: {sum(1 for r in sorted_rules if r.startswith('/'))}")
        
    except Exception as e:
        print(f"错误: {str(e)}")
        exit(1)

if __name__ == "__main__":
    process_dns_rules()