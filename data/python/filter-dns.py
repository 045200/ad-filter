import re
from pathlib import Path
from collections import OrderedDict

def filter_dns_rules(input_path, output_path):
    """
    AdGuard Home DNS规则转换器
    只处理拦截规则，白名单规则直接使用allow.txt
    """
    input_path = Path(input_path)
    output_path = Path(output_path)
    
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    # 预编译正则表达式
    patterns = {
        'block': re.compile(r'^\|\|([\w.-]+)\^(\$.*)?$'),
        'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$'),
        'dns_type': re.compile(r'^\|\|([\w.-]+)\^\$dnstype=~?(?:[\w,]+)$'),
        'dnsrewrite': re.compile(r'^\|\|([\w.-]+)\^\$dnsrewrite=.*$'),
        'regex': re.compile(r'^/(.+)/$'),
        'domain_only': re.compile(r'^([\w.-]+)$'),
        'comment': re.compile(r'^[!#]|^$')
    }

    seen = OrderedDict()
    count = 0

    with input_path.open('r', encoding='utf-8') as infile, \
         output_path.open('w', encoding='utf-8') as outfile:

        for line in infile:
            line = line.strip()
            if patterns['comment'].match(line) or line.startswith('@@'):
                continue  # 跳过注释和白名单

            domain = None
            for pattern in ['block', 'hosts', 'dns_type', 'dnsrewrite', 'domain_only']:
                if match := patterns[pattern].match(line):
                    domain = match.group(1)
                    break
            
            if domain and domain not in seen:
                outfile.write(f"||{domain}^\n")
                seen[domain] = True
                count += 1
            elif patterns['regex'].match(line) and line not in seen:
                outfile.write(f"{line}\n")
                seen[line] = True
                count += 1

        print(f"转换完成: 共生成 {count} 条DNS拦截规则")

if __name__ == "__main__":
    repo_root = Path(__file__).parent.parent.parent
    filter_dns_rules(
        input_path=repo_root / "adblock.txt",
        output_path=repo_root / "dns.txt"
    )
    print("请手动将 allow.txt 重命名为 dnsallow.txt (如需)")