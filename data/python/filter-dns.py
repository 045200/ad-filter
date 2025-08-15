import re
from pathlib import Path
from collections import OrderedDict
from typing import Dict, Pattern

class DNSRuleProcessor:
    """支持5类拦截器的DNS规则转换器"""
    
    def __init__(self):
        # 预编译所有拦截器支持的正则模式
        self.patterns = {
            # 通用域名规则（兼容所有拦截器）
            'domain': re.compile(r'^\|\|([\w*.-]+)\^(?:\$[\w-]+(?:=[\w.-]*)?)*$'),
            
            # 各拦截器特有规则
            'ublock': re.compile(r'^\|\|([\w.-]+)\^\$.*,\~?\w+'),  # uBlock修饰符组合
            'abp': re.compile(r'^\|\|([\w.-]+)\^\$~?\w+(?:,~?\w+)*'),  # ABP修饰符
            'adguard': re.compile(r'^\|\|([\w.-]+)\^\$(?:[\w-]+=[\w.-]+|ctag|dnstype)'),
            'pihole': re.compile(r'^(?:[\w*.-]+\s)?[\d.]+[\w*.-]+'),  # Pi-hole hosts格式
            'brave': re.compile(r'^\|\|([\w.-]+)\^$$'),  # Brave简化格式
            
            # DNS特定规则
            'dns_type': re.compile(r'^\|\|([\w.-]+)\^\$dnstype=~?[\w,]+$'),
            'dnsrewrite': re.compile(r'^\|\|([\w.-]+)\^\$dnsrewrite=(?:NOERROR\|)?(?:[A-Z]+\|)?(?:.+)?$'),
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w*.-]+)$'),
            
            # 其他可转换规则
            'regex': re.compile(r'^/(.+)/[imsxADSUXJ]*$'),  # 支持修饰符的正则
            'domain_only': re.compile(r'^([\w*.-]+)$'),  # 纯域名
            'comment': re.compile(r'^[!#]|^$')  # 注释/空行
        }
        
        # 各拦截器特殊处理标记
        self.handlers = {
            'ublock': self._handle_ublock,
            'abp': self._handle_abp,
            'adguard': self._handle_adguard,
            'pihole': self._handle_pihole,
            'brave': self._handle_brave
        }

    def process_file(self, input_path: Path, output_path: Path) -> int:
        """处理输入文件并生成DNS规则"""
        seen = OrderedDict()
        count = 0

        with input_path.open('r', encoding='utf-8', errors='replace') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            for line in infile:
                line = line.strip()
                if self._is_comment_or_whitelist(line):
                    continue

                # 尝试各拦截器的特殊处理
                processed = False
                for handler in self.handlers.values():
                    if result := handler(line, seen):
                        outfile.write(result + '\n')
                        count += 1
                        processed = True
                        break

                # 通用处理
                if not processed:
                    if result := self._handle_general(line, seen):
                        outfile.write(result + '\n')
                        count += 1

        return count

    def _is_comment_or_whitelist(self, line: str) -> bool:
        """判断是否为注释或白名单规则"""
        return bool(self.patterns['comment'].match(line)) or line.startswith('@@')

    def _handle_general(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        """处理通用DNS规则"""
        domain = None
        
        # 检查标准域名规则
        if match := self.patterns['domain'].match(line):
            domain = match.group(1)
        # 检查hosts格式
        elif match := self.patterns['hosts'].match(line):
            domain = match.group(1)
        # 检查纯域名
        elif match := self.patterns['domain_only'].match(line):
            domain = match.group(1)
        # 保留有效正则规则
        elif match := self.patterns['regex'].match(line):
            if line not in seen:
                seen[line] = True
                return line

        if domain and domain not in seen:
            seen[domain] = True
            return f"||{domain}^"

        return None

    # 各拦截器的特殊处理逻辑
    def _handle_ublock(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        if match := self.patterns['ublock'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^"
        return None

    def _handle_abp(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        if match := self.patterns['abp'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^"
        return None

    def _handle_adguard(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        if match := self.patterns['adguard'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^"
        # 处理AdGuard的DNS特殊规则
        elif match := self.patterns['dns_type'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^$dnstype=~A"
        elif match := self.patterns['dnsrewrite'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^$dnsrewrite=NOERROR;;"
        return None

    def _handle_pihole(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        if match := self.patterns['pihole'].match(line):
            parts = line.split()
            domain = parts[-1] if len(parts) > 1 else parts[0]
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^"
        return None

    def _handle_brave(self, line: str, seen: Dict[str, bool]) -> Optional[str]:
        if match := self.patterns['brave'].match(line):
            domain = match.group(1)
            if domain not in seen:
                seen[domain] = True
                return f"||{domain}^"
        return None

if __name__ == "__main__":
    processor = DNSRuleProcessor()
    
    repo_root = Path(__file__).parent.parent.parent
    input_file = repo_root / "adblock.txt"
    output_file = repo_root / "dns.txt"
    
    if not input_file.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_file}")

    count = processor.process_file(input_file, output_file)
    print(f"转换完成: 共生成 {count} 条兼容5类拦截器的DNS规则")
    print(f"输出文件: {output_file}")