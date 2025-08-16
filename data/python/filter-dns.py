import re
from pathlib import Path
from collections import OrderedDict
from typing import Dict, Pattern, Optional, Set
from urllib.parse import urlsplit

class DNSRuleProcessor:
    """支持ABP/AdGuard/uBO的DNS规则转换器（增强版）"""

    def __init__(self):
        # 预编译三大拦截器支持的正则模式
        self.patterns = {
            # 基础域名规则（三大拦截器通用）
            'domain': re.compile(r'^\|\|([\w*.-]+)\^(?:\$[\w-]+(?:=[\w.-]*)?(?:,~?[\w-]+)*)?$'),
            
            # 各拦截器特有规则
            'ubo': re.compile(r'^\|\|([\w.-]+)\^\$.*,\~?\w+'),  # uBO修饰符组合
            'abp': re.compile(r'^\|\|([\w.-]+)\^\$~?\w+(?:,~?\w+)*'),  # ABP修饰符
            'adguard': re.compile(r'^\|\|([\w.-]+)\^\$(?:[\w-]+=[\w.-]+|ctag|dnstype)'),
            
            # DNS特定规则（AdGuard Home专用）
            'dns_type': re.compile(r'^\|\|([\w.-]+)\^\$dnstype=~?[\w,]+$'),
            'dnsrewrite': re.compile(r'^\|\|([\w.-]+)\^\$dnsrewrite=(?:NOERROR;)?(?:[A-Z]+;)?(?:.+)?$'),
            'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w*.-]+)$'),
            
            # 其他可转换规则
            'domain_only': re.compile(r'^([\w*.-]+)$'),  # 纯域名
            'comment': re.compile(r'^[!#]|^$'),  # 注释/空行
            
            # 新增支持的特殊语法
            'ubo_js': re.compile(r'^\+js\([^)]+\)'),  # uBO动态规则
            'adguard_script': re.compile(r'^\$\$[\w#.-]+'),  # AdGuard脚本规则
            'element_hiding': re.compile(r'^##[^#\s\[].*')  # 元素隐藏规则（跳过）
        }

        # 支持的DNS修饰符（三大拦截器共同支持）
        self.valid_dns_modifiers = {
            'dnstype', 'dnsrewrite', 'important', 'badfilter'
        }

    def process_file(self, input_path: Path, output_path: Path) -> int:
        """处理输入文件并生成DNS规则"""
        seen = OrderedDict()  # 保持插入顺序
        count = 0

        with input_path.open('r', encoding='utf-8', errors='replace') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            for line in infile:
                line = line.strip()
                if self._is_comment_or_whitelist(line):
                    continue

                # 跳过元素隐藏规则
                if self.patterns['element_hiding'].match(line):
                    continue

                # 处理特殊规则
                if self._is_special_rule(line):
                    continue

                # 提取基础域名
                domain = self._extract_domain(line)
                if not domain:
                    continue

                # 处理修饰符
                modifiers = self._extract_modifiers(line)
                dns_modifiers = self._filter_dns_modifiers(modifiers)

                # 生成标准化规则
                rule = self._build_rule(domain, dns_modifiers)
                if rule and rule not in seen:
                    seen[rule] = True
                    outfile.write(rule + '\n')
                    count += 1

        return count

    def _is_comment_or_whitelist(self, line: str) -> bool:
        """判断是否为注释或白名单规则"""
        return bool(self.patterns['comment'].match(line)) or line.startswith('@@')

    def _is_special_rule(self, line: str) -> bool:
        """判断是否为需要跳过的特殊规则"""
        return (self.patterns['ubo_js'].match(line) or 
                self.patterns['adguard_script'].match(line))

    def _extract_domain(self, line: str) -> Optional[str]:
        """从规则中提取基础域名（增强版）"""
        # 标准域名规则
        if match := self.patterns['domain'].match(line):
            return match.group(1).lower()
        
        # 拦截器特有规则
        for pattern in ['ubo', 'abp', 'adguard']:
            if match := self.patterns[pattern].match(line):
                return match.group(1).lower()
        
        # hosts格式
        if match := self.patterns['hosts'].match(line):
            return match.group(1).lower()
        
        # 纯域名
        if match := self.patterns['domain_only'].match(line):
            return match.group(1).lower()
        
        return None

    def _extract_modifiers(self, line: str) -> Set[str]:
        """提取规则中的修饰符"""
        if '$' not in line:
            return set()
        
        modifiers = line.split('$', 1)[1]
        return {m.split('=')[0] for m in modifiers.split(',')}

    def _filter_dns_modifiers(self, modifiers: Set[str]) -> Set[str]:
        """过滤出DNS相关的修饰符"""
        return {m for m in modifiers if m in self.valid_dns_modifiers}

    def _build_rule(self, domain: str, modifiers: Set[str]) -> str:
        """构建标准化DNS规则"""
        # 基础域名规则
        rule = f"||{domain}^"
        
        # 添加修饰符
        if modifiers:
            sorted_mods = sorted(modifiers)  # 保证输出一致性
            rule += '$' + ','.join(sorted_mods)
            
            # 为AdGuard Home添加默认DNS重写
            if 'dnsrewrite' not in modifiers:
                rule += ',dnsrewrite=NOERROR;;'
        
        return rule

if __name__ == "__main__":
    processor = DNSRuleProcessor()

    # 文件路径处理（适配Github CI）
    repo_root = Path(__file__).parent.parent.parent
    input_file = repo_root / "adblock.txt"
    output_file = repo_root / "dns.txt"

    if not input_file.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_file}")

    try:
        count = processor.process_file(input_file, output_file)
        print(f"转换完成: 共生成 {count} 条兼容DNS规则")
        print(f"输出文件: {output_file}")
    except Exception as e:
        print(f"::error::处理失败: {str(e)}")
        raise