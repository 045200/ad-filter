#!/usr/bin/env python3
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, OrderedDict
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import mmap

class AdGuardHomeRuleValidator:
    """AdGuard Home DNS规则验证器（支持v0.108+全语法）"""
    
    @staticmethod
    def _compile_patterns() -> Dict[str, re.Pattern]:
        """预编译所有正则模式（提升性能）"""
        return {
            # 基础域名规则（含IDN支持）
            'domain': re.compile(r'^(\|\|)?([\w.*-]+|xn--[\w-]+)\^(?:\$[\w,=-]+)?$'),
            
            # 完整修饰符语法（官方文档2024版）
            'modifiers': re.compile(
                r'^\|\|[\w.-]+\^\$('
                r'dnsrewrite=[^;]+(?:;[^;]+)*|'  # DNS重写
                r'ctag=[\w,]+|'                  # 设备标签
                r'client(?:=~?[\w.-]+)?|'        # 客户端
                r'dnstype=[\w,]+|'               # DNS类型
                r'denyallow=[\w.|-]+|'           # 例外允许
                r'badfilter|'                    # 规则排除
                r'important'                     # 强制规则
                r')(?:,~?[\w.=-]+)*$'
            ),
            
            # Hosts格式（支持IPv4/IPv6/CIDR）
            'hosts': re.compile(
                r'^((?:\d{1,3}\.){3}\d{1,3}|[\da-fA-F:]+(?:/\d{1,3})?)\s+'
                r'([\w.-]+|xn--[\w-]+)(?:\s*#.*)?$'
            ),
            
            # 正则表达式规则
            'regex': re.compile(r'^/.*/[ims]*(?:\$[\w,=-]+)?$'),
            
            # 白名单规则（增强版）
            'allow': re.compile(
                r'^@@\|\|([\w.*-]+|xn--[\w-]+)\^(?:\$[\w,=-]+)?|'
                r'^@@\d+\.\d+\.\d+\.\d+(?:/\d+)?|'
                r'^@@/.*/[ims]*(?:\$[\w,=-]+)?'
            )
        }

    def __init__(self):
        self.patterns = self._compile_patterns()
        
    def validate(self, line: str) -> Optional[str]:
        """验证单条规则并返回标准化格式"""
        line = line.strip()
        if not line or line[0] in ('!', '#', '['):
            return None
            
        # 白名单优先检测
        if line.startswith('@@'):
            if self.patterns['allow'].match(line):
                return line
            return None
            
        # 修饰符规则检测
        if self.patterns['modifiers'].match(line):
            return line
            
        # 基础域名规则
        if match := self.patterns['domain'].match(line):
            # 标准化通配符位置
            domain = match.group(2).lower()
            if domain.startswith('*.'):
                domain = domain[2:]
            return f"||{domain}^" + (match.group(3) or '')
            
        # Hosts规则处理
        if match := self.patterns['hosts'].match(line):
            ip, host = match.groups()
            return f"{ip}\t{host.lower()}"
            
        # 正则表达式规则
        if self.patterns['regex'].match(line):
            return line
            
        return None

def process_rules_concurrently(lines: List[str], validator: AdGuardHomeRuleValidator) -> Tuple[List[str], List[str]]:
    """并发处理规则（返回有效规则和白名单）"""
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(validator.validate, lines))
    
    valid_rules = []
    allow_rules = []
    
    for rule in filter(None, results):
        if rule.startswith('@@'):
            allow_rules.append(rule)
        else:
            valid_rules.append(rule)
    
    return valid_rules, allow_rules

def analyze_rules(rules: List[str]) -> Dict:
    """深度规则分析（含冲突检测）"""
    stats = {
        'domains': 0,
        'hosts': 0,
        'regex': 0,
        'modified': 0,
        'conflicts': []
    }
    
    domain_map = defaultdict(list)
    
    for rule in rules:
        if rule.startswith('||'):
            stats['domains'] += 1
            domain = rule.split('^')[0][2:]
            domain_map[domain].append(rule)
        elif re.match(r'^[\d:]', rule):
            stats['hosts'] += 1
        elif rule.startswith('/'):
            stats['regex'] += 1
        elif '$' in rule:
            stats['modified'] += 1
            
    # 冲突检测（域名级）
    for domain, rules in domain_map.items():
        if len(rules) > 1:
            blocking = [r for r in rules if not r.startswith('@@')]
            allowing = [r for r in rules if r.startswith('@@')]
            
            if blocking and allowing:
                suggested = allowing[-1]  # 保留最后一条白名单
                stats['conflicts'].append({
                    'domain': domain,
                    'count': len(rules),
                    'suggestion': suggested
                })
    
    return stats

def write_output_files(output_dir: Path, rules: List[str], allow_rules: List[str]) -> None:
    """原子化写入输出文件"""
    # 智能排序（域名规则优先）
    def sort_key(r: str) -> tuple:
        if r.startswith('||'): return (0, len(r), r)
        if re.match(r'^[\d:]', r): return (1, len(r), r)
        return (2, len(r), r
    
    sorted_rules = sorted(rules, key=sort_key)
    sorted_allow = sorted(allow_rules, key=sort_key)
    
    # 写入主规则文件
    dns_file = output_dir / "dns.txt"
    with dns_file.open('w', encoding='utf-8') as f:
        f.write("! Title: AdGuard Home DNS Rules\n")
        f.write("! Updated: " + datetime.now().isoformat() + "\n")
        f.write("\n".join(sorted_rules))
    
    # 写入白名单文件
    allow_file = output_dir / "dnsallow.txt"
    with allow_file.open('w', encoding='utf-8') as f:
        f.write("! Title: AdGuard Home Allowlist\n")
        f.write("! Contains exception rules only\n\n")
        f.write("\n".join(sorted_allow))

def main():
    try:
        repo_root = Path(__file__).resolve().parent
        input_file = repo_root / "adblock.txt"
        output_dir = repo_root / "output"
        
        output_dir.mkdir(exist_ok=True)
        
        print(f"🔍 Processing: {input_file}")
        
        # 内存映射读取大文件
        with input_file.open('rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                content = mm.read().decode('utf-8', errors='replace')
        
        lines = content.splitlines()
        validator = AdGuardHomeRuleValidator()
        
        print("⚙️ Validating rules...")
        valid_rules, allow_rules = process_rules_concurrently(lines, validator)
        
        print("📊 Analyzing rules...")
        stats = analyze_rules(valid_rules + allow_rules)
        
        print("\n📝 Statistics:")
        print(f"- Total input: {len(lines)}")
        print(f"- Valid rules: {len(valid_rules)} (domains: {stats['domains']})")
        print(f"- Allow rules: {len(allow_rules)}")
        print(f"- Hosts rules: {stats['hosts']}")
        print(f"- Regex rules: {stats['regex']}")
        print(f"- Modified rules: {stats['modified']}")
        
        if stats['conflicts']:
            print("\n⚠️ Found conflicts:")
            for conflict in stats['conflicts'][:5]:  # 显示前5个冲突
                print(f"  {conflict['domain']} ({conflict['count']} rules)")
                print(f"  Suggested: {conflict['suggestion']}")
        
        print("\n💾 Writing output files...")
        write_output_files(output_dir, valid_rules, allow_rules)
        
        print(f"\n✅ Successfully generated:")
        print(f"- {output_dir/'dns.txt'} ({len(valid_rules)} rules)")
        print(f"- {output_dir/'dnsallow.txt'} ({len(allow_rules)} rules)")
        
    except Exception as e:
        print(f"❌ Error: {type(e).__name__} - {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    from datetime import datetime
    main()