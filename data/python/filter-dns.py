#!/usr/bin/env python3
import re
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import mmap

class AdGuardHomeRuleValidator:
    """AdGuard Home DNS规则验证器"""

    @staticmethod
    def _compile_patterns() -> Dict[str, re.Pattern]:
        return {
            'domain': re.compile(r'^(\|\|)?([\w.*-]+|xn--[\w-]+)\^(?:\$[\w,=-]+)?$'),
            'modifiers': re.compile(
                r'^\|\|[\w.-]+\^\$('
                r'dnsrewrite=[^;]+(?:;[^;]+)*|'
                r'ctag=[\w,]+|'
                r'client(?:=~?[\w.-]+)?|'
                r'dnstype=[\w,]+|'
                r'denyallow=[\w.|-]+|'
                r'badfilter|'
                r'important'
                r')(?:,~?[\w.=-]+)*$'
            ),
            'hosts': re.compile(
                r'^((?:\d{1,3}\.){3}\d{1,3}|[\da-fA-F:]+(?:/\d{1,3})?)\s+'
                r'([\w.-]+|xn--[\w-]+)(?:\s*#.*)?$'
            ),
            'regex': re.compile(r'^/.*/[ims]*(?:\$[\w,=-]+)?$'),
            'allow': re.compile(
                r'^@@\|\|([\w.*-]+|xn--[\w-]+)\^(?:\$[\w,=-]+)?|'
                r'^@@\d+\.\d+\.\d+\.\d+(?:/\d+)?|'
                r'^@@/.*/[ims]*(?:\$[\w,=-]+)?'
            )
        }

    def __init__(self):
        self.patterns = self._compile_patterns()

    def validate(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line or line[0] in ('!', '#', '['):
            return None

        if line.startswith('@@'):
            if self.patterns['allow'].match(line):
                return line
            return None

        if self.patterns['modifiers'].match(line):
            return line

        if match := self.patterns['domain'].match(line):
            domain = match.group(2).lower()
            if domain.startswith('*.'):
                domain = domain[2:]
            return f"||{domain}^" + (match.group(3) or '')

        if match := self.patterns['hosts'].match(line):
            ip, host = match.groups()
            return f"{ip}\t{host.lower()}"

        if self.patterns['regex'].match(line):
            return line

        return None

def process_rules_concurrently(lines: List[str], validator: AdGuardHomeRuleValidator) -> Tuple[List[str], List[str]]:
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(validator.validate, lines))

    return (
        [rule for rule in filter(None, results) if not rule.startswith('@@')],
        [rule for rule in filter(None, results) if rule.startswith('@@')]
    )

def analyze_rules(rules: List[str]) -> Dict:
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

    for domain, rules in domain_map.items():
        if len(rules) > 1:
            blocking = [r for r in rules if not r.startswith('@@')]
            allowing = [r for r in rules if r.startswith('@@')]
            if blocking and allowing:
                stats['conflicts'].append({
                    'domain': domain,
                    'count': len(rules),
                    'suggestion': allowing[-1]
                })
    return stats

def write_output_files(output_dir: Path, rules: List[str], allow_rules: List[str]) -> None:
    def sort_key(r: str) -> tuple:
        if r.startswith('||'): return (0, len(r), r)
        if re.match(r'^[\d:]', r): return (1, len(r), r)
        return (2, len(r), r)

    for filename, content in [
        ("dns.txt", sorted(rules, key=sort_key)),
        ("dnsallow.txt", sorted(allow_rules, key=sort_key))
    ]:
        with (output_dir / filename).open('w', encoding='utf-8') as f:
            f.write(f"! Title: AdGuard Home {'DNS Rules' if filename == 'dns.txt' else 'Allowlist'}\n")
            f.write(f"! Updated: {datetime.now().isoformat()}\n")
            if filename == "dnsallow.txt":
                f.write("! Contains exception rules only\n\n")
            f.write("\n".join(content))

def main():
    try:
        # 使用repo变量设置路径
        repo_path = os.getenv('REPO_PATH', os.getcwd())
        repo = Path(repo_path).resolve()
        
        input_file = repo / "adblock.txt"
        output_dir = repo

        print(f"🏠 Repository root: {repo}")
        print(f"📂 Input file: {input_file}")
        print(f"📂 Output directory: {output_dir}")

        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found at: {input_file}")

        with input_file.open('rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                lines = mm.read().decode('utf-8', errors='replace').splitlines()

        valid_rules, allow_rules = process_rules_concurrently(
            lines, AdGuardHomeRuleValidator()
        )

        stats = analyze_rules(valid_rules + allow_rules)
        print("\n📊 Statistics:")
        print(f"• Total rules: {len(lines)}")
        print(f"• Valid rules: {len(valid_rules)}")
        print(f"• Allow rules: {len(allow_rules)}")
        print(f"• Domain rules: {stats['domains']}")
        print(f"• Hosts rules: {stats['hosts']}")
        print(f"• Regex rules: {stats['regex']}")

        write_output_files(output_dir, valid_rules, allow_rules)
        print(f"\n✅ Output files created in: {output_dir}")

    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__} - {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    from datetime import datetime
    main()