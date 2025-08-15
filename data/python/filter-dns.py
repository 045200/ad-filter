#!/usr/bin/env python3
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any


class AdGuardHomeRuleValidator:
    """Enhanced AdGuard Home DNS rule validator"""

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
                r'important|'
                r'document|'
                r'redirect(?:=[\w.:/-]+)?|'
                r'removeparam(?:=[^,]+)?|'
                r'replace=/.*/[ims]*'
                r')(?:,~?[\w.=-]+)*$'
            ),
            'hosts': re.compile(
                r'^((?:\d{1,3}\.){3}\d{1,3}|[\da-fA-F:]+(?:/\d{1,3})?)\s+'
                r'([\w.-]+|xn--[\w-]+)(?:\s*#.*)?$'
            ),
            'regex': re.compile(r'^/(?:\\/|[^/])+/[ims]*(?:\$[\w,=-]+)?$'),
            'allow': re.compile(
                r'^@@\|\|([\w.*-]+|xn--[\w-]+)\^(?:\$[\w,=-]+)|'
                r'^@@\d+\.\d+\.\d+\.\d+(?:/\d+)?|'
                r'^@@/.*/[ims]*(?:\$[\w,=-]+)?'
            ),
            'dnsrewrite': re.compile(
                r'^\|\|[\w.-]+\^\$dnsrewrite='
                r'(?:NOERROR|NXDOMAIN|SERVFAIL|REFUSED);'
                r'(?:A|AAAA|CNAME|TXT|MX|NS|SVBC|HTTPS)'
                r'(?:;[^;]+)*$'
            )
        }

    def __init__(self):
        self.patterns = self._compile_patterns()

    def validate(self, line: str) -> Optional[str]:
        """Validate and normalize a single rule line"""
        line = re.sub(r'[ \t]#.*$', '', line.strip())
        if not line or line[0] in ('!', '#', '['):
            return None

        if line.startswith('@@'):
            if self.patterns['allow'].match(line):
                return line
            return None

        if self.patterns['dnsrewrite'].match(line):
            return line

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
    """Process rules in parallel using ThreadPoolExecutor"""
    with ThreadPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as executor:
        results = list(executor.map(validator.validate, lines))

    valid_rules = [rule for rule in results if rule is not None and not rule.startswith('@@')]
    allow_rules = [rule for rule in results if rule is not None and rule.startswith('@@')]
    return valid_rules, allow_rules


def analyze_rules(rules: List[str]) -> Dict[str, Any]:
    """Analyze rule statistics and find conflicts"""
    stats: Dict[str, Any] = {
        'total': len(rules),
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
                    'blocking': len(blocking),
                    'allowing': len(allowing),
                    'suggestion': allowing[-1] if allowing else None
                })
    return stats


def write_output_files(output_dir: Path, rules: List[str], allow_rules: List[str]) -> None:
    """Write output files with sorted rules"""
    def sort_key(r: str) -> tuple:
        if r.startswith('||'):
            return (0, len(r), r)
        if re.match(r'^[\d:]', r):
            return (1, len(r), r)
        return (2, len(r), r)

    for filename, content in [
        ("dns.txt", sorted(rules, key=sort_key)),
        ("dnsallow.txt", sorted(allow_rules, key=sort_key))
    ]:
        try:
            with (output_dir / filename).open('w', encoding='utf-8') as f:
                f.write("\n".join(content))
                f.write("\n")  # Ensure file ends with newline
        except IOError as e:
            print(f"⚠️ Failed to write {filename}: {e}", file=sys.stderr)


def main() -> None:
    """Main function to process rules"""
    try:
        # Get script directory and repository root
        script_dir = Path(__file__).parent
        repo_root = script_dir.parent.parent

        # Set input/output paths
        input_file = repo_root / "adblock.txt"
        output_dir = repo_root

        print(f"🏠 Repository root: {repo_root}")
        print(f"📂 Input file: {input_file}")
        print(f"📂 Output directory: {output_dir}")

        # Check input file
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found at: {input_file}")

        # Initialize empty rules
        valid_rules: List[str] = []
        allow_rules: List[str] = []

        # Process file if not empty
        if input_file.stat().st_size > 0:
            try:
                with input_file.open('r', encoding='utf-8', errors='replace') as f:
                    lines = [line.strip() for line in f if line.strip()]
                
                validator = AdGuardHomeRuleValidator()
                valid_rules, allow_rules = process_rules_concurrently(lines, validator)
            except UnicodeDecodeError:
                print("⚠️ File encoding issue, trying with fallback encoding", file=sys.stderr)
                with input_file.open('r', encoding='latin-1', errors='replace') as f:
                    lines = [line.strip() for line in f if line.strip()]
                validator = AdGuardHomeRuleValidator()
                valid_rules, allow_rules = process_rules_concurrently(lines, validator)

        # Analyze and output results
        stats = analyze_rules(valid_rules + allow_rules)
        print("\n📊 Statistics:")
        print(f"• Total rules processed: {stats['total']}")
        print(f"• Valid blocking rules: {len(valid_rules)}")
        print(f"• Allow rules: {len(allow_rules)}")
        print(f"• Domain rules: {stats['domains']}")
        print(f"• Hosts rules: {stats['hosts']}")
        print(f"• Regex rules: {stats['regex']}")
        print(f"• Rules with modifiers: {stats['modified']}")
        if stats['conflicts']:
            print("\n⚠️ Found rule conflicts:")
            for conflict in stats['conflicts']:
                print(f"  - {conflict['domain']}: {conflict['blocking']} blocking vs {conflict['allowing']} allowing")

        # Write output files
        write_output_files(output_dir, valid_rules, allow_rules)
        print(f"\n✅ Successfully created output files in: {output_dir}")

    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__} - {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()