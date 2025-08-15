import os
import re
from pathlib import Path
from collections import OrderedDict

def filter_adblock_rules(input_path, output_dns_path, output_allow_path):
    """
    Filter AdBlock rules and write DNS rules format for both block and allow lists,
    with full support for AdGuard Home syntax.
    
    Args:
        input_path (str/Path): Path to input AdBlock rules file
        output_dns_path (str/Path): Path to output DNS block rules file
        output_allow_path (str/Path): Path to output DNS allow rules file
    """
    input_path = Path(input_path)
    output_dns_path = Path(output_dns_path)
    output_allow_path = Path(output_allow_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Precompile regex patterns for better performance
    basic_block_pattern = re.compile(r'^\|\|([\w.-]+)\^(\$.*)?$')
    basic_allow_pattern = re.compile(r'^@@\|\|([\w.-]+)\^(\$.*)?$')
    hostfile_pattern = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w.-]+)$')
    dns_rule_pattern = re.compile(r'^\|\|([\w.-]+)\^\$dnstype=~?(?:[\w,]+)$')
    regex_rule_pattern = re.compile(r'^/(.+)/$')
    comment_pattern = re.compile(r'^[!#]|^$')

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_dns_path.open('w', encoding='utf-8') as dns_file, \
             output_allow_path.open('w', encoding='utf-8') as allow_file:

            block_count = 0
            allow_count = 0
            seen_domains = OrderedDict()

            for line in infile:
                line = line.strip()
                
                # Skip comments and empty lines
                if comment_pattern.match(line):
                    continue

                # Process basic blocking rules (||domain^)
                if match := basic_block_pattern.match(line):
                    domain = match.group(1)
                    if domain not in seen_domains:
                        dns_file.write(f"||{domain}^\n")
                        seen_domains[domain] = True
                        block_count += 1
                
                # Process basic allow rules (@@||domain^)
                elif match := basic_allow_pattern.match(line):
                    domain = match.group(1)
                    if domain not in seen_domains:
                        allow_file.write(f"||{domain}^\n")
                        seen_domains[domain] = True
                        allow_count += 1
                
                # Process hostfile format rules (0.0.0.0 domain)
                elif match := hostfile_pattern.match(line):
                    domain = match.group(1)
                    if domain not in seen_domains:
                        dns_file.write(f"||{domain}^\n")
                        seen_domains[domain] = True
                        block_count += 1
                
                # Process DNS-specific rules (||domain^$dnstype=...)
                elif match := dns_rule_pattern.match(line):
                    domain = match.group(1)
                    if domain not in seen_domains:
                        dns_file.write(f"||{domain}^\n")
                        seen_domains[domain] = True
                        block_count += 1
                
                # Process regex rules (/regex/)
                elif regex_rule_pattern.match(line):
                    # AdGuard Home supports regex rules directly
                    if line not in seen_domains:
                        dns_file.write(f"{line}\n")
                        seen_domains[line] = True
                        block_count += 1

            print(f"Processed {block_count} DNS block rules")
            print(f"Processed {allow_count} DNS allow rules")

    except IOError as e:
        print(f"Error processing files: {e}")
        raise

if __name__ == "__main__":
    # Get repository root directory (assuming script is in scripts/ directory)
    repo_root = Path(__file__).parent.parent.parent

    input_file = repo_root / "adblock.txt"
    output_dns_file = repo_root / "dns.txt"
    output_allow_file = repo_root / "dnsallow.txt"

    # Ensure output directory exists
    output_dns_file.parent.mkdir(parents=True, exist_ok=True)

    filter_adblock_rules(input_file, output_dns_file, output_allow_file)