import os
from pathlib import Path

def filter_adblock_rules(input_path, output_dns_path, output_allow_path):
    """
    Filter AdBlock rules and write DNS rules format for both block and allow lists.
    
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

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_dns_path.open('w', encoding='utf-8') as dns_file, \
             output_allow_path.open('w', encoding='utf-8') as allow_file:

            block_count = 0
            allow_count = 0
            
            for line in infile:
                line = line.strip()
                
                # Process blocking rules (||domain^)
                if line.startswith("||") and line.endswith("^"):
                    dns_file.write(line + '\n')
                    block_count += 1
                # Process allow rules (@@||domain^)
                elif line.startswith("@@||") and line.endswith("^"):
                    domain = line[4:-1]  # Remove @@ and ^
                    allow_file.write(f"||{domain}^\n")  # Convert to blocking format
                    allow_count += 1

            print(f"Processed {block_count} DNS block rules")
            print(f"Processed {allow_count} DNS allow rules")

    except IOError as e:
        print(f"Error processing files: {e}")

if __name__ == "__main__":
    # Get repository root directory (assuming script is in scripts/ directory)
    repo_root = Path(__file__).parent.parent.parent
    
    input_file = repo_root / "adblock.txt"
    output_dns_file = repo_root / "dns.txt"
    output_allow_file = repo_root / "dnsallow.txt"

    # Ensure output directory exists
    output_dns_file.parent.mkdir(parents=True, exist_ok=True)

    filter_adblock_rules(input_file, output_dns_file, output_allow_file)