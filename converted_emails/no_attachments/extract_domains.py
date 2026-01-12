#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path

def extract_domains_from_json_files():
    """Extract all unique domains from JSON files in current directory."""
    current_dir = Path.cwd()
    all_domains = set()
    processed_files = 0
    error_files = 0
    
    print(f"Scanning directory: {current_dir}")
    
    # Find all JSON files in current directory
    json_files = list(current_dir.glob("*.json"))
    print(f"Found {len(json_files)} JSON files")
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract domains from the payload.domains field
            if 'email_data' in data and 'payload' in data['email_data'] and 'domains' in data['email_data']['payload']:
                domains = data['email_data']['payload']['domains']
                if domains:
                    for domain in domains:
                        if domain:  # Skip empty domains
                            all_domains.add(domain.strip().lower())
                            
            processed_files += 1
            
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            error_files += 1
            continue
    
    print(f"\nProcessing complete:")
    print(f"- Files processed: {processed_files}")
    print(f"- Files with errors: {error_files}")
    print(f"- Unique domains found: {len(all_domains)}")
    
    return sorted(all_domains)

def save_domains_to_file(domains, filename="unique_domains.txt"):
    """Save domains to a text file."""
    filepath = Path.cwd() / filename
    
    with open(filepath, 'w', encoding='utf-8') as f:
        for domain in domains:
            f.write(f"{domain}\n")
    
    print(f"\nDomains saved to: {filepath}")
    return filepath

def main():
    print("Domain Extraction Tool")
    print("=" * 50)
    
    # Extract domains
    domains = extract_domains_from_json_files()
    
    if not domains:
        print("No domains found!")
        sys.exit(1)
    
    # Save to file
    output_file = save_domains_to_file(domains)
    
    # Print sample of domains
    print(f"\nFirst 10 domains:")
    for i, domain in enumerate(domains[:10]):
        print(f"  {i+1}. {domain}")
    
    if len(domains) > 10:
        print(f"  ... and {len(domains) - 10} more")
    
    print(f"\nAll {len(domains)} unique domains have been saved to {output_file.name}")

if __name__ == "__main__":
    main()