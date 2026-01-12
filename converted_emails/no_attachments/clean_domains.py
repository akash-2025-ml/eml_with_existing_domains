#!/usr/bin/env python3

import re

def is_valid_domain(domain):
    """Check if a string looks like a valid domain."""
    if not domain or len(domain) < 2:
        return False
    
    # Remove common HTML artifacts and trailing punctuation
    domain = domain.strip('=",;><')
    
    # Basic domain pattern: letters, numbers, dots, hyphens
    # Must contain at least one dot (unless it's a single word like localhost)
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
    
    if not re.match(pattern, domain):
        return False
    
    # Must not end with dot, hyphen, or be just punctuation
    if domain.endswith('.') or domain.endswith('-') or domain.startswith('-'):
        return False
    
    # Skip obviously invalid entries
    if domain in ['=', 'co=', 'am=', 'america=']:
        return False
        
    return True

def clean_domain(domain):
    """Clean up a domain string."""
    # Remove HTML artifacts and quotes
    cleaned = domain.strip('=",;><').strip()
    return cleaned if cleaned else None

# Read existing domains
with open('unique_domains.txt', 'r') as f:
    domains = [line.strip() for line in f if line.strip()]

print(f"Original domains: {len(domains)}")

# Clean and validate
valid_domains = set()
invalid_count = 0

for domain in domains:
    cleaned = clean_domain(domain)
    if cleaned and is_valid_domain(cleaned):
        valid_domains.add(cleaned.lower())
    else:
        print(f"Invalid: '{domain}' -> '{cleaned}'")
        invalid_count += 1

print(f"Valid domains: {len(valid_domains)}")
print(f"Invalid/removed: {invalid_count}")

# Save cleaned domains
with open('unique_domains_cleaned.txt', 'w') as f:
    for domain in sorted(valid_domains):
        f.write(f"{domain}\n")

print("Cleaned domains saved to unique_domains_cleaned.txt")