#!/usr/bin/env python3
"""Validate a sample of corrected emails"""

from pathlib import Path
from rfc5322_validator import RFC5322Validator
import random

validator = RFC5322Validator()
corrected_dir = Path("rfc5322_corrected_emails")

# Get all corrected files
corrected_files = list(corrected_dir.glob("*.eml"))

# Sample 20 random files
sample_files = random.sample(corrected_files, min(20, len(corrected_files)))

compliant_count = 0
non_compliant_count = 0

print("Validating sample of corrected emails...")
print("="*60)

for i, file_path in enumerate(sample_files):
    print(f"\nChecking {i+1}/20: {file_path.name}")
    is_compliant, report = validator.validate_eml_file(str(file_path))
    
    if is_compliant:
        compliant_count += 1
        print("  ✓ COMPLIANT")
    else:
        non_compliant_count += 1
        print(f"  ✗ NON-COMPLIANT - {len(report['violations'])} violations:")
        for violation in report['violations'][:3]:
            print(f"    - {violation}")

print(f"\n{'='*60}")
print(f"Sample validation results:")
print(f"  Compliant: {compliant_count}/20")
print(f"  Non-compliant: {non_compliant_count}/20")
print(f"  Success rate: {compliant_count/20*100:.1f}%")