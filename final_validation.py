#!/usr/bin/env python3
"""
Final RFC 5322 validation for all remaining files
This is the brutal honest check - no files should fail
"""

import os
from pathlib import Path
import json
from datetime import datetime
from rfc5322_validator import RFC5322Validator

def main():
    validator = RFC5322Validator()
    corrected_dir = Path("rfc5322_corrected_emails")
    
    # Get all remaining .eml files
    remaining_files = list(corrected_dir.glob("*.eml"))
    total_files = len(remaining_files)
    
    print(f"FINAL RFC 5322 VALIDATION")
    print(f"{'='*60}")
    print(f"Validating {total_files} files in corrected folder...")
    print(f"This is the FINAL check - ALL files should be compliant.\n")
    
    compliant_count = 0
    non_compliant_files = []
    all_violations = []
    
    final_report = {
        'validation_date': datetime.now().isoformat(),
        'total_files': total_files,
        'compliant_files': 0,
        'non_compliant_files': 0,
        'files_with_violations': []
    }
    
    # Validate each file
    for i, file_path in enumerate(remaining_files):
        print(f"Validating {i+1}/{total_files}: {file_path.name}", end="")
        
        is_compliant, report = validator.validate_eml_file(str(file_path))
        
        if is_compliant:
            compliant_count += 1
            print(" ✓ COMPLIANT")
        else:
            print(f" ✗ FAILED - {len(report['violations'])} violations")
            non_compliant_files.append(file_path.name)
            all_violations.extend(report['violations'])
            
            final_report['files_with_violations'].append({
                'filename': file_path.name,
                'violations': report['violations']
            })
            
            # Show violations
            for violation in report['violations']:
                print(f"    - {violation}")
    
    final_report['compliant_files'] = compliant_count
    final_report['non_compliant_files'] = len(non_compliant_files)
    
    # Save final report
    with open('final_validation_report.json', 'w') as f:
        json.dump(final_report, f, indent=2)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"FINAL VALIDATION RESULTS")
    print(f"{'='*60}")
    print(f"Total files checked: {total_files}")
    print(f"RFC 5322 Compliant: {compliant_count}")
    print(f"Non-compliant: {len(non_compliant_files)}")
    print(f"Success rate: {(compliant_count/total_files)*100:.1f}%")
    
    if non_compliant_files:
        print(f"\n⚠️  UNEXPECTED RESULT: Found {len(non_compliant_files)} non-compliant files!")
        print("These files somehow still have RFC 5322 violations:")
        for fname in non_compliant_files[:10]:
            print(f"  - {fname}")
        if len(non_compliant_files) > 10:
            print(f"  ... and {len(non_compliant_files) - 10} more")
        
        # Analyze violation types
        violation_types = {}
        for v in all_violations:
            vtype = v.split(':')[0] if ':' in v else v
            violation_types[vtype] = violation_types.get(vtype, 0) + 1
        
        print(f"\nViolation types found:")
        for vtype, count in sorted(violation_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {vtype}: {count} occurrences")
    else:
        print(f"\n✅ PERFECT! All {total_files} files are fully RFC 5322 compliant!")
    
    print(f"\nDetailed report saved to: final_validation_report.json")
    
    return compliant_count == total_files

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)