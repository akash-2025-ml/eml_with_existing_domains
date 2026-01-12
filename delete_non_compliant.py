#!/usr/bin/env python3
"""
Delete non-RFC 5322 compliant emails from corrected folder
"""

import os
from pathlib import Path
import json
from datetime import datetime
from rfc5322_validator import RFC5322Validator

def main():
    validator = RFC5322Validator()
    corrected_dir = Path("rfc5322_corrected_emails")
    
    # Get all corrected .eml files
    corrected_files = list(corrected_dir.glob("*.eml"))
    total_files = len(corrected_files)
    
    compliant_count = 0
    non_compliant_files = []
    deletion_report = {
        'deletion_date': datetime.now().isoformat(),
        'total_files_checked': total_files,
        'files_deleted': [],
        'files_kept': 0
    }
    
    print(f"Validating all {total_files} files in corrected folder...")
    print("This will DELETE any files that are still non-compliant.\n")
    
    # Validate each file
    for i, file_path in enumerate(corrected_files):
        print(f"Checking {i+1}/{total_files}: {file_path.name}", end="")
        
        is_compliant, report = validator.validate_eml_file(str(file_path))
        
        if is_compliant:
            compliant_count += 1
            print(" ✓ COMPLIANT")
        else:
            print(f" ✗ NON-COMPLIANT - {len(report['violations'])} violations")
            non_compliant_files.append({
                'file': file_path.name,
                'path': str(file_path),
                'violations': report['violations']
            })
            deletion_report['files_deleted'].append({
                'filename': file_path.name,
                'violations': report['violations']
            })
    
    deletion_report['files_kept'] = compliant_count
    
    # Delete non-compliant files
    if non_compliant_files:
        print(f"\n{'='*60}")
        print(f"Found {len(non_compliant_files)} non-compliant files.")
        print("Deleting non-compliant files...\n")
        
        for file_info in non_compliant_files:
            file_path = Path(file_info['path'])
            print(f"Deleting: {file_info['file']}")
            print(f"  Violations: {', '.join(file_info['violations'][:2])}")
            if len(file_info['violations']) > 2:
                print(f"  ... and {len(file_info['violations']) - 2} more")
            
            # Delete the file
            file_path.unlink()
            print("  ✗ DELETED")
    
    # Save deletion report
    with open('deletion_report.json', 'w') as f:
        json.dump(deletion_report, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"Deletion Complete!")
    print(f"{'='*60}")
    print(f"Total files checked: {total_files}")
    print(f"Compliant files kept: {compliant_count}")
    print(f"Non-compliant files deleted: {len(non_compliant_files)}")
    print(f"Success rate: {(compliant_count/total_files)*100:.1f}%")
    print(f"\nDeletion report saved to: deletion_report.json")

if __name__ == "__main__":
    main()