#!/usr/bin/env python3
"""
RFC 5322 Email Validator
Performs comprehensive validation of email messages against RFC 5322 standard
"""

import os
import re
import email
import email.utils
from email import policy
from datetime import datetime
from pathlib import Path
import shutil
import json
import traceback
from typing import List, Dict, Tuple, Optional

class RFC5322Validator:
    def __init__(self):
        # RFC 5322 compliant patterns
        self.ATEXT = r'[a-zA-Z0-9!#$%&\'*+\-/=?^_`{|}~]'
        self.ATOM = f'{self.ATEXT}+'
        self.DOT_ATOM_TEXT = f'{self.ATOM}(\\.{self.ATOM})*'
        self.QUOTED_STRING = r'"([^"\\]|\\.)*"'
        self.LOCAL_PART = f'({self.DOT_ATOM_TEXT}|{self.QUOTED_STRING})'
        self.DOMAIN = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        self.ADDR_SPEC = f'^{self.LOCAL_PART}@{self.DOMAIN}$'
        
        # Header field patterns
        self.HEADER_FIELD = re.compile(r'^([!-9;-~]+):(.*)$', re.MULTILINE)
        self.FOLDED_LINE = re.compile(r'\r?\n[ \t]+')
        
        # Required headers
        self.REQUIRED_HEADERS = {'from', 'date'}
        
        # Date format patterns (RFC 5322 section 3.3)
        self.DATE_PATTERNS = [
            # Day, DD Mon YYYY HH:MM:SS +ZZZZ
            r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$',
            # DD Mon YYYY HH:MM:SS +ZZZZ (without day)
            r'^\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$',
            # With timezone names
            r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT)$',
        ]
        
        self.violations = []
        self.warnings = []

    def validate_email_address(self, addr_string: str) -> Tuple[bool, List[str]]:
        """Validate email address according to RFC 5322"""
        issues = []
        
        # Parse the address
        try:
            parsed = email.utils.parseaddr(addr_string)
            email_addr = parsed[1]
            
            if not email_addr:
                issues.append(f"Could not parse email address from: {addr_string}")
                return False, issues
            
            # Check against regex pattern
            if not re.match(self.ADDR_SPEC, email_addr, re.IGNORECASE):
                issues.append(f"Invalid email address format: {email_addr}")
                return False, issues
                
            # Check local part length (max 64 octets)
            local_part = email_addr.split('@')[0]
            if len(local_part) > 64:
                issues.append(f"Local part too long ({len(local_part)} > 64): {local_part}")
                
            # Check domain part length (max 255 octets)
            domain_part = email_addr.split('@')[1]
            if len(domain_part) > 255:
                issues.append(f"Domain part too long ({len(domain_part)} > 255): {domain_part}")
                
            # Check for consecutive dots
            if '..' in email_addr:
                issues.append(f"Consecutive dots not allowed: {email_addr}")
                
            return len(issues) == 0, issues
            
        except Exception as e:
            issues.append(f"Error parsing email address '{addr_string}': {str(e)}")
            return False, issues

    def validate_date_header(self, date_string: str) -> Tuple[bool, List[str]]:
        """Validate date header according to RFC 5322 section 3.3"""
        issues = []
        
        # Remove folding whitespace
        date_string = re.sub(r'\s+', ' ', date_string.strip())
        
        # Check against RFC 5322 date patterns
        valid = False
        for pattern in self.DATE_PATTERNS:
            if re.match(pattern, date_string):
                valid = True
                break
        
        if not valid:
            # Try parsing with email.utils as fallback
            try:
                parsed_date = email.utils.parsedate_to_datetime(date_string)
                if parsed_date:
                    # Date is parseable but not strictly RFC 5322 format
                    issues.append(f"Date format not strictly RFC 5322 compliant: {date_string}")
                else:
                    issues.append(f"Invalid date format: {date_string}")
            except Exception:
                issues.append(f"Invalid date format: {date_string}")
        
        return len(issues) == 0, issues

    def validate_line_length(self, content: str) -> List[str]:
        """Check line length constraints (RFC 5322 section 2.1.1)"""
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Remove CR if present
            line = line.rstrip('\r')
            
            # Maximum line length is 998 characters (excluding CRLF)
            if len(line) > 998:
                issues.append(f"Line {i+1} exceeds 998 characters ({len(line)} chars)")
            
            # Recommended line length is 78 characters
            elif len(line) > 78:
                self.warnings.append(f"Line {i+1} exceeds recommended 78 characters ({len(line)} chars)")
        
        return issues

    def validate_header_syntax(self, header_name: str, header_value: str) -> List[str]:
        """Validate header field syntax"""
        issues = []
        
        # Header name should only contain visible ASCII characters (33-126) except colon
        if not re.match(r'^[!-9;-~]+$', header_name):
            issues.append(f"Invalid header name characters: {header_name}")
        
        # Check for improper folding
        if '\r' in header_value or '\n' in header_value:
            # Should be properly folded with CRLF + space/tab
            if not re.match(r'^([^\r\n]|\r\n[ \t])*$', header_value):
                issues.append(f"Improper header folding in {header_name}")
        
        return issues

    def validate_message_structure(self, msg: email.message.EmailMessage) -> List[str]:
        """Validate overall message structure"""
        issues = []
        
        # Check for required headers
        headers_lower = {h.lower() for h in msg.keys()}
        for req_header in self.REQUIRED_HEADERS:
            if req_header not in headers_lower:
                issues.append(f"Missing required header: {req_header.upper()}")
        
        # Check for duplicate headers that should be unique
        unique_headers = {'from', 'date', 'message-id', 'in-reply-to', 'references', 'subject'}
        for header in unique_headers:
            values = msg.get_all(header)
            if values and len(values) > 1:
                issues.append(f"Duplicate {header.upper()} header (should be unique)")
        
        return issues

    def validate_eml_file(self, file_path: str) -> Tuple[bool, Dict[str, List[str]]]:
        """Validate a single .eml file for RFC 5322 compliance"""
        self.violations = []
        self.warnings = []
        report = {
            'file': file_path,
            'violations': [],
            'warnings': [],
            'compliant': False
        }
        
        try:
            # Read raw content
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            
            # Decode and check line lengths
            try:
                text_content = raw_content.decode('utf-8', errors='replace')
            except:
                text_content = raw_content.decode('latin-1', errors='replace')
            
            line_issues = self.validate_line_length(text_content)
            self.violations.extend(line_issues)
            
            # Parse email with strict policy
            msg = email.message_from_bytes(raw_content, policy=policy.default)
            
            # Validate message structure
            struct_issues = self.validate_message_structure(msg)
            self.violations.extend(struct_issues)
            
            # Validate FROM header
            from_header = msg.get('From')
            if from_header:
                valid, issues = self.validate_email_address(from_header)
                if not valid:
                    self.violations.extend([f"FROM header: {issue}" for issue in issues])
                
                # Validate header syntax
                syntax_issues = self.validate_header_syntax('From', from_header)
                self.violations.extend(syntax_issues)
            
            # Validate TO header(s)
            to_headers = msg.get_all('To') or []
            for to_header in to_headers:
                # Split multiple addresses
                addresses = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', to_header)
                for addr in addresses:
                    addr = addr.strip()
                    if addr:
                        valid, issues = self.validate_email_address(addr)
                        if not valid:
                            self.violations.extend([f"TO header: {issue}" for issue in issues])
            
            # Validate CC header(s)
            cc_headers = msg.get_all('Cc') or []
            for cc_header in cc_headers:
                addresses = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', cc_header)
                for addr in addresses:
                    addr = addr.strip()
                    if addr:
                        valid, issues = self.validate_email_address(addr)
                        if not valid:
                            self.violations.extend([f"CC header: {issue}" for issue in issues])
            
            # Validate DATE header
            date_header = msg.get('Date')
            if date_header:
                valid, issues = self.validate_date_header(date_header)
                if not valid:
                    self.violations.extend([f"DATE header: {issue}" for issue in issues])
                
                # Validate header syntax
                syntax_issues = self.validate_header_syntax('Date', date_header)
                self.violations.extend(syntax_issues)
            
            # Validate SUBJECT header
            subject_header = msg.get('Subject')
            if subject_header:
                # Check for non-ASCII without proper encoding
                try:
                    subject_header.encode('ascii')
                except UnicodeEncodeError:
                    # Should be properly encoded with RFC 2047
                    if not re.search(r'=\?[^?]+\?[BQ]\?[^?]+\?=', subject_header):
                        self.warnings.append("SUBJECT contains non-ASCII without RFC 2047 encoding")
                
                # Validate header syntax
                syntax_issues = self.validate_header_syntax('Subject', subject_header)
                self.violations.extend(syntax_issues)
            
            # Validate MESSAGE-ID header
            msg_id = msg.get('Message-ID')
            if msg_id:
                # Message-ID should be in format <id@domain>
                if not re.match(r'^<[^@\s]+@[^@\s]+>$', msg_id.strip()):
                    self.violations.append(f"Invalid Message-ID format: {msg_id}")
            
            # Check all headers for proper syntax
            for header_name in msg.keys():
                header_value = msg.get(header_name)
                if header_value:
                    syntax_issues = self.validate_header_syntax(header_name, header_value)
                    self.violations.extend(syntax_issues)
            
            # Check for bare LF (should be CRLF)
            if b'\r\n' not in raw_content and b'\n' in raw_content:
                self.violations.append("Message uses bare LF instead of CRLF")
            
            # Check header/body separator
            if b'\r\n\r\n' not in raw_content and b'\n\n' not in raw_content:
                self.violations.append("Missing blank line between headers and body")
            
            report['violations'] = self.violations
            report['warnings'] = self.warnings
            report['compliant'] = len(self.violations) == 0
            
            return report['compliant'], report
            
        except Exception as e:
            report['violations'] = [f"Failed to parse email: {str(e)}", traceback.format_exc()]
            return False, report

def main():
    validator = RFC5322Validator()
    compliant_dir = Path("rfc5322_compliant_emails")
    report_file = "rfc5322_validation_report.json"
    
    # Create directory for compliant emails
    compliant_dir.mkdir(exist_ok=True)
    
    # Get all .eml files
    eml_files = list(Path('.').rglob('*.eml'))
    total_files = len(eml_files)
    compliant_count = 0
    non_compliant_count = 0
    
    all_reports = []
    
    print(f"Starting RFC 5322 validation for {total_files} .eml files...")
    print(f"This will be a STRICT validation checking all RFC 5322 requirements.\n")
    
    for i, eml_file in enumerate(eml_files):
        if eml_file.parent == compliant_dir:
            continue  # Skip files already in compliant directory
            
        print(f"Processing {i+1}/{total_files}: {eml_file}")
        
        is_compliant, report = validator.validate_eml_file(str(eml_file))
        all_reports.append(report)
        
        if is_compliant:
            compliant_count += 1
            # Move to compliant directory
            dest_path = compliant_dir / eml_file.name
            
            # Handle duplicate filenames
            if dest_path.exists():
                base = dest_path.stem
                ext = dest_path.suffix
                counter = 1
                while dest_path.exists():
                    dest_path = compliant_dir / f"{base}_{counter}{ext}"
                    counter += 1
            
            shutil.move(str(eml_file), str(dest_path))
            print(f"  ✓ COMPLIANT - Moved to {dest_path}")
        else:
            non_compliant_count += 1
            print(f"  ✗ NON-COMPLIANT - {len(report['violations'])} violations found")
            for violation in report['violations'][:3]:  # Show first 3 violations
                print(f"    - {violation}")
            if len(report['violations']) > 3:
                print(f"    ... and {len(report['violations']) - 3} more violations")
    
    # Save detailed report
    with open(report_file, 'w') as f:
        json.dump({
            'summary': {
                'total_files': total_files,
                'compliant': compliant_count,
                'non_compliant': non_compliant_count,
                'validation_date': datetime.now().isoformat()
            },
            'files': all_reports
        }, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"RFC 5322 Validation Complete!")
    print(f"{'='*60}")
    print(f"Total files processed: {total_files}")
    print(f"Compliant files: {compliant_count} (moved to {compliant_dir}/)")
    print(f"Non-compliant files: {non_compliant_count}")
    print(f"\nDetailed report saved to: {report_file}")
    
    # Show some statistics
    if all_reports:
        violation_types = {}
        for report in all_reports:
            for violation in report['violations']:
                vtype = violation.split(':')[0].split(' ')[0]
                violation_types[vtype] = violation_types.get(vtype, 0) + 1
        
        print(f"\nMost common violation types:")
        for vtype, count in sorted(violation_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  - {vtype}: {count} occurrences")

if __name__ == "__main__":
    main()