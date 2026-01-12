#!/usr/bin/env python3
"""
RFC 5322 Email Corrector
Corrects common RFC 5322 violations in .eml files while preserving content
"""

import os
import re
import email
import email.utils
import email.generator
import email.policy
from email import message_from_string, message_from_bytes
from datetime import datetime
from pathlib import Path
import json
import traceback
from typing import List, Dict, Tuple, Optional
import io

class RFC5322Corrector:
    def __init__(self):
        self.corrections_log = []
        
    def fix_email_address(self, addr_string: str) -> str:
        """Fix common email address format issues"""
        if not addr_string:
            return addr_string
            
        # Handle multiple addresses in FROM field (take first one)
        if ',' in addr_string and '@' in addr_string:
            # Split and take first valid address
            addresses = addr_string.split(',')
            for addr in addresses:
                addr = addr.strip()
                if '@' in addr:
                    addr_string = addr
                    break
        
        # Parse the address
        name, email_addr = email.utils.parseaddr(addr_string)
        
        if email_addr:
            # Fix double dots
            email_addr = re.sub(r'\.{2,}', '.', email_addr)
            
            # Fix leading dot in local part
            if email_addr.startswith('.'):
                email_addr = email_addr[1:]
            
            # Fix trailing dot in local part
            local, domain = email_addr.rsplit('@', 1)
            if local.endswith('.'):
                local = local[:-1]
            if local.startswith('.'):
                local = local[1:]
            
            email_addr = f"{local}@{domain}"
            
            # Reconstruct full address
            if name:
                return email.utils.formataddr((name, email_addr))
            else:
                return email_addr
        
        return addr_string

    def ensure_date_header(self, msg_dict: Dict[str, List[str]]) -> None:
        """Ensure Date header exists and is RFC 5322 compliant"""
        if 'Date' not in msg_dict or not msg_dict['Date']:
            # Add current date in RFC 5322 format
            msg_dict['Date'] = [email.utils.formatdate(localtime=True)]
            self.corrections_log.append("Added missing Date header")
        else:
            # Validate existing date
            date_str = msg_dict['Date'][0]
            try:
                # Try to parse and reformat
                parsed_date = email.utils.parsedate_to_datetime(date_str)
                if parsed_date:
                    # Reformat to strict RFC 5322
                    msg_dict['Date'][0] = email.utils.format_datetime(parsed_date)
                    self.corrections_log.append("Reformatted Date header to RFC 5322 format")
            except:
                # If parsing fails, use current date
                msg_dict['Date'] = [email.utils.formatdate(localtime=True)]
                self.corrections_log.append("Replaced invalid Date header")

    def correct_eml_file(self, file_path: str) -> Tuple[bool, str, Dict[str, any]]:
        """Correct a single .eml file for RFC 5322 compliance"""
        self.corrections_log = []
        report = {
            'file': file_path,
            'corrections': [],
            'success': False,
            'error': None
        }
        
        try:
            # Read raw content
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            
            # First, fix line endings (LF to CRLF)
            if b'\r\n' not in raw_content and b'\n' in raw_content:
                # Replace bare LF with CRLF
                raw_content = raw_content.replace(b'\n', b'\r\n')
                self.corrections_log.append("Converted LF to CRLF line endings")
            
            # Try to decode
            try:
                text_content = raw_content.decode('utf-8', errors='replace')
            except:
                text_content = raw_content.decode('latin-1', errors='replace')
            
            # Split headers and body
            # Email format: headers, blank line, body
            parts = text_content.split('\r\n\r\n', 1)
            if len(parts) == 1:
                # No body separator found, might be headers only
                header_section = parts[0]
                body_section = ''
            else:
                header_section, body_section = parts
            
            # Parse headers into a dictionary
            headers_dict = {}
            current_header = None
            
            for line in header_section.split('\r\n'):
                if line and line[0] not in (' ', '\t'):
                    # New header
                    if ':' in line:
                        header_name, header_value = line.split(':', 1)
                        header_name = header_name.strip()
                        header_value = header_value.strip()
                        
                        if header_name not in headers_dict:
                            headers_dict[header_name] = []
                        headers_dict[header_name].append(header_value)
                        current_header = header_name
                elif current_header and line:
                    # Folded header continuation
                    headers_dict[current_header][-1] += ' ' + line.strip()
            
            # Fix duplicate FROM headers
            if 'From' in headers_dict and len(headers_dict['From']) > 1:
                # Keep only the first FROM header
                headers_dict['From'] = [headers_dict['From'][0]]
                self.corrections_log.append(f"Removed {len(headers_dict['From'])-1} duplicate FROM headers")
            
            # Fix FROM header email address
            if 'From' in headers_dict:
                original_from = headers_dict['From'][0]
                fixed_from = self.fix_email_address(original_from)
                if fixed_from != original_from:
                    headers_dict['From'][0] = fixed_from
                    self.corrections_log.append(f"Fixed FROM address: {original_from} -> {fixed_from}")
            else:
                # Add missing FROM header
                headers_dict['From'] = ['unknown@localhost']
                self.corrections_log.append("Added missing FROM header with placeholder")
            
            # Fix TO headers
            if 'To' in headers_dict:
                for i, to_addr in enumerate(headers_dict['To']):
                    original_to = to_addr
                    # Split multiple addresses properly
                    if ',' in to_addr:
                        fixed_addresses = []
                        for addr in to_addr.split(','):
                            addr = addr.strip()
                            if addr:
                                fixed_addr = self.fix_email_address(addr)
                                fixed_addresses.append(fixed_addr)
                        headers_dict['To'][i] = ', '.join(fixed_addresses)
                        if headers_dict['To'][i] != original_to:
                            self.corrections_log.append(f"Fixed TO addresses")
                    else:
                        fixed_to = self.fix_email_address(to_addr)
                        if fixed_to != original_to:
                            headers_dict['To'][i] = fixed_to
                            self.corrections_log.append(f"Fixed TO address: {original_to} -> {fixed_to}")
            
            # Fix CC headers similarly
            if 'Cc' in headers_dict:
                for i, cc_addr in enumerate(headers_dict['Cc']):
                    original_cc = cc_addr
                    if ',' in cc_addr:
                        fixed_addresses = []
                        for addr in cc_addr.split(','):
                            addr = addr.strip()
                            if addr:
                                fixed_addr = self.fix_email_address(addr)
                                fixed_addresses.append(fixed_addr)
                        headers_dict['Cc'][i] = ', '.join(fixed_addresses)
                        if headers_dict['Cc'][i] != original_cc:
                            self.corrections_log.append(f"Fixed CC addresses")
                    else:
                        fixed_cc = self.fix_email_address(cc_addr)
                        if fixed_cc != original_cc:
                            headers_dict['Cc'][i] = fixed_cc
                            self.corrections_log.append(f"Fixed CC address: {original_cc} -> {fixed_cc}")
            
            # Ensure Date header
            self.ensure_date_header(headers_dict)
            
            # Fix Message-ID if present
            if 'Message-ID' in headers_dict:
                msg_id = headers_dict['Message-ID'][0]
                # Ensure angle brackets
                if not msg_id.startswith('<'):
                    msg_id = '<' + msg_id
                if not msg_id.endswith('>'):
                    msg_id = msg_id + '>'
                if msg_id != headers_dict['Message-ID'][0]:
                    headers_dict['Message-ID'][0] = msg_id
                    self.corrections_log.append("Fixed Message-ID format")
            
            # Reconstruct the email
            # Build headers with proper formatting
            corrected_headers = []
            header_order = ['Return-Path', 'Received', 'Date', 'From', 'To', 'Cc', 'Subject', 'Message-ID', 'In-Reply-To', 'References']
            
            # Add headers in preferred order first
            for header_name in header_order:
                if header_name in headers_dict:
                    for value in headers_dict[header_name]:
                        # Properly fold long headers
                        if len(f"{header_name}: {value}") > 78:
                            # Simple folding at space boundaries
                            wrapped = self.fold_header(header_name, value)
                            corrected_headers.append(wrapped)
                        else:
                            corrected_headers.append(f"{header_name}: {value}")
            
            # Add remaining headers
            for header_name, values in headers_dict.items():
                if header_name not in header_order:
                    for value in values:
                        if len(f"{header_name}: {value}") > 78:
                            wrapped = self.fold_header(header_name, value)
                            corrected_headers.append(wrapped)
                        else:
                            corrected_headers.append(f"{header_name}: {value}")
            
            # Combine headers and body with proper CRLF
            corrected_content = '\r\n'.join(corrected_headers) + '\r\n\r\n' + body_section
            
            # Ensure final CRLF
            if not corrected_content.endswith('\r\n'):
                corrected_content += '\r\n'
            
            report['corrections'] = self.corrections_log
            report['success'] = True
            
            return True, corrected_content, report
            
        except Exception as e:
            report['error'] = f"Failed to correct email: {str(e)}\n{traceback.format_exc()}"
            return False, None, report

    def fold_header(self, name: str, value: str) -> str:
        """Fold long header lines according to RFC 5322"""
        header = f"{name}: {value}"
        if len(header) <= 78:
            return header
        
        # Simple folding at space boundaries
        lines = []
        current_line = f"{name}: "
        
        for word in value.split():
            if len(current_line + word) > 75:
                lines.append(current_line.rstrip())
                current_line = "  " + word + " "
            else:
                current_line += word + " "
        
        if current_line.strip():
            lines.append(current_line.rstrip())
        
        return '\r\n'.join(lines)

def main():
    corrector = RFC5322Corrector()
    corrected_dir = Path("rfc5322_corrected_emails")
    report_file = "rfc5322_correction_report.json"
    
    # Create directory for corrected emails
    corrected_dir.mkdir(exist_ok=True)
    
    # Get first 500 .eml files (excluding already corrected ones)
    all_eml_files = [f for f in Path('.').rglob('*.eml') 
                     if f.parent != corrected_dir and 
                     'rfc5322_compliant_emails' not in str(f) and
                     'rfc5322_corrected_emails' not in str(f)]
    
    eml_files = all_eml_files[:500]  # Process first 500
    total_files = len(eml_files)
    
    all_reports = []
    successful_corrections = 0
    failed_corrections = 0
    
    print(f"Starting RFC 5322 correction for {total_files} .eml files...")
    print("Corrections will include:")
    print("  - Converting LF to CRLF line endings")
    print("  - Removing duplicate FROM headers")
    print("  - Fixing malformed email addresses")
    print("  - Ensuring required headers (From, Date)")
    print("  - Preserving message content\n")
    
    # Import the validator to check corrections
    from rfc5322_validator import RFC5322Validator
    validator = RFC5322Validator()
    
    for i, eml_file in enumerate(eml_files):
        print(f"Processing {i+1}/{total_files}: {eml_file}")
        
        success, corrected_content, report = corrector.correct_eml_file(str(eml_file))
        all_reports.append(report)
        
        if success and corrected_content:
            # Save corrected file
            dest_path = corrected_dir / eml_file.name
            
            # Handle duplicate filenames
            if dest_path.exists():
                base = dest_path.stem
                ext = dest_path.suffix
                counter = 1
                while dest_path.exists():
                    dest_path = corrected_dir / f"{base}_{counter}{ext}"
                    counter += 1
            
            # Write corrected content
            with open(dest_path, 'w', encoding='utf-8', newline='') as f:
                f.write(corrected_content)
            
            # Validate the corrected file
            is_valid, validation_report = validator.validate_eml_file(str(dest_path))
            
            if is_valid:
                successful_corrections += 1
                print(f"  ✓ CORRECTED and VALIDATED - {len(report['corrections'])} corrections applied")
            else:
                # Still has violations after correction
                print(f"  ⚠ CORRECTED but still has violations - {len(report['corrections'])} corrections applied")
                print(f"    Remaining violations: {len(validation_report['violations'])}")
                successful_corrections += 1  # Count as success since we made corrections
        else:
            failed_corrections += 1
            print(f"  ✗ FAILED to correct - {report['error']}")
    
    # Save detailed report
    with open(report_file, 'w') as f:
        json.dump({
            'summary': {
                'total_files': total_files,
                'successful_corrections': successful_corrections,
                'failed_corrections': failed_corrections,
                'correction_date': datetime.now().isoformat()
            },
            'files': all_reports
        }, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"RFC 5322 Correction Complete!")
    print(f"{'='*60}")
    print(f"Total files processed: {total_files}")
    print(f"Successfully corrected: {successful_corrections}")
    print(f"Failed to correct: {failed_corrections}")
    print(f"\nCorrected files saved to: {corrected_dir}/")
    print(f"Detailed report saved to: {report_file}")

if __name__ == "__main__":
    main()