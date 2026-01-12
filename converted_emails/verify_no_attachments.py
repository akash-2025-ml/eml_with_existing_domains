#!/usr/bin/env python3
import json
import os
import base64

def check_for_attachments(data, filepath):
    """Thoroughly check if a JSON file has any attachments"""
    issues = []
    
    # Check hasAttachments field
    if "email_data" in data and "emailcontent" in data["email_data"]:
        email_content = data["email_data"]["emailcontent"]
        if "hasAttachments" in email_content and email_content["hasAttachments"]:
            issues.append("hasAttachments is set to True")
    
    # Check for attachments field at various levels
    def check_attachments_field(obj, path=""):
        if isinstance(obj, dict):
            if "attachments" in obj and obj["attachments"]:
                issues.append(f"Found attachments field at {path}")
            if "attachment" in obj and obj["attachment"]:
                issues.append(f"Found attachment field at {path}")
            for key, value in obj.items():
                check_attachments_field(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                check_attachments_field(item, f"{path}[{i}]")
    
    check_attachments_field(data)
    
    # Check for base64 content
    def check_base64_content(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ["contentBytes", "content_bytes", "data", "fileData", "file_data"]:
                    if isinstance(value, str) and len(value) > 100:
                        try:
                            # Try to decode as base64
                            base64.b64decode(value)
                            if len(value) > 1000:  # Likely a file, not just a small encoded string
                                issues.append(f"Found large base64 content in {path}.{key} (length: {len(value)})")
                        except:
                            pass
                check_base64_content(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                check_base64_content(item, f"{path}[{i}]")
    
    check_base64_content(data)
    
    return issues

# Check all files in no_attachments directory
no_attach_dir = "no_attachments"
files_with_issues = []
total_files = 0

for filename in os.listdir(no_attach_dir):
    if filename.endswith(".json"):
        total_files += 1
        filepath = os.path.join(no_attach_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            issues = check_for_attachments(data, filepath)
            if issues:
                files_with_issues.append({
                    "file": filename,
                    "issues": issues
                })
        except Exception as e:
            print(f"Error checking {filename}: {str(e)}")

# Report results
print(f"=== ATTACHMENT VERIFICATION REPORT ===")
print(f"Total files checked: {total_files}")
print(f"Files with potential attachments: {len(files_with_issues)}")

if files_with_issues:
    print(f"\n⚠️  WARNING: Found {len(files_with_issues)} files that may have attachments!")
    print("\nDetailed issues:")
    for item in files_with_issues[:10]:  # Show first 10
        print(f"\n{item['file']}:")
        for issue in item['issues']:
            print(f"  - {issue}")
    
    if len(files_with_issues) > 10:
        print(f"\n... and {len(files_with_issues) - 10} more files with issues")
else:
    print("\n✅ VERIFIED: All files in no_attachments folder are clean - no attachments found!")