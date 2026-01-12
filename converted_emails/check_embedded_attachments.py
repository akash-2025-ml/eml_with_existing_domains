#!/usr/bin/env python3
import json
import os

def has_embedded_attachments(filepath):
    """Check if JSON file has embedded attachments in content"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Get the email content
        content = ""
        if "email_data" in data and "emailcontent" in data["email_data"] and "body" in data["email_data"]["emailcontent"]:
            body = data["email_data"]["emailcontent"]["body"]
            if isinstance(body, dict) and "content" in body:
                content = body["content"]
        
        # Check for MIME attachment indicators
        attachment_indicators = [
            "Content-Disposition: attachment",
            "Content-Transfer-Encoding: base64",
            "Content-Type: application/",
            "Content-Type: image/",
            "Content-Type: video/",
            "Content-Type: audio/",
            "filename="
        ]
        
        for indicator in attachment_indicators:
            if indicator in content:
                return True
                
        return False
        
    except Exception as e:
        print(f"Error checking {filepath}: {str(e)}")
        return False

# Check files in no_attachments directory
no_attach_dir = "no_attachments"
files_with_embedded = []

for filename in os.listdir(no_attach_dir):
    if filename.endswith(".json"):
        filepath = os.path.join(no_attach_dir, filename)
        if has_embedded_attachments(filepath):
            files_with_embedded.append(filename)

print(f"Files with embedded attachments in content: {len(files_with_embedded)}")
if files_with_embedded:
    print("\nThese files have attachments embedded in email content:")
    for f in files_with_embedded:
        print(f"  - {f}")

# Move these files back to parent directory
if files_with_embedded:
    print("\nMoving files with embedded attachments back...")
    import shutil
    for filename in files_with_embedded:
        src = os.path.join(no_attach_dir, filename)
        dst = os.path.join(".", filename)
        shutil.move(src, dst)
        print(f"Moved {filename} back to main directory")
    
    print(f"\nCorrected count: {len(os.listdir(no_attach_dir)) - 1} files truly without attachments")