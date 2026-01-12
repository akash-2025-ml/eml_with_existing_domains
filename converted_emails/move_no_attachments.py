#!/usr/bin/env python3
import json
import os
import shutil

# Create the target directory if it doesn't exist
target_dir = "no_attachments"
if not os.path.exists(target_dir):
    os.makedirs(target_dir)

# Counter for moved files
moved_count = 0
total_count = 0
error_count = 0

# Process all JSON files in the current directory
for filename in os.listdir("."):
    if filename.endswith(".json"):
        total_count += 1
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Check if the file has attachments
            has_attachments = False
            
            # Check for hasAttachments field
            if "email_data" in data and "emailcontent" in data["email_data"]:
                email_content = data["email_data"]["emailcontent"]
                if "hasAttachments" in email_content and email_content["hasAttachments"]:
                    has_attachments = True
            
            # Also check for attachments field
            if "attachments" in data and data["attachments"]:
                has_attachments = True
            elif "email_data" in data and "emailcontent" in data["email_data"]:
                if "attachments" in data["email_data"]["emailcontent"] and data["email_data"]["emailcontent"]["attachments"]:
                    has_attachments = True
            
            # Move file if no attachments found
            if not has_attachments:
                target_path = os.path.join(target_dir, filename)
                shutil.move(filename, target_path)
                moved_count += 1
                print(f"Moved: {filename}")
        
        except Exception as e:
            error_count += 1
            print(f"Error processing {filename}: {str(e)}")

print(f"\nSummary:")
print(f"Total JSON files processed: {total_count}")
print(f"Files moved (no attachments): {moved_count}")
print(f"Files with attachments (not moved): {total_count - moved_count - error_count}")
print(f"Errors: {error_count}")