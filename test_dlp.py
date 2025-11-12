#!/usr/bin/env python3
"""
DLP System Test Script
Creates test files and scenarios to test DLP functionality.
"""
import os
import shutil
from pathlib import Path

def create_test_files():
    """Create test files for DLP testing."""
    
    # Create test directories
    test_src = "test_dlp_src"
    test_dst = "test_dlp_dst"
    
    os.makedirs(test_src, exist_ok=True)
    os.makedirs(test_dst, exist_ok=True)
    
    print("Creating test files for DLP testing...")
    
    # 1. File that should be blocked (restricted extension - .pdf)
    with open(os.path.join(test_src, "document.pdf"), "w") as f:
        f.write("This is a PDF document that should be blocked.\n")
    print("✓ Created: document.pdf (should be blocked - restricted extension)")
    
    # 2. File that should be blocked (restricted pattern - contains "confidential")
    with open(os.path.join(test_src, "confidential_report.txt"), "w") as f:
        f.write("This is a confidential report.\n")
    print("✓ Created: confidential_report.txt (should be blocked - restricted pattern)")
    
    # 3. File with sensitive content (password)
    with open(os.path.join(test_src, "config.txt"), "w") as f:
        f.write("Database configuration:\n")
        f.write("password: mySecretPassword123\n")
        f.write("api_key: sk-1234567890abcdef\n")
    print("✓ Created: config.txt (should be blocked - sensitive content)")
    
    # 4. File with credit card number
    with open(os.path.join(test_src, "payment_info.txt"), "w") as f:
        f.write("Customer payment information:\n")
        f.write("Credit Card: 4532-1234-5678-9010\n")
        f.write("SSN: 123-45-6789\n")
    print("✓ Created: payment_info.txt (should be blocked - sensitive data)")
    
    # 5. File that should pass (normal file)
    with open(os.path.join(test_src, "normal_file.txt"), "w") as f:
        f.write("This is a normal file that should transfer successfully.\n")
    print("✓ Created: normal_file.txt (should pass)")
    
    # 6. File with "secret" in name (restricted pattern)
    with open(os.path.join(test_src, "secret_notes.txt"), "w") as f:
        f.write("Secret notes here.\n")
    print("✓ Created: secret_notes.txt (should be blocked - restricted pattern)")
    
    # 7. File that should be encrypted (if encryption is enabled)
    with open(os.path.join(test_src, "sensitive_data.docx"), "w") as f:
        f.write("This is a sensitive document.\n")
    print("✓ Created: sensitive_data.docx (may be encrypted if encryption enabled)")
    
    print(f"\n✅ Test files created in '{test_src}' directory")
    print(f"   Destination directory: '{test_dst}'")
    print("\n📋 Test Scenarios:")
    print("   1. document.pdf - Should be BLOCKED (restricted extension)")
    print("   2. confidential_report.txt - Should be BLOCKED (restricted pattern)")
    print("   3. config.txt - Should be BLOCKED (sensitive content: password, api_key)")
    print("   4. payment_info.txt - Should be BLOCKED (sensitive data: credit card, SSN)")
    print("   5. normal_file.txt - Should PASS")
    print("   6. secret_notes.txt - Should be BLOCKED (restricted pattern)")
    print("   7. sensitive_data.docx - May be ENCRYPTED (if encryption enabled)")
    print("\n🚀 Next Steps:")
    print("   1. Run the GUI: python3 gui.py")
    print("   2. Go to 'File Transfer' tab")
    print("   3. Set Source: test_dlp_src")
    print("   4. Set Destination: test_dlp_dst")
    print("   5. Click 'Start Transfer'")
    print("   6. Check the DLP Dashboard tab for violations")
    print("   7. Check transfer summary for blocked files")

def cleanup_test_files():
    """Remove test directories."""
    import shutil
    test_dirs = ["test_dlp_src", "test_dlp_dst"]
    for dir_name in test_dirs:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"✓ Removed: {dir_name}")

def reset_test_files():
    """Clean up and recreate test files for fresh demo."""
    print("🔄 Resetting test files for demo...\n")
    cleanup_test_files()
    print()
    create_test_files()
    print("\n✨ Test files reset and ready for demo!")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "cleanup":
            cleanup_test_files()
            print("\n✅ Cleanup complete")
        elif command == "reset":
            reset_test_files()
        else:
            print(f"Unknown command: {command}")
            print("Usage: python3 test_dlp.py [cleanup|reset]")
            print("  cleanup - Remove test directories")
            print("  reset   - Remove and recreate test files (for fresh demo)")
    else:
        create_test_files()

