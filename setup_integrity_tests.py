#!/usr/bin/env python3
"""
Integrity Test Files Setup Script
Creates test files in tests/test_data/src and test_transfer for checksum validation testing.
"""
import os
import shutil
from pathlib import Path


def create_integrity_test_files():
    """Create test files for integrity/checksum validation testing."""
    
    # Source directory
    test_src = "tests/test_data/src"
    # Destination directory
    test_dst = "test_transfer"
    
    os.makedirs(test_src, exist_ok=True)
    os.makedirs(test_dst, exist_ok=True)
    
    print("Creating integrity test files for checksum validation...")
    
    # Create various test files
    test_files = [
        ("file1.txt", "This is the first test file for integrity validation.\nIt contains some sample text."),
        ("file2.txt", "Second test file with different content.\nUsed for checksum comparison testing."),
        ("document.txt", "A document file for testing data integrity.\nThis should transfer correctly."),
        ("data.txt", "Sample data file.\nContains test information for validation."),
        ("important.txt", "Important file content.\nThis file should be validated after transfer."),
    ]
    
    for filename, content in test_files:
        filepath = os.path.join(test_src, filename)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"✓ Created: {filename}")
    
    # Create a file that will be corrupted after transfer
    # We'll create a corrupted version in destination that will fail checksum
    corrupted_file = "data.txt"
    corrupted_content = "CORRUPTED DATA - This file has been tampered with!\nOriginal content modified."
    corrupted_path = os.path.join(test_dst, corrupted_file)
    with open(corrupted_path, "w") as f:
        f.write(corrupted_content)
    print(f"⚠ Created corrupted version in destination: {corrupted_file} (will show as corrupted after transfer)")
    
    print(f"\n✅ Integrity test files created in '{test_src}' directory")
    print(f"   Destination directory: '{test_dst}'")
    print(f"\n⚠️  Note: '{corrupted_file}' already exists in destination with corrupted content")
    print("   After transfer, this file will show as CORRUPTED (checksum mismatch)")
    print("\n📋 Usage:")
    print("   Transfer Tab:")
    print("     - Source: tests/test_data/src")
    print("     - Destination: test_transfer")
    print("     - Result: Will show 1 file as CORRUPTED (data.txt)")
    print("   Validation Tab:")
    print("     - Source: tests/test_data/src")
    print("     - Destination: test_transfer")
    print("     - Result: Will show 1 file as CORRUPTED (data.txt)")


def cleanup_integrity_test_files():
    """Remove test files but keep directory structure."""
    test_src = "tests/test_data/src"
    test_dst = "test_transfer"
    
    # Clean up unnecessary files in tests/test_data (keep only src/)
    cleanup_dirs = [
        "tests/test_data/dst",
        "tests/test_data/dst_corrupt",
        "tests/test_data/gui_dst",
        "tests/test_data/gui_src",
        "tests/test_data/src_corrupt",
    ]
    
    for dir_path in cleanup_dirs:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
            print(f"✓ Removed directory: {dir_path}")
    
    # Remove loose files in tests/test_data
    test_data_dir = "tests/test_data"
    if os.path.exists(test_data_dir):
        for item in os.listdir(test_data_dir):
            item_path = os.path.join(test_data_dir, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
                print(f"✓ Removed: {item_path}")
    
    # Remove files from source (keep directory)
    if os.path.exists(test_src):
        for filename in os.listdir(test_src):
            filepath = os.path.join(test_src, filename)
            if os.path.isfile(filepath):
                os.remove(filepath)
                print(f"✓ Removed: {filepath}")
    
    # Clean up test_transfer directory (remove all subdirectories and files)
    if os.path.exists(test_dst):
        for item in os.listdir(test_dst):
            item_path = os.path.join(test_dst, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
                print(f"✓ Removed directory: {item_path}")
            elif os.path.isfile(item_path):
                os.remove(item_path)
                print(f"✓ Removed: {item_path}")


def reset_integrity_test_files():
    """Clean up and recreate integrity test files for fresh testing."""
    print("🔄 Resetting integrity test files...\n")
    cleanup_integrity_test_files()
    print()
    create_integrity_test_files()
    print("\n✨ Integrity test files reset and ready!")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "cleanup":
            cleanup_integrity_test_files()
            print("\n✅ Cleanup complete")
        elif command == "reset":
            reset_integrity_test_files()
        else:
            print(f"Unknown command: {command}")
            print("Usage: python3 setup_integrity_tests.py [cleanup|reset]")
            print("  cleanup - Remove test files")
            print("  reset   - Remove and recreate test files (for fresh testing)")
    else:
        create_integrity_test_files()

