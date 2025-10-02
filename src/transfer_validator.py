import os
from src import checksum_utils

def validate_transfer(source, destination, algorithm="sha256"):
    """Validate transfer between source and destination directories."""
    missing_files = []
    corrupted_files = []

    for root, _, files in os.walk(source):
        for name in files:
            if name.startswith("."): 
              continue
            src_file = os.path.join(root, name)
            rel_path = os.path.relpath(src_file, source)
            dest_file = os.path.join(destination, rel_path)

            if not os.path.exists(dest_file):
                missing_files.append(rel_path)
            else:
                if not checksum_utils.compare_files(src_file, dest_file, algorithm):
                    corrupted_files.append(rel_path)

    return missing_files, corrupted_files
