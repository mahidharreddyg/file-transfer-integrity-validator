import hashlib
import os

def calculate_checksum(file_path, algorithm="sha256"):
    """Calculate file checksum using the given algorithm."""
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def compare_files(file1, file2, algorithm="sha256"):
    """Compare two files by checksum."""
    return calculate_checksum(file1, algorithm) == calculate_checksum(file2, algorithm)

def create_manifest(directory, output_file, algorithm="sha256"):
    """Generate a checksum manifest for all files in a directory."""
    with open(output_file, "w") as f:
        for root, _, files in os.walk(directory):
            for name in files:
                file_path = os.path.join(root, name)
                checksum = calculate_checksum(file_path, algorithm)
                f.write(f"{checksum}  {file_path}\n")
