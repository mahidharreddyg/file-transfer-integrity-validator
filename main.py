#!/usr/bin/env python3
import argparse
from src import transfer_validator, checksum_utils, report_generator

def main():
    parser = argparse.ArgumentParser(
        description="File Transfer Integrity Validator - CLI Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # transfer command
    transfer_parser = subparsers.add_parser("transfer", help="Transfer files with integrity validation")
    transfer_parser.add_argument("source", help="Source directory")
    transfer_parser.add_argument("destination", help="Destination directory")
    transfer_parser.add_argument("--recursive", action="store_true", help="Recursively copy files")
    transfer_parser.add_argument("--progress", action="store_true", help="Show transfer progress")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate existing transfer")
    validate_parser.add_argument("source", help="Source directory")
    validate_parser.add_argument("destination", help="Destination directory")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify two files against each other")
    verify_parser.add_argument("file1", help="First file")
    verify_parser.add_argument("file2", help="Second file")

    # manifest command
    manifest_parser = subparsers.add_parser("manifest", help="Create checksum manifest of a directory")
    manifest_parser.add_argument("directory", help="Target directory")
    manifest_parser.add_argument("--output", default="checksums.txt", help="Output file for checksums")

    args = parser.parse_args()

    if args.command == "transfer":
        print(f"[CLI] Simulating transfer from {args.source} to {args.destination}")
        # transfer_validator.transfer_files(args.source, args.destination, args.recursive)

    elif args.command == "validate":
        print(f"[CLI] Validating {args.source} vs {args.destination}")
        # transfer_validator.validate_transfer(args.source, args.destination)

    elif args.command == "verify":
        print(f"[CLI] Comparing {args.file1} vs {args.file2}")
        # checksum_utils.compare_files(args.file1, args.file2)

    elif args.command == "manifest":
        print(f"[CLI] Creating manifest for {args.directory}, output -> {args.output}")
        # checksum_utils.create_manifest(args.directory, args.output)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
