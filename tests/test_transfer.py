import unittest
import os
from src import checksum_utils, transfer_validator

class TestTransferValidator(unittest.TestCase):
    def setUp(self):
        # Base test folder
        self.base_dir = "tests/test_data"
        os.makedirs(self.base_dir, exist_ok=True)

        # Clean up any leftover test files from previous runs
        for f in os.listdir(self.base_dir):
            try:
                os.remove(os.path.join(self.base_dir, f))
            except:
                pass

        # Create a clean file for testing
        self.sample_file = os.path.join(self.base_dir, "file1.txt")
        with open(self.sample_file, "w") as f:
            f.write("This is a test file.")

    def test_checksum(self):
        checksum = checksum_utils.calculate_checksum(self.sample_file)
        self.assertIsInstance(checksum, str)
        self.assertTrue(len(checksum) > 0)

    def test_transfer_validation_identical(self):
        """If source and destination are identical, nothing should be missing/corrupted."""
        missing, corrupted = transfer_validator.validate_transfer(self.base_dir, self.base_dir)
        self.assertEqual(missing, [])
        self.assertEqual(corrupted, [])

    def test_missing_file_detection(self):
        """If a file is in source but not in destination, it should be flagged as missing."""
        src_dir = os.path.join(self.base_dir, "src")
        dst_dir = os.path.join(self.base_dir, "dst")

        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(dst_dir, exist_ok=True)

        src_file = os.path.join(src_dir, "important.txt")
        with open(src_file, "w") as f:
            f.write("Critical content")

        missing, corrupted = transfer_validator.validate_transfer(src_dir, dst_dir)
        self.assertIn("important.txt", missing)
        self.assertEqual(corrupted, [])

    def test_corrupted_file_detection(self):
        """If file contents differ between source and destination, it should be flagged as corrupted."""
        src_dir = os.path.join(self.base_dir, "src_corrupt")
        dst_dir = os.path.join(self.base_dir, "dst_corrupt")

        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(dst_dir, exist_ok=True)

        src_file = os.path.join(src_dir, "data.txt")
        dst_file = os.path.join(dst_dir, "data.txt")

        with open(src_file, "w") as f:
            f.write("This is the original file content")

        with open(dst_file, "w") as f:
            f.write("This content has been tampered!")

        missing, corrupted = transfer_validator.validate_transfer(src_dir, dst_dir)

        self.assertEqual(missing, [])
        self.assertIn("data.txt", corrupted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
