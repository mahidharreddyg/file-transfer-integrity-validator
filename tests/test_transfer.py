import unittest
import os
from src import checksum_utils, transfer_validator

class TestTransferValidator(unittest.TestCase):
    def setUp(self):
        self.sample_file = "tests/test_data/file1.txt"

    def test_checksum(self):
        checksum = checksum_utils.calculate_checksum(self.sample_file)
        self.assertIsInstance(checksum, str)
        self.assertTrue(len(checksum) > 0)

    def test_transfer_validation(self):
        missing, corrupted = transfer_validator.validate_transfer("tests/test_data", "tests/test_data")
        self.assertEqual(missing, [])
        self.assertEqual(corrupted, [])

if __name__ == "__main__":
    unittest.main()
