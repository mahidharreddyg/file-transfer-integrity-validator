import unittest
import os
import tkinter as tk
from gui import FileTransferGUI

class TestGUI(unittest.TestCase):
    def setUp(self):
        # Tkinter root
        self.root = tk.Tk()
        self.app = FileTransferGUI(self.root)

        # Setup test folders
        self.src_dir = "tests/test_data/gui_src"
        self.dst_dir = "tests/test_data/gui_dst"
        os.makedirs(self.src_dir, exist_ok=True)
        os.makedirs(self.dst_dir, exist_ok=True)

        # Create a test file
        with open(os.path.join(self.src_dir, "hello.txt"), "w") as f:
            f.write("Hello world")

    def tearDown(self):
        self.root.destroy()

    def test_transfer_via_gui(self):
        """Simulate using the GUI to transfer files."""
        # Set the source and destination in the GUI
        self.app.source_var.set(self.src_dir)
        self.app.dest_var.set(self.dst_dir)

        # Run transfer directly (bypasses button click)
        self.app.copy_and_validate(self.src_dir, self.dst_dir)

        # Verify the file was copied
        dst_file = os.path.join(self.dst_dir, "hello.txt")
        self.assertTrue(os.path.exists(dst_file))

        # Verify checksum matches
        from src.checksum_utils import compare_files
        self.assertTrue(compare_files(os.path.join(self.src_dir, "hello.txt"), dst_file))

if __name__ == "__main__":
    unittest.main(verbosity=2)
