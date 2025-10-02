import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import shutil
from src import checksum_utils, transfer_validator, config_manager

class FileTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer Integrity Validator")
        self.root.geometry("700x400")

        # Load config
        self.config = config_manager.load_config()

        notebook = ttk.Notebook(root)

        # Tabs
        self.transfer_tab = ttk.Frame(notebook)
        self.validation_tab = ttk.Frame(notebook)
        self.settings_tab = ttk.Frame(notebook)
        self.logs_tab = ttk.Frame(notebook)

        notebook.add(self.transfer_tab, text="File Transfer")
        notebook.add(self.validation_tab, text="Validation")
        notebook.add(self.settings_tab, text="Settings")
        notebook.add(self.logs_tab, text="Logs")

        notebook.pack(expand=True, fill="both")

        # Build tabs
        self.build_transfer_tab()
        self.build_validation_tab()
        self.build_settings_tab()
        self.build_logs_tab()

    # ---------------- FILE TRANSFER TAB ----------------
    def build_transfer_tab(self):
        frame = self.transfer_tab

        # Source picker
        self.source_var = tk.StringVar()
        ttk.Label(frame, text="Source Folder:").pack(pady=5, anchor="w")
        source_frame = ttk.Frame(frame)
        source_frame.pack(fill="x", padx=10)
        ttk.Entry(source_frame, textvariable=self.source_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(source_frame, text="Browse", command=self.pick_source).pack(side="left", padx=5)

        # Destination picker
        self.dest_var = tk.StringVar()
        ttk.Label(frame, text="Destination Folder:").pack(pady=5, anchor="w")
        dest_frame = ttk.Frame(frame)
        dest_frame.pack(fill="x", padx=10)
        ttk.Entry(dest_frame, textvariable=self.dest_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(dest_frame, text="Browse", command=self.pick_destination).pack(side="left", padx=5)

        # Start button
        ttk.Button(frame, text="Start Transfer", command=self.start_transfer).pack(pady=15)

        # Progress bar
        self.progress = ttk.Progressbar(frame, length=500, mode="determinate")
        self.progress.pack(pady=10)

        # Status label
        self.status_label = ttk.Label(frame, text="Status: Waiting")
        self.status_label.pack(pady=5)

    def pick_source(self):
        folder = filedialog.askdirectory(title="Select Source Folder")
        if folder:
            self.source_var.set(folder)

    def pick_destination(self):
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            self.dest_var.set(folder)

    def start_transfer(self):
        source = self.source_var.get()
        dest = self.dest_var.get()

        if not source or not dest:
            messagebox.showerror("Error", "Please select both source and destination folders.")
            return

        threading.Thread(target=self.copy_and_validate, args=(source, dest), daemon=True).start()

    def copy_and_validate(self, source, dest):
        # Collect all files
        files = []
        for root, _, filenames in os.walk(source):
            for name in filenames:
                src_file = os.path.join(root, name)
                rel_path = os.path.relpath(src_file, source)
                dest_file = os.path.join(dest, rel_path)
                files.append((src_file, dest_file))

        total_files = len(files)
        if total_files == 0:
            messagebox.showwarning("No Files", "No files found in source directory.")
            return

        # Prepare progress bar
        self.progress["value"] = 0
        self.progress["maximum"] = total_files
        self.status_label.config(text=f"Transferring {total_files} files...")

        success_count = 0
        corrupted = []
        missing = []

        for i, (src_file, dest_file) in enumerate(files, start=1):
            os.makedirs(os.path.dirname(dest_file), exist_ok=True)

            try:
                shutil.copy2(src_file, dest_file)

                # Verify checksum
                algo = self.config.get("checksum_algorithm", "sha256")
                if not checksum_utils.compare_files(src_file, dest_file, algo):
                    corrupted.append(os.path.relpath(src_file, source))
                else:
                    success_count += 1

            except Exception as e:
                missing.append(os.path.relpath(src_file, source))

            # Update progress bar
            self.progress["value"] = i
            self.status_label.config(text=f"Transferred {i}/{total_files} files")
            self.root.update_idletasks()

        # Final summary
        summary = (
            f"✅ Successful: {success_count}\n"
            f"⚠️ Corrupted: {len(corrupted)}\n"
            f"❌ Failed/Missing: {len(missing)}"
        )
        self.status_label.config(text="Transfer Complete")
        messagebox.showinfo("Transfer Summary", summary)

    # ---------------- VALIDATION TAB ----------------
    def build_validation_tab(self):
        ttk.Label(self.validation_tab, text="Validation Interface (Coming Soon)").pack(pady=20)

    # ---------------- SETTINGS TAB ----------------
    def build_settings_tab(self):
        ttk.Label(self.settings_tab, text="Settings Panel (Coming Soon)").pack(pady=20)

    # ---------------- LOGS TAB ----------------
    def build_logs_tab(self):
        ttk.Label(self.logs_tab, text="Logs Viewer (Coming Soon)").pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferGUI(root)
    root.mainloop()
