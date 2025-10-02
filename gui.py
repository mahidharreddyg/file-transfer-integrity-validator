import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import shutil
from src import checksum_utils, transfer_validator, config_manager
import webbrowser
import glob
from src import logger



class FileTransferGUI:
    def open_last_report(self):
      """Open the latest HTML report in the default browser."""
      report_files = glob.glob("reports/*.html")
      if not report_files:
          messagebox.showwarning("No Reports", "No HTML reports found in /reports folder.")
          return
      latest_report = max(report_files, key=os.path.getctime)
      webbrowser.open(f"file://{os.path.abspath(latest_report)}")

    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer Integrity Validator")
        self.root.geometry("700x400")

        self.log = logger.get_logger()

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

        # Open Last Report button
        ttk.Button(frame, text="📂 Open Last Report", command=self.open_last_report).pack(pady=5)


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

        # Build report data
        report_data = {}
        for i, (src_file, dest_file) in enumerate(files, start=1):
            rel_path = os.path.relpath(src_file, source)
            if rel_path in missing:
                report_data[rel_path] = "MISSING"
            elif rel_path in corrupted:
                report_data[rel_path] = "CORRUPTED"
            else:
                report_data[rel_path] = "OK"

        from src import report_generator
        reports = report_generator.generate_reports(report_data)

        # Final summary
        summary = (
            f"✅ Successful: {success_count}\n"
            f"⚠️ Corrupted: {len(corrupted)}\n"
            f"❌ Failed/Missing: {len(missing)}\n\n"
            f"Reports saved to:\n" + "\n".join(reports)
        )
        self.status_label.config(text="Transfer Complete")
        messagebox.showinfo("Transfer Summary", summary)

        self.log.info(f"Transfer Summary: Success={success_count}, Corrupted={len(corrupted)}, Missing={len(missing)}")


        # ---------------- VALIDATION TAB ----------------
    def build_validation_tab(self):
        frame = self.validation_tab

        # Source picker
        self.val_source_var = tk.StringVar()
        ttk.Label(frame, text="Source Folder:").pack(pady=5, anchor="w")
        source_frame = ttk.Frame(frame)
        source_frame.pack(fill="x", padx=10)
        ttk.Entry(source_frame, textvariable=self.val_source_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(source_frame, text="Browse", command=self.pick_val_source).pack(side="left", padx=5)

        # Destination picker
        self.val_dest_var = tk.StringVar()
        ttk.Label(frame, text="Destination Folder:").pack(pady=5, anchor="w")
        dest_frame = ttk.Frame(frame)
        dest_frame.pack(fill="x", padx=10)
        ttk.Entry(dest_frame, textvariable=self.val_dest_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(dest_frame, text="Browse", command=self.pick_val_dest).pack(side="left", padx=5)

        # Validate button
        ttk.Button(frame, text="Validate Transfer", command=self.start_validation).pack(pady=15)

        # Progress bar
        self.val_progress = ttk.Progressbar(frame, length=500, mode="determinate")
        self.val_progress.pack(pady=10)

        # Status label
        self.val_status_label = ttk.Label(frame, text="Status: Waiting")
        self.val_status_label.pack(pady=5)

        # Open Last Report button
        ttk.Button(frame, text="📂 Open Last Report", command=self.open_last_report).pack(pady=5)


    def pick_val_source(self):
        folder = filedialog.askdirectory(title="Select Source Folder")
        if folder:
            self.val_source_var.set(folder)

    def pick_val_dest(self):
        folder = filedialog.askdirectory(title="Select Destination Folder")
        if folder:
            self.val_dest_var.set(folder)

    def start_validation(self):
        source = self.val_source_var.get()
        dest = self.val_dest_var.get()

        if not source or not dest:
            messagebox.showerror("Error", "Please select both source and destination folders.")
            return

        threading.Thread(target=self.validate_folders, args=(source, dest), daemon=True).start()

    def validate_folders(self, source, dest):
        from src import transfer_validator

        self.val_status_label.config(text="Status: Validating...")
        self.val_progress["value"] = 0

        # Run validation
        missing, corrupted = transfer_validator.validate_transfer(source, dest)

        total = len(missing) + len(corrupted)
        self.val_progress["maximum"] = 100
        self.val_progress["value"] = 100  # instantly fill for now

        # Build report data
        report_data = {}
        for root, _, files in os.walk(source):
            for name in files:
                rel_path = os.path.relpath(os.path.join(root, name), source)
                if rel_path in missing:
                    report_data[rel_path] = "MISSING"
                elif rel_path in corrupted:
                    report_data[rel_path] = "CORRUPTED"
                else:
                    report_data[rel_path] = "OK"

        from src import report_generator
        reports = report_generator.generate_reports(report_data)

        # Summary popup
        summary = (
            f"⚠️ Corrupted: {len(corrupted)}\n"
            f"❌ Missing: {len(missing)}\n\n"
            f"Reports saved to:\n" + "\n".join(reports)
        )
        self.val_status_label.config(text="Validation Complete")
        messagebox.showinfo("Validation Summary", summary)

        self.log.info(f"Validation Summary: Corrupted={len(corrupted)}, Missing={len(missing)}")



        # Print details in terminal (for debugging)
        if missing:
            print("\n[MISSING FILES]")
            for f in missing:
                print(" -", f)
        if corrupted:
            print("\n[CORRUPTED FILES]")
            for f in corrupted:
                print(" -", f)


    # ---------------- SETTINGS TAB ----------------
    def build_settings_tab(self):
        ttk.Label(self.settings_tab, text="Settings Panel (Coming Soon)").pack(pady=20)

    # ---------------- LOGS TAB ----------------
    def build_logs_tab(self):
        frame = self.logs_tab

        ttk.Label(frame, text="Application Logs").pack(pady=5)

        self.log_text = tk.Text(frame, wrap="word", height=15, state="disabled")
        self.log_text.pack(expand=True, fill="both", padx=10, pady=10)

        ttk.Button(frame, text="🔄 Refresh Logs", command=self.load_logs).pack(pady=5)

    def load_logs(self):
        try:
            with open("logs/app.log", "r") as f:
                content = f.read()
        except FileNotFoundError:
            content = "No logs found yet."

        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, content)
        self.log_text.config(state="disabled")



if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferGUI(root)
    root.mainloop()
