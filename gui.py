#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import shutil
import webbrowser
import glob
import subprocess

from src import checksum_utils, transfer_validator, config_manager, logger
from src import chain_logger, watchdog_monitor, signing, report_generator   # ✅ added imports
from src import policy_engine, content_inspector, alert_system, encryption, dlp_tracker


# GUI Application
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
        self.root.title("File Transfer Integrity Validator - DLP System")
        self.root.geometry("1000x600")
        self.root.configure(bg="#1e1e1e")  # dark theme

        # Logger
        self.log = logger.get_logger()

        # Load config
        try:
            self.config = config_manager.load_config()
        except Exception:
            # fallback defaults
            self.config = {
                "checksum_algorithm": "sha256",
                "report_formats": ["html", "csv", "json"],
                "log_level": "INFO",
                "user_role": "user"
            }
        
        # Initialize DLP components
        self.policy_engine = policy_engine.PolicyEngine(self.config)
        self.content_inspector = content_inspector.ContentInspector(self.config)
        self.alert_system = alert_system.AlertSystem(self.config)
        self.encryption_manager = encryption.EncryptionManager()
        self.dlp_tracker = dlp_tracker.DLPTracker()
        
        # Get user role
        self.user_role = self.config.get("user_role", "user")

        # ttk style
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff", font=("Segoe UI", 11))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.map("TButton", background=[("active", "#444444")])
        style.configure("TEntry", fieldbackground="#2b2b2b", foreground="#ffffff")
        style.configure("TProgressbar", troughcolor="#2d2d2d", background="#00c853")

        notebook = ttk.Notebook(root)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Tabs
        self.transfer_tab = ttk.Frame(notebook)
        self.validation_tab = ttk.Frame(notebook)
        self.settings_tab = ttk.Frame(notebook)
        self.logs_tab = ttk.Frame(notebook)

        notebook.add(self.transfer_tab, text="File Transfer")
        notebook.add(self.validation_tab, text="Validation")
        notebook.add(self.settings_tab, text="Settings")
        notebook.add(self.logs_tab, text="Logs")
        
        # Add DLP Dashboard tab
        self.dlp_tab = ttk.Frame(notebook)
        notebook.add(self.dlp_tab, text="DLP Dashboard")

        # Build tabs
        self.build_transfer_tab()
        self.build_validation_tab()
        self.build_settings_tab()
        self.build_logs_tab()
        self.build_dlp_tab()

    # ---------------- FILE TRANSFER TAB ----------------
    def build_transfer_tab(self):
        frame = self.transfer_tab

        ttk.Label(frame, text="File Transfer", style="Header.TLabel").pack(pady=8, anchor="w", padx=10)

        # Source picker
        self.source_var = tk.StringVar()
        ttk.Label(frame, text="Source Folder:").pack(pady=(6, 2), anchor="w", padx=10)
        source_frame = ttk.Frame(frame)
        source_frame.pack(fill="x", padx=10)
        ttk.Entry(source_frame, textvariable=self.source_var, width=60).pack(side="left", fill="x", expand=True)
        ttk.Button(source_frame, text="Browse", command=self.pick_source).pack(side="left", padx=6)

        # Destination picker
        self.dest_var = tk.StringVar()
        ttk.Label(frame, text="Destination Folder:").pack(pady=(8, 2), anchor="w", padx=10)
        dest_frame = ttk.Frame(frame)
        dest_frame.pack(fill="x", padx=10)
        ttk.Entry(dest_frame, textvariable=self.dest_var, width=60).pack(side="left", fill="x", expand=True)
        ttk.Button(dest_frame, text="Browse", command=self.pick_destination).pack(side="left", padx=6)

        # Controls
        ctrl_frame = ttk.Frame(frame)
        ctrl_frame.pack(fill="x", padx=10, pady=(12, 6))
        ttk.Button(ctrl_frame, text="Start Transfer", command=self.start_transfer).pack(side="left")
        ttk.Button(ctrl_frame, text="📂 Open Last Report", command=self.open_last_report).pack(side="left", padx=8)

        # Progress and status
        self.progress = ttk.Progressbar(frame, length=640, mode="determinate")
        self.progress.pack(pady=(8, 6), padx=10)
        self.status_label = ttk.Label(frame, text="Status: Waiting", foreground="yellow")
        self.status_label.pack(pady=(0, 10), anchor="w", padx=10)

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
        # Collect all user files (ignore hidden/system files)
        files = []
        for root_dir, _, filenames in os.walk(source):
            for name in filenames:
                if name.startswith("."):
                    continue  # ignore hidden files like .DS_Store
                src_file = os.path.join(root_dir, name)
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
        self.status_label.config(text=f"Transferring {total_files} files...", foreground="white")

        success_count = 0
        corrupted = []
        missing = []
        blocked = []  # DLP blocked files

        from src import watchdog_monitor, chain_logger
        def file_event(event, path):
            self.log.info(f"Watchdog: {event} detected on {path}")
            chain_logger.append_event("ALERT", f"File {event}: {path}")

        self.observer = watchdog_monitor.start_monitor(dest, file_event)

        for i, (src_file, dest_file) in enumerate(files, start=1):
            rel_path = os.path.relpath(src_file, source)
            
            # DLP Policy Check
            if self.policy_engine.is_policy_enabled():
                allowed, policy_msg = self.policy_engine.check_policy(src_file, dest)
                if not allowed:
                    blocked.append(rel_path)
                    self.log.warning(f"DLP BLOCK: {src_file} - {policy_msg}")
                    chain_logger.append_event("BLOCK", f"DLP Policy Violation: {src_file} - {policy_msg}")
                    self.dlp_tracker.log_violation(src_file, policy_msg, "BLOCK", {"destination": dest})
                    self.alert_system.send_alert("BLOCK", f"File transfer blocked: {os.path.basename(src_file)}\n{policy_msg}", 
                                                {"file": src_file, "destination": dest}, self.root)
                    self.progress["value"] = i
                    self.status_label.config(text=f"Transferred {i}/{total_files} files (Blocked: {len(blocked)})", foreground="orange")
                    self.root.update_idletasks()
                    continue
            
            # Content Inspection
            if self.content_inspector.is_inspection_enabled():
                safe, inspect_msg, findings = self.content_inspector.inspect_content(src_file)
                if not safe:
                    blocked.append(rel_path)
                    self.log.warning(f"DLP BLOCK: {src_file} - {inspect_msg}")
                    chain_logger.append_event("BLOCK", f"DLP Content Violation: {src_file} - {inspect_msg}")
                    self.dlp_tracker.log_violation(src_file, inspect_msg, "BLOCK", {"findings": findings})
                    self.alert_system.send_alert("BLOCK", f"Sensitive data detected: {os.path.basename(src_file)}\n{inspect_msg}", 
                                                {"file": src_file, "findings": findings}, self.root)
                    self.progress["value"] = i
                    self.status_label.config(text=f"Transferred {i}/{total_files} files (Blocked: {len(blocked)})", foreground="orange")
                    self.root.update_idletasks()
                    continue
            
            try:
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
            except Exception:
                # possible when dest path points to a root or invalid location; treat as missing
                missing.append(rel_path)
                self.progress["value"] = i
                self.status_label.config(text=f"Transferred {i}/{total_files} files", foreground="white")
                self.root.update_idletasks()
                continue

            try:
                # Check if encryption is needed
                should_encrypt = self.encryption_manager.should_encrypt_file(src_file, self.config)
                if should_encrypt:
                    # Encrypt before copying
                    encrypted_path = self.encryption_manager.encrypt_file(src_file)
                    shutil.copy2(encrypted_path, dest_file + ".encrypted")
                    os.remove(encrypted_path)  # Clean up temp encrypted file
                    dest_file = dest_file + ".encrypted"
                    self.log.info(f"Encrypted file: {src_file}")
                    # For encrypted files, verify the encrypted file integrity
                    # (we can't compare original vs encrypted, so we verify encrypted file exists and is valid)
                    if os.path.exists(dest_file) and os.path.getsize(dest_file) > 0:
                        success_count += 1
                    else:
                        corrupted.append(rel_path)
                else:
                    shutil.copy2(src_file, dest_file)

                    # Verify checksum (only for non-encrypted files)
                    algo = self.config.get("checksum_algorithm", "sha256")
                    if not checksum_utils.compare_files(src_file, dest_file, algo):
                        corrupted.append(rel_path)
                    else:
                        success_count += 1

            except Exception as e:
                # log exception details for debugging
                self.log.error(f"Error copying {src_file} -> {dest_file}: {e}")
                missing.append(rel_path)

            # Update progress bar
            self.progress["value"] = i
            self.status_label.config(text=f"Transferred {i}/{total_files} files", foreground="white")
            self.root.update_idletasks()

        # Build report data
        report_data = {}
        for src_file, _ in files:
            rel_path = os.path.relpath(src_file, source)
            if rel_path in blocked:
                report_data[rel_path] = "BLOCKED"
            elif rel_path in missing:
                report_data[rel_path] = "MISSING"
            elif rel_path in corrupted:
                report_data[rel_path] = "CORRUPTED"
            else:
                report_data[rel_path] = "OK"

        from src import report_generator
        formats = self.config.get("report_formats", ["html", "csv", "json"])
        reports = report_generator.generate_reports(report_data, formats=formats)

        from src import signing
        for r in reports: 
            signing.sign_report_file(r)

        # Final summary
        summary = (
            f"✅ Successful: {success_count}\n"
            f"🚫 Blocked (DLP): {len(blocked)}\n"
            f"⚠️ Corrupted: {len(corrupted)}\n"
            f"❌ Failed/Missing: {len(missing)}\n\n"
            f"Reports saved to:\n" + "\n".join(reports)
        )

        # update UI and log
        status_color = "green" if len(corrupted) == 0 and len(missing) == 0 and len(blocked) == 0 else ("orange" if len(corrupted) > 0 or len(blocked) > 0 else "red")
        self.status_label.config(text="Transfer Complete", foreground=status_color)
        # log before showing popup to ensure persistence
        self.log.info(f"Transfer Summary: Success={success_count}, Blocked={len(blocked)}, Corrupted={len(corrupted)}, Missing={len(missing)}")
        messagebox.showinfo("Transfer Summary", summary)

        from src import chain_logger
        chain_logger.append_event(
        "INFO",
        f"Transfer completed: Success={success_count}, Blocked={len(blocked)}, Corrupted={len(corrupted)}, Missing={len(missing)}"
        )
        if hasattr(self, "observer"):
            watchdog_monitor.stop_monitor(self.observer)

    # ---------------- VALIDATION TAB ----------------
    def build_validation_tab(self):
        frame = self.validation_tab
        ttk.Label(frame, text="Validation", style="Header.TLabel").pack(pady=8, anchor="w", padx=10)

        # source/dest pickers (same as your version)
        self.val_source_var = tk.StringVar()
        ttk.Label(frame, text="Source Folder:").pack(pady=(6, 2), anchor="w", padx=10)
        source_frame = ttk.Frame(frame)
        source_frame.pack(fill="x", padx=10)
        ttk.Entry(source_frame, textvariable=self.val_source_var, width=60).pack(side="left", fill="x", expand=True)
        ttk.Button(source_frame, text="Browse", command=self.pick_val_source).pack(side="left", padx=6)

        self.val_dest_var = tk.StringVar()
        ttk.Label(frame, text="Destination Folder:").pack(pady=(8, 2), anchor="w", padx=10)
        dest_frame = ttk.Frame(frame)
        dest_frame.pack(fill="x", padx=10)
        ttk.Entry(dest_frame, textvariable=self.val_dest_var, width=60).pack(side="left", fill="x", expand=True)
        ttk.Button(dest_frame, text="Browse", command=self.pick_val_dest).pack(side="left", padx=6)

        ctrl_frame = ttk.Frame(frame)
        ctrl_frame.pack(fill="x", padx=10, pady=(12, 6))
        ttk.Button(ctrl_frame, text="Validate Transfer", command=self.start_validation).pack(side="left")
        ttk.Button(ctrl_frame, text="📂 Open Last Report", command=self.open_last_report).pack(side="left", padx=8)

        self.val_progress = ttk.Progressbar(frame, length=640, mode="determinate")
        self.val_progress.pack(pady=(8, 6), padx=10)
        self.val_status_label = ttk.Label(frame, text="Status: Waiting", foreground="yellow")
        self.val_status_label.pack(pady=(0, 10), anchor="w", padx=10)

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
        self.val_status_label.config(text="Status: Validating...", foreground="white")
        self.val_progress["value"] = 0

        def file_event(event, path):
            self.log.info(f"Watchdog: {event} detected on {path}")
            chain_logger.append_event("ALERT", f"File {event}: {path}")

        # ✅ FIX: closed parenthesis
        self.observer = watchdog_monitor.start_monitor(dest, file_event)

        # Run validation
        missing, corrupted = transfer_validator.validate_transfer(source, dest)

        self.val_progress["maximum"] = 100
        self.val_progress["value"] = 100

        # Build report data (ignore hidden)
        report_data = {}
        for root_dir, _, files in os.walk(source):
            for name in files:
                if name.startswith("."):
                    continue
                rel_path = os.path.relpath(os.path.join(root_dir, name), source)
                if rel_path in missing:
                    report_data[rel_path] = "MISSING"
                elif rel_path in corrupted:
                    report_data[rel_path] = "CORRUPTED"
                else:
                    report_data[rel_path] = "OK"

        reports = report_generator.generate_reports(report_data, formats=self.config.get("report_formats", ["html", "csv", "json"]))
        for r in reports:
            signing.sign_report_file(r)

        summary = (
            f"⚠️ Corrupted: {len(corrupted)}\n"
            f"❌ Missing: {len(missing)}\n\n"
            f"Reports saved to:\n" + "\n".join(reports)
        )

        status_color = "green" if not corrupted and not missing else ("orange" if corrupted else "red")
        self.val_status_label.config(text="Validation Complete", foreground=status_color)
        self.log.info(f"Validation Summary: Corrupted={len(corrupted)}, Missing={len(missing)}")
        messagebox.showinfo("Validation Summary", summary)

        chain_logger.append_event("INFO", f"Validation completed: Corrupted={len(corrupted)}, Missing={len(missing)}")

        if hasattr(self, "observer"):
            watchdog_monitor.stop_monitor(self.observer)

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
        frame = self.settings_tab

        ttk.Label(frame, text="Settings", style="Header.TLabel").pack(pady=10, anchor="w", padx=10)
        
        # Role indicator
        role_label = ttk.Label(frame, text=f"Current Role: {self.user_role.upper()}", 
                               font=("Segoe UI", 9, "italic"), foreground="gray")
        role_label.pack(pady=(0, 10), anchor="w", padx=10)

        # ----- Checksum Algorithm -----
        ttk.Label(frame, text="Select Checksum Algorithm:").pack(pady=(6, 2), anchor="w", padx=10)

        self.checksum_var = tk.StringVar(value=self.config.get("checksum_algorithm", "sha256"))
        algo_dropdown = ttk.Combobox(
            frame,
            textvariable=self.checksum_var,
            values=["md5", "sha1", "sha256", "sha512"],
            state="readonly",
            width=20
        )
        algo_dropdown.pack(pady=5, padx=10)

        # Algorithm description box
        self.algo_desc = tk.Text(frame, height=6, wrap="word", bg="#151515", fg="#dcdcdc")
        self.algo_desc.pack(fill="x", padx=10, pady=(4, 8))
        self.algo_desc.insert(tk.END, self.get_algo_description(self.checksum_var.get()))
        self.algo_desc.config(state="disabled")

        # Update description when selection changes
        def on_algo_change(event):
            algo = self.checksum_var.get()
            desc = self.get_algo_description(algo)
            self.algo_desc.config(state="normal")
            self.algo_desc.delete(1.0, tk.END)
            self.algo_desc.insert(tk.END, desc)
            self.algo_desc.config(state="disabled")
        algo_dropdown.bind("<<ComboboxSelected>>", on_algo_change)

        # ----- Report Format Selection -----
        ttk.Label(frame, text="Select Report Formats:").pack(pady=(10, 4), anchor="w", padx=10)

        self.report_vars = {
            "html": tk.BooleanVar(value="html" in self.config.get("report_formats", [])),
            "csv": tk.BooleanVar(value="csv" in self.config.get("report_formats", [])),
            "json": tk.BooleanVar(value="json" in self.config.get("report_formats", [])),
        }

        chk_frame = ttk.Frame(frame)
        chk_frame.pack(padx=10, anchor="w")
        for fmt, var in self.report_vars.items():
            ttk.Checkbutton(chk_frame, text=fmt.upper(), variable=var).pack(side="left", padx=6)

        # Save button
        ttk.Button(frame, text="Save Settings", command=self.save_settings).pack(pady=12, padx=10, anchor="w")
        
        # DLP Settings (Admin only)
        if self.user_role == "admin":
            ttk.Separator(frame, orient="horizontal").pack(fill="x", padx=10, pady=(20, 10))
            ttk.Label(frame, text="DLP Policy Settings (Admin Only)", style="Header.TLabel").pack(pady=(10, 5), anchor="w", padx=10)
            
            # DLP Enabled checkbox
            self.dlp_enabled_var = tk.BooleanVar(value=self.config.get("dlp_policies", {}).get("enabled", False))
            ttk.Checkbutton(frame, text="Enable DLP Policies", variable=self.dlp_enabled_var).pack(pady=5, padx=10, anchor="w")
            
            # Content Inspection checkbox
            self.content_inspection_var = tk.BooleanVar(value=self.config.get("content_inspection", {}).get("enabled", False))
            ttk.Checkbutton(frame, text="Enable Content Inspection", variable=self.content_inspection_var).pack(pady=5, padx=10, anchor="w")
            
            # Encryption checkbox
            self.encryption_enabled_var = tk.BooleanVar(value=self.config.get("encryption", {}).get("enabled", False))
            ttk.Checkbutton(frame, text="Enable Encryption for Sensitive Files", variable=self.encryption_enabled_var).pack(pady=5, padx=10, anchor="w")
            
            # Desktop notifications checkbox
            self.desktop_notifications_var = tk.BooleanVar(value=self.config.get("alerts", {}).get("desktop_notifications", True))
            ttk.Checkbutton(frame, text="Enable Desktop Notifications", variable=self.desktop_notifications_var).pack(pady=5, padx=10, anchor="w")
            
            ttk.Button(frame, text="Save DLP Settings", command=self.save_dlp_settings).pack(pady=12, padx=10, anchor="w")
        
        # Test Files Reset Buttons
        ttk.Separator(frame, orient="horizontal").pack(fill="x", padx=10, pady=(20, 10))
        ttk.Label(frame, text="Test Files Management", style="Header.TLabel").pack(pady=(10, 5), anchor="w", padx=10)
        
        # DLP Test Files
        ttk.Label(frame, text="DLP Test Files (for DLP demo)", 
                  font=("Segoe UI", 9, "bold")).pack(pady=(5, 2), anchor="w", padx=10)
        ttk.Label(frame, text="Resets test_dlp_src and test_dlp_dst for DLP policy testing", 
                  font=("Segoe UI", 9), foreground="gray").pack(pady=(0, 5), anchor="w", padx=10)
        ttk.Button(frame, text="🔄 Reset DLP Test Files", command=self.reset_test_files).pack(pady=5, padx=10, anchor="w")
        
        # Integrity Test Files
        ttk.Label(frame, text="Integrity Test Files (for checksum validation)", 
                  font=("Segoe UI", 9, "bold")).pack(pady=(15, 2), anchor="w", padx=10)
        ttk.Label(frame, text="Resets tests/test_data/src and test_transfer for integrity/checksum testing", 
                  font=("Segoe UI", 9), foreground="gray").pack(pady=(0, 5), anchor="w", padx=10)
        ttk.Button(frame, text="🔄 Reset Integrity Test Files", command=self.reset_integrity_test_files).pack(pady=5, padx=10, anchor="w")

        # Status
        current = f"Algorithm: {self.checksum_var.get()}, Reports: {', '.join(self.config.get('report_formats', []))}"
        self.settings_status = ttk.Label(frame, text=current)
        self.settings_status.pack(pady=(0, 8), padx=10, anchor="w")

    def get_algo_description(self, algo):
        """Return a human-readable description for each checksum algorithm."""
        descriptions = {
            "md5": (
                "MD5 (128-bit): Fast but insecure.\n"
                "- Vulnerable to collisions\n"
                "- Use only for quick, non-critical checks\n"
                "- NOT recommended for security"
            ),
            "sha1": (
                "SHA-1 (160-bit): Slightly stronger than MD5 but also broken.\n"
                "- Practical collision attacks exist\n"
                "- Avoid for security use"
            ),
            "sha256": (
                "SHA-256 (256-bit): Secure and widely used.\n"
                "- Good balance of speed and strength\n"
                "- Recommended for file integrity validation"
            ),
            "sha512": (
                "SHA-512 (512-bit): Very strong but slower.\n"
                "- Best for high-security needs\n"
                "- Suitable for large files or compliance requirements"
            )
        }
        return descriptions.get(algo, "No description available.")

    def save_settings(self):
        # Save checksum algorithm
        new_algo = self.checksum_var.get()
        self.config["checksum_algorithm"] = new_algo

        # Save report formats
        selected_formats = [fmt for fmt, var in self.report_vars.items() if var.get()]
        if not selected_formats:
            selected_formats = ["html"]
        self.config["report_formats"] = selected_formats

        # Write to settings.json
        try:
            config_manager.save_config(self.config)
        except Exception as e:
            self.log.error(f"Failed to save config: {e}")
            messagebox.showerror("Error", "Failed to save settings.")
            return

        # Update status
        self.settings_status.config(
            text=f"Algorithm: {new_algo}, Reports: {', '.join(selected_formats)}"
        )

        # Log the change
        self.log.info(
            f"Settings updated: checksum_algorithm={new_algo}, report_formats={selected_formats}"
        )

        messagebox.showinfo("Settings Saved", f"Saved algorithm={new_algo}, reports={', '.join(selected_formats)}")
    
    def save_dlp_settings(self):
        """Save DLP settings (admin only)."""
        if self.user_role != "admin":
            messagebox.showerror("Access Denied", "Only administrators can modify DLP settings.")
            return
        
        # Update DLP policies
        if "dlp_policies" not in self.config:
            self.config["dlp_policies"] = {}
        self.config["dlp_policies"]["enabled"] = self.dlp_enabled_var.get()
        
        # Update content inspection
        if "content_inspection" not in self.config:
            self.config["content_inspection"] = {}
        self.config["content_inspection"]["enabled"] = self.content_inspection_var.get()
        
        # Update encryption
        if "encryption" not in self.config:
            self.config["encryption"] = {}
        self.config["encryption"]["enabled"] = self.encryption_enabled_var.get()
        
        # Update alerts
        if "alerts" not in self.config:
            self.config["alerts"] = {}
        self.config["alerts"]["desktop_notifications"] = self.desktop_notifications_var.get()
        
        # Reinitialize DLP components with new config
        self.policy_engine = policy_engine.PolicyEngine(self.config)
        self.content_inspector = content_inspector.ContentInspector(self.config)
        self.alert_system = alert_system.AlertSystem(self.config)
        
        # Save to file
        try:
            config_manager.save_config(self.config)
            messagebox.showinfo("DLP Settings Saved", "DLP settings have been updated successfully.")
            self.log.info("DLP settings updated by admin")
        except Exception as e:
            self.log.error(f"Failed to save DLP config: {e}")
            messagebox.showerror("Error", "Failed to save DLP settings.")
    
    def reset_test_files(self):
        """Reset DLP test files for fresh demo."""
        import subprocess
        import sys
        
        # Confirm action
        if not messagebox.askyesno("Reset DLP Test Files", 
                                   "This will remove and recreate test_dlp_src and test_dlp_dst directories.\n\n"
                                   "Continue?"):
            return
        
        try:
            # Run the reset command
            result = subprocess.run(
                [sys.executable, "test_dlp.py", "reset"],
                capture_output=True,
                text=True,
                cwd=os.getcwd()
            )
            
            if result.returncode == 0:
                messagebox.showinfo("Success", "DLP test files have been reset successfully!\n\n"
                                              "You can now run a fresh DLP demo.")
                self.log.info("DLP test files reset from GUI")
            else:
                messagebox.showerror("Error", f"Failed to reset DLP test files:\n{result.stderr}")
                self.log.error(f"DLP test files reset failed: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset DLP test files:\n{str(e)}")
            self.log.error(f"DLP test files reset exception: {e}")
    
    def reset_integrity_test_files(self):
        """Reset integrity test files for fresh checksum validation testing."""
        import subprocess
        import sys
        
        # Confirm action
        if not messagebox.askyesno("Reset Integrity Test Files", 
                                   "This will remove and recreate test files in:\n"
                                   "- tests/test_data/src\n"
                                   "- test_transfer\n\n"
                                   "Continue?"):
            return
        
        try:
            # Run the reset command
            result = subprocess.run(
                [sys.executable, "setup_integrity_tests.py", "reset"],
                capture_output=True,
                text=True,
                cwd=os.getcwd()
            )
            
            if result.returncode == 0:
                messagebox.showinfo("Success", "Integrity test files have been reset successfully!\n\n"
                                              "You can now test checksum validation:\n"
                                              "Source: tests/test_data/src\n"
                                              "Destination: test_transfer")
                self.log.info("Integrity test files reset from GUI")
            else:
                messagebox.showerror("Error", f"Failed to reset integrity test files:\n{result.stderr}")
                self.log.error(f"Integrity test files reset failed: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset integrity test files:\n{str(e)}")
            self.log.error(f"Integrity test files reset exception: {e}")

    # ---------------- LOGS TAB ----------------
    def build_logs_tab(self):
        frame = self.logs_tab

        ttk.Label(frame, text="Application Logs", style="Header.TLabel").pack(pady=8, anchor="w", padx=10)

        self.log_text = tk.Text(frame, wrap="word", height=18, state="disabled", bg="#151515", fg="#dcdcdc")
        self.log_text.pack(expand=True, fill="both", padx=10, pady=6)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=(0, 10), padx=10, anchor="w")
        ttk.Button(btn_frame, text="🔄 Refresh Logs", command=self.load_logs).pack(side="left")
        ttk.Button(btn_frame, text="📁 Open Log Folder", command=self.open_log_folder).pack(side="left", padx=8)
        ttk.Button(btn_frame, text="🔗 Verify Chain", command=self.verify_chain_integrity).pack(side="left", padx=8)

        # Load logs once at startup
        self.load_logs()

    def verify_chain_integrity(self):
        from src import chain_logger
        ok, message = chain_logger.verify_chain()
        if ok:
            messagebox.showinfo("Chain Verification", f"✅ {message}")
            self.log.info(f"Chain verification success: {message}")
        else:
            messagebox.showerror("Chain Verification", f"❌ {message}")
            self.log.error(f"Chain verification failed: {message}")
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

    def open_log_folder(self):
        os.makedirs("logs", exist_ok=True)
        folder = os.path.abspath("logs")
        try:
            if os.name == "nt":
                os.startfile(folder)
            else:
                # macOS / Linux
                import subprocess
                subprocess.run(["open", folder], check=False)
        except Exception:
            # fallback: message with path
            messagebox.showinfo("Logs Folder", f"Logs are at: {folder}")

    # ---------------- DLP DASHBOARD TAB ----------------
    def build_dlp_tab(self):
        frame = self.dlp_tab
        
        ttk.Label(frame, text="DLP Dashboard", style="Header.TLabel").pack(pady=8, anchor="w", padx=10)
        
        # Statistics frame
        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.dlp_stats_label = ttk.Label(stats_frame, text="Loading statistics...", font=("Segoe UI", 10))
        self.dlp_stats_label.pack(anchor="w")
        
        # Violations list
        ttk.Label(frame, text="Recent Violations:", font=("Segoe UI", 11, "bold")).pack(pady=(10, 5), anchor="w", padx=10)
        
        # Treeview for violations
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Treeview
        self.violations_tree = ttk.Treeview(
            tree_frame,
            columns=("Timestamp", "File", "Type", "Reason"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=15
        )
        scrollbar.config(command=self.violations_tree.yview)
        
        # Configure columns
        self.violations_tree.heading("Timestamp", text="Timestamp")
        self.violations_tree.heading("File", text="File")
        self.violations_tree.heading("Type", text="Type")
        self.violations_tree.heading("Reason", text="Reason")
        
        self.violations_tree.column("Timestamp", width=180)
        self.violations_tree.column("File", width=300)
        self.violations_tree.column("Type", width=80)
        self.violations_tree.column("Reason", width=400)
        
        self.violations_tree.pack(side="left", fill="both", expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=(0, 10), padx=10, anchor="w")
        ttk.Button(btn_frame, text="🔄 Refresh", command=self.refresh_dlp_dashboard).pack(side="left")
        if self.user_role == "admin":
            ttk.Button(btn_frame, text="🗑️ Clear All", command=self.clear_dlp_violations).pack(side="left", padx=8)
        
        # Load initial data
        self.refresh_dlp_dashboard()
    
    def refresh_dlp_dashboard(self):
        """Refresh DLP dashboard with latest violations."""
        stats = self.dlp_tracker.get_statistics()
        stats_text = (
            f"Total Violations: {stats['total']} | "
            f"Blocks: {stats['blocks']} | "
            f"Warnings: {stats['warnings']} | "
            f"Today: {stats['today']}"
        )
        self.dlp_stats_label.config(text=stats_text)
        
        # Clear existing items
        for item in self.violations_tree.get_children():
            self.violations_tree.delete(item)
        
        # Load recent violations
        violations = self.dlp_tracker.get_recent_violations(limit=100)
        for violation in reversed(violations):  # Show newest first
            timestamp = violation.get("timestamp", "")
            # Format timestamp for display
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
            
            filepath = violation.get("filepath", "")
            # Show only filename if path is too long
            if len(filepath) > 50:
                filepath = "..." + filepath[-47:]
            
            violation_type = violation.get("type", "UNKNOWN")
            reason = violation.get("reason", "")
            if len(reason) > 60:
                reason = reason[:57] + "..."
            
            self.violations_tree.insert(
                "",
                "end",
                values=(timestamp, filepath, violation_type, reason)
            )
    
    def clear_dlp_violations(self):
        """Clear all DLP violations (admin only)."""
        if self.user_role != "admin":
            messagebox.showerror("Access Denied", "Only administrators can clear violations.")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all DLP violations?"):
            self.dlp_tracker.clear_violations()
            self.refresh_dlp_dashboard()
            messagebox.showinfo("Success", "All violations cleared.")
            self.log.info("DLP violations cleared by admin")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferGUI(root)
    root.mainloop()
