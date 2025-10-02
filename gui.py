import tkinter as tk
from tkinter import ttk

class FileTransferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer Integrity Validator")
        self.root.geometry("600x400")

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

        tk.Label(self.transfer_tab, text="File Transfer Interface").pack(pady=20)
        tk.Label(self.validation_tab, text="Validation Interface").pack(pady=20)
        tk.Label(self.settings_tab, text="Settings Panel").pack(pady=20)
        tk.Label(self.logs_tab, text="Logs Viewer").pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferGUI(root)
    root.mainloop()
