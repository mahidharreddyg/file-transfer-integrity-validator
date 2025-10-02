import json
import csv
import os
from datetime import datetime

def _timestamped_filename(prefix, extension):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join("reports", f"{prefix}_{ts}.{extension}")

def generate_json_report(report_data):
    os.makedirs("reports", exist_ok=True)
    file_path = _timestamped_filename("report", "json")
    with open(file_path, "w") as f:
        json.dump(report_data, f, indent=4)
    return file_path

def generate_csv_report(report_data):
    os.makedirs("reports", exist_ok=True)
    file_path = _timestamped_filename("report", "csv")
    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Status"])
        for file, status in report_data.items():
            writer.writerow([file, status])
    return file_path

def generate_html_report(report_data):
    os.makedirs("reports", exist_ok=True)
    file_path = _timestamped_filename("report", "html")
    with open(file_path, "w") as f:
        f.write("<html><head><title>Transfer Report</title></head><body>")
        f.write("<h1>File Transfer Integrity Report</h1>")
        f.write("<table border='1' cellpadding='5'>")
        f.write("<tr><th>File</th><th>Status</th></tr>")
        for file, status in report_data.items():
            color = "green" if status == "OK" else ("red" if status == "MISSING" else "orange")
            f.write(f"<tr><td>{file}</td><td style='color:{color}'>{status}</td></tr>")
        f.write("</table></body></html>")
    return file_path

def generate_reports(report_data, formats=("html", "csv", "json")):
    """Generate multiple report formats. Returns list of file paths."""
    files = []
    if "json" in formats:
        files.append(generate_json_report(report_data))
    if "csv" in formats:
        files.append(generate_csv_report(report_data))
    if "html" in formats:
        files.append(generate_html_report(report_data))
    return files
