import json
import csv
import os

def generate_json_report(report_data, output_file="report.json"):
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

def generate_csv_report(report_data, output_file="report.csv"):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Status"])
        for file, status in report_data.items():
            writer.writerow([file, status])

def generate_html_report(report_data, output_file="report.html"):
    with open(output_file, "w") as f:
        f.write("<html><head><title>Transfer Report</title></head><body>")
        f.write("<h1>File Transfer Integrity Report</h1><ul>")
        for file, status in report_data.items():
            f.write(f"<li>{file}: {status}</li>")
        f.write("</ul></body></html>")
