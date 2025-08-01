# 🔐 WordPress Vulnerability Scanner Web App

This project is a complete **security scanning web application** built with Python and Flask, designed to identify common vulnerabilities in WordPress websites. It integrates multiple tools such as **WPScan**, **SQLMap**, and **Hydra**, and supports exporting reports in **PDF** and **Excel** format. All scanned results are stored in a local **SQLite database**.

---

## 🚀 Features

✅ Scan any WordPress target URL via the web interface  
✅ Detect vulnerabilities in:
- WordPress core version
- Plugins
- XML-RPC exposure
- HTTP security headers  
✅ Optional brute force testing with Hydra  
✅ SQL injection testing using SQLMap  
✅ WPScan integration with API key support  
✅ Save scan results into SQLite  
✅ Export reports as:
- 📄 PDF (converted via LibreOffice)
- 📊 Excel (via `pandas`)  
✅ Web interface to view latest 10 scans  
✅ Pretty console output using `PrettyTable`

---

## 🌐 Web Interface

- **Flask App** serves a simple web UI.
- Users enter a URL and receive a detailed scan result.
- PDF and Excel download options are available.

**Endpoints:**
| Route              | Functionality                    |
|-------------------|----------------------------------|
| `/`               | Enter target and start scan      |
| `/results`        | View last 10 scan results        |
| `/download/pdf`   | Export latest scan as PDF        |
| `/download/excel` | Export latest scan as Excel file |

---

## 🛠 Tools Used

- `Flask` – Web framework  
- `sqlite3` – Embedded database for results  
- `pandas` – For Excel export  
- `WPScan` – WordPress vulnerability scanner  
- `SQLMap` – SQL injection automation tool  
- `Hydra` – Brute force attack tool  
- `LibreOffice` – Converts HTML to PDF  
- `PrettyTable` – Console output formatting

---

## 📁 Project Structure

project/
├── app.py # Flask app (web interface)
├── secur1.py # Core scanner logic
├── database.db # SQLite DB file
├── log.json # JSON log of scanned results
├── passwords.txt # Password list for Hydra
├── templates/ # HTML templates (index, result, report)
├── static/ # CSS/JS assets
├── report.xlsx # Excel export
├── report.pdf # PDF export
├── scan_results.csv # Optional output
├── setup.py # Script setup or config
└── other test files # test1.py, test2.py, ...

#install
pip install flask pandas prettytable requests
python app.py
python secur1.py




yaml
Kopieren
Bearbeiten
#   H a c k  
 