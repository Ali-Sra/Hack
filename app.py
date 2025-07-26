from flask import Flask, render_template, request, send_file
import sqlite3
import subprocess
import pandas as pd
import os

app = Flask(__name__)

DB_FILE = "security_scan.db"

# بررسی و ایجاد پایگاه داده در صورت نیاز
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            report TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# دریافت آخرین نتایج اسکن
def get_latest_scans(limit=10):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT target, report, timestamp FROM scan_results ORDER BY id DESC LIMIT ?", (limit,))
    results = cursor.fetchall()
    conn.close()
    return results

# اجرای `secur1.py` و دریافت خروجی
def run_security_scan(target_url):
    try:
        result = subprocess.run(["python", "secur1.py", target_url], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"⚠️ خطا در اجرای برنامه: {str(e)}"

# ذخیره نتیجه اسکن در دیتابیس
def save_scan_result(target, report):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_results (target, report) VALUES (?, ?)", (target, report))
    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target_url = request.form.get("target_url")
        if target_url:
            report = run_security_scan(target_url)
            save_scan_result(target_url, report)
            return render_template("result.html", target=target_url, report=report)
    return render_template("index.html")

@app.route("/results")
def results():
    latest_scans = get_latest_scans()
    return render_template("results.html", scans=latest_scans)

# دانلود گزارش در قالب PDF با LibreOffice
@app.route("/download/pdf")
def download_pdf():
    latest_scans = get_latest_scans()

    # ساخت فایل HTML برای تبدیل به PDF
    html_file = "report.html"
    pdf_file = "report.pdf"

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(render_template("pdf_report.html", scans=latest_scans))

    # مسیر LibreOffice برای تبدیل HTML به PDF
    LIBREOFFICE_PATH = r"C:\Program Files\LibreOffice\program\soffice.exe"

    # اجرای LibreOffice برای تبدیل فایل HTML به PDF
    try:
        subprocess.run([LIBREOFFICE_PATH, "--headless", "--convert-to", "pdf", html_file], check=True)
    except subprocess.CalledProcessError as e:
        return f"⚠️ خطا در تبدیل به PDF: {str(e)}"

    return send_file(pdf_file, as_attachment=True)

# دانلود گزارش در قالب Excel
@app.route("/download/excel")
def download_excel():
    latest_scans = get_latest_scans()
    df = pd.DataFrame(latest_scans, columns=["آدرس", "گزارش", "زمان"])
    df.to_excel("report.xlsx", index=False)
    return send_file("report.xlsx", as_attachment=True)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
