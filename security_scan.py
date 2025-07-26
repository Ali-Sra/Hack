import requests
import socket
import subprocess
import os
import json
import sqlite3
from prettytable import PrettyTable

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
REPORT_FILE = "security_report.txt"
DB_FILE = "security_scan.db"
LOG_FILE = "log.json"
WORDPRESS_PATHS = [
    "readme.html", "wp-includes/version.php", "wp-content/plugins/",
    "wp-login.php", "wp-admin/", "wp-json/wp/v2/", "xmlrpc.php"
]

# ایجاد پایگاه داده
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

# ذخیره نتایج در پایگاه داده
def save_to_db(target, report):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_results (target, report) VALUES (?, ?)", (target, report))
    conn.commit()
    conn.close()

# ذخیره لاگ به صورت JSON
def save_log(target, report):
    log_data = {}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                log_data = json.load(f)
            except json.JSONDecodeError:
                log_data = {}
    log_data[target] = report
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=4, ensure_ascii=False)

# بررسی آسیب‌پذیری‌های وردپرس
def check_wordpress_vulnerabilities(target_url):
    results = []
    for path in WORDPRESS_PATHS:
        url = f"{target_url}/{path}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            results.append(f"⚠️ {url} در دسترس است، ممکن است اطلاعات حساس فاش شود.")
    return "\n".join(results) if results else "✅ به نظر می‌رسد که وردپرس پیکربندی ایمن دارد."

# بررسی نسخه وردپرس
def check_wordpress_version(target_url):
    url = f"{target_url}/readme.html"
    response = requests.get(url, headers=HEADERS, timeout=10)
    if response.status_code == 200 and "WordPress" in response.text:
        version = response.text.split("WordPress ")[1].split()[0]
        return f"⚠️ نسخه وردپرس پیدا شد: {version}"
    return "✅ نسخه وردپرس در دسترس عموم نیست."

# بررسی XML-RPC برای حملات
def check_xmlrpc(target_url):
    url = f"{target_url}/xmlrpc.php"
    response = requests.get(url, headers=HEADERS, timeout=10)
    if response.status_code == 200 and "XML-RPC server accepts POST requests" in response.text:
        return "⚠️ XML-RPC فعال است. ممکن است برای حملات Brute Force استفاده شود."
    return "✅ XML-RPC غیرفعال است."

# بررسی هدرهای امنیتی HTTP
def check_security_headers(target_url):
    response = requests.get(target_url, headers=HEADERS, timeout=10)
    security_headers = {
        "Content-Security-Policy": "CSP محافظت را کاهش می‌دهد.",
        "X-Frame-Options": "امکان کلیک‌جکینگ وجود دارد.",
        "Strict-Transport-Security": "HSTS فعال نیست.",
        "X-Content-Type-Options": "محافظت از MIME Sniffing غیرفعال است."
    }
    issues = []
    for header, message in security_headers.items():
        if header not in response.headers:
            issues.append(f"⚠️ {header} وجود ندارد: {message}")
    return "\n".join(issues) if issues else "✅ هدرهای امنیتی مناسب تنظیم شده‌اند."

# اجرای WPScan برای بررسی پلاگین‌های وردپرس
def run_wpscan(target_url):
    try:
        result = subprocess.run(["wpscan", "--url", target_url, "--enumerate", "vp"], capture_output=True, text=True)
        return result.stdout if result.stdout else "✅ هیچ پلاگین آسیب‌پذیری یافت نشد."
    except FileNotFoundError:
        return "❌ WPScan نصب نشده است."

# اجرای تست امنیتی کامل
def run_security_scan(target_url):
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    
    try:
        target_ip = socket.gethostbyname(target_url.replace("http://", "").replace("https://", ""))
    except socket.gaierror:
        return f"[❌] نمی‌توان IP را برای {target_url} دریافت کرد."
    
    results = [
        check_wordpress_version(target_url),
        check_wordpress_vulnerabilities(target_url),
        check_xmlrpc(target_url),
        check_security_headers(target_url),
        run_wpscan(target_url)
    ]
    
    report = "\n".join(results)
    save_to_db(target_url, report)
    save_log(target_url, report)
    
    # نمایش نتایج با جدول زیباتر
    table = PrettyTable(["آیتم", "وضعیت"])
    for result in results:
        table.add_row([result.split(" ")[0], result])
    print(table)
    
    return report

if __name__ == "__main__":
    init_db()
    target_url = input("🔹 آدرس سایت وردپرسی را وارد کنید: ")
    report = run_security_scan(target_url)
    print(report)
