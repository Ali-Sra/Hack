import requests
import socket
import subprocess
import os
import json
import sqlite3
import random
import time
from prettytable import PrettyTable
from fake_useragent import UserAgent

# تنظیمات اولیه
DB_FILE = "security_scan.db"
LOG_FILE = "log.json"
UA = UserAgent()
HEADERS = {"User-Agent": UA.random}
SENSITIVE_PATHS = [
    "robots.txt", "admin/", "login/", "config.php", "backup/", 
    ".git/", ".env", "wp-admin/", "wp-login.php"
]
PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}  # برای استفاده از Tor در صورت نیاز

# بررسی DNS قبل از اجرای تست‌ها
def check_dns_resolution(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

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

# ذخیره نتایج
def save_to_db(target, report):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_results (target, report) VALUES (?, ?)", (target, report))
    conn.commit()
    conn.close()

# بررسی مسیرهای حساس
def check_sensitive_paths(target_url):
    results = []
    for path in SENSITIVE_PATHS:
        url = f"{target_url}/{path}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                results.append(f"⚠️ {url} در دسترس است. ممکن است اطلاعات حساس افشا شود.")
        except requests.exceptions.RequestException:
            continue
    return "\n".join(results) if results else "✅ مسیرهای حساس ایمن هستند."

# بررسی SQL Injection
def check_sql_injection(target_url):
    payloads = ["' OR '1'='1 --", "' UNION SELECT NULL, NULL, NULL --"]
    for payload in payloads:
        try:
            response = requests.get(f"{target_url}?id={payload}", headers=HEADERS, timeout=10)
            if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
                return f"⚠️ سایت ممکن است به SQL Injection آسیب‌پذیر باشد (payload: {payload})"
        except requests.exceptions.RequestException:
            continue
    return "✅ سایت در برابر SQL Injection ایمن است."

# بررسی Brute Force
def check_brute_force(target_url):
    usernames = ["admin", "user", "test"]
    passwords = ["123456", "password", "admin123"]
    for user in usernames:
        for pwd in passwords:
            data = {"username": user, "password": pwd}
            try:
                response = requests.post(target_url, data=data, headers=HEADERS, timeout=10)
                if "incorrect password" not in response.text.lower():
                    return f"⚠️ احتمال حمله Brute Force روی {target_url}"
            except requests.exceptions.RequestException:
                continue
    return "✅ سایت در برابر Brute Force ایمن است."

# بررسی SSL/TLS Configuration
def check_ssl_tls(target_url):
    try:
        result = subprocess.run(["sslscan", target_url], capture_output=True, text=True)
        return f"🔍 گزارش SSL/TLS:\n{result.stdout}"
    except FileNotFoundError:
        return "❌ ابزار sslscan نصب نیست."

# اجرای تست امنیتی کامل
def run_security_scan(target_url):
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    domain = target_url.replace("http://", "").replace("https://", "").split("/")[0]
    resolved_ip = check_dns_resolution(domain)
    
    if resolved_ip is None:
        print(f"[❌] نمی‌توان DNS را برای {domain} حل کرد. ممکن است سایت از فایروال استفاده کند.")
        return
    
    results = [
        check_sensitive_paths(target_url),
        check_sql_injection(target_url),
        check_brute_force(target_url),
        check_ssl_tls(target_url)
    ]

    report = "\n".join(results)
    save_to_db(target_url, report)
    
    # نمایش نتایج
    table = PrettyTable(["آیتم", "وضعیت"])
    for result in results:
        table.add_row([result.split(" ")[0], result])
    print(table)

    return report

if __name__ == "__main__":
    init_db()
    target_url = input("🔹 آدرس سایت موردنظر را وارد کنید: ")
    report = run_security_scan(target_url)
    print(report)
