import requests
import os

PASSWORD_LIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
HIDDEN_PATHS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

PASSWORD_LIST_FILE = "passwords.txt"
HIDDEN_PATHS_FILE = "hidden_paths.txt"

def download_file(url, filename):
    """ دانلود فایل‌های موردنیاز از اینترنت و ذخیره آن‌ها """
    if not os.path.exists(filename):
        print(f"🔹 دانلود {filename} ...")
        response = requests.get(url)
        if response.status_code == 200:
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"✅ {filename} با موفقیت دانلود شد.")
        else:
            print(f"❌ دانلود {filename} ناموفق بود.")
    else:
        print(f"✅ {filename} از قبل موجود است.")

# دانلود فایل‌های موردنیاز
download_file(PASSWORD_LIST_URL, PASSWORD_LIST_FILE)
download_file(HIDDEN_PATHS_URL, HIDDEN_PATHS_FILE)
