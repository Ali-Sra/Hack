import os
import requests

def setup_directories():
    directories = ["database", "reports", "data"]
    for dir in directories:
        if not os.path.exists(dir):
            os.makedirs(dir)

def download_password_list():
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    response = requests.get(url)
    with open("data/passwords.txt", "w") as f:
        f.write(response.text)

if __name__ == "__main__":
    setup_directories()
    download_password_list()
    print("✅ تنظیمات اولیه انجام شد!")
