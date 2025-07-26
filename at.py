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

def run_nmap(target):
    nmap_cmd = f"nmap -sV -p 21,22,80,443,8080 {target}"
    print(f"Running: {nmap_cmd}")
    result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def run_hydra(url, username, password_list):
    hydra_cmd = f"hydra -l {username} -P {password_list} {url} http-post-form \"/wp-login.php:log=^USER^&pwd=^PASS^:incorrect\""
    print(f"Running: {hydra_cmd}")
    result = subprocess.run(hydra_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def run_directory_bruteforce(url, wordlist):
    dirb_cmd = f"gobuster dir -u {url} -w {wordlist}"
    print(f"Running: {dirb_cmd}")
    result = subprocess.run(dirb_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def run_instagram_osint(username):
    instaloader_cmd = f"instaloader --no-pictures --no-videos --login YOUR_USERNAME {username}"
    print(f"Running: {instaloader_cmd}")
    result = subprocess.run(instaloader_cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("=" * 50)

def main():
    url = input("Enter target URL (e.g., http://example.com): ")
    api_key = input("Enter WPScan API Key (optional): ") or None
    target_ip = input("Enter target IP for Nmap scan (optional, press enter to skip): ")
    username = input("Enter username for Brute Force test (optional, press enter to skip): ")
    insta_user = input("Enter Instagram username for OSINT (optional, press enter to skip): ")
    password_list = "passwords.txt"
    wordlist = "wordlist.txt"
    
    print("\n[1] Running WPScan for WordPress Security Scan...")
    run_wpscan(url, api_key)
    
    print("\n[2] Running SQL Injection Test with SQLMap...")
    run_sqlmap(url)
    
    if target_ip:
        print("\n[3] Running Nmap Scan...")
        run_nmap(target_ip)
    
    if username:
        print("\n[4] Running Brute Force Attack with Hydra...")
        run_hydra(url, username, password_list)
    
    print("\n[5] Running Directory Bruteforce with Gobuster...")
    run_directory_bruteforce(url, wordlist)
    
    if insta_user:
        print("\n[6] Running Instagram OSINT with Instaloader...")
        run_instagram_osint(insta_user)
    
    print("\nSecurity scan completed!")
    
if __name__ == "__main__":
    main()
