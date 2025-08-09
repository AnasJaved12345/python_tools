import os
import sys
import time
import json
import random
import string
import logging
from datetime import date, timedelta
import requests
from faker import Faker

# ---------------- CONFIG ----------------
EMAILS_FILE = "emails.txt"
PROXIES_FILE = "proxies.txt"
OUTPUT_FILE = "accounts.txt"
LOG_FILE = "signup_real.log"

API_SIGNUP_URL = "https://www.instagram.com/accounts/web_create_ajax/"
API_HEADERS = {
    "User-Agent": "Instagram 155.0.0.37.107 Android",
    "Accept": "*/*",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
}

USERNAME_TRIES = 6
COOLDOWN_AFTER = 5
COOLDOWN_MIN_SEC = 200
COOLDOWN_MAX_SEC = 300
DELAY_BETWEEN_ACCOUNTS = 12

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

fake = Faker()

# ---------------- File helpers ----------------
def ensure_files():
    for file in [EMAILS_FILE, PROXIES_FILE, OUTPUT_FILE]:
        if not os.path.exists(file):
            open(file, "w", encoding="utf-8").close()
            print(f"[i] Created {file}")

def read_emails():
    if os.path.getsize(EMAILS_FILE) == 0:
        print("[!] No emails found.")
        count = int(input("How many emails do you want to add? "))
        with open(EMAILS_FILE, "a", encoding="utf-8") as f:
            for _ in range(count):
                email = input("Enter email: ").strip()
                f.write(email + "\n")
    with open(EMAILS_FILE, "r", encoding="utf-8") as f:
        return [(line.strip(), "") for line in f if line.strip()]

def read_proxies():
    if not os.path.exists(PROXIES_FILE) or os.path.getsize(PROXIES_FILE) == 0:
        print("[i] No proxies found. Continuing without proxies.")
        return []
    with open(PROXIES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# ---------------- Generators ----------------
def gen_username():
    base = fake.user_name()
    suffix = str(random.randint(100, 9999))
    uname = (base + suffix).lower()
    allowed = set(string.ascii_lowercase + string.digits + "_.")
    return ''.join(ch for ch in uname if ch in allowed)[:30]

def gen_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return ''.join(random.choice(chars) for _ in range(length))

def gen_dob(min_age=13, max_age=18):
    today = date.today()
    start = today.replace(year=today.year - max_age)
    end = today.replace(year=today.year - min_age)
    days_range = (end - start).days
    rand = start + timedelta(days=random.randint(0, days_range))
    return rand.day, rand.month, rand.year

# ---------------- Core functions ----------------
class ProxyRotator:
    def __init__(self, proxies):
        self.proxies = proxies
        self.i = 0
    def next(self):
        if not self.proxies:
            return None
        p = self.proxies[self.i % len(self.proxies)]
        self.i += 1
        return p

def save_account(email, full_name, username, password, dob):
    line = f"{email} | {full_name} | {username} | {password} | DOB:{dob}\n"
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    logging.info(f"Account saved: {line.strip()}")

def create_account(email, password, proxy=None):
    full_name = fake.name()
    dob_day, dob_month, dob_year = gen_dob()
    chosen_username = None

    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None

    # Try usernames until one works
    for _ in range(USERNAME_TRIES):
        uname = gen_username()
        # In a real API flow, we'd check availability
        chosen_username = uname
        break

    if not chosen_username:
        logging.warning(f"No username for {email}")
        return False

    payload = {
        "email": email,
        "password": password,
        "username": chosen_username,
        "first_name": full_name,
        "day": dob_day,
        "month": dob_month,
        "year": dob_year
    }

    try:
        session = requests.Session()
        resp = session.post(API_SIGNUP_URL, headers=API_HEADERS, data=payload, proxies=proxies, timeout=20)
        if resp.status_code == 200:
            print(f"[+] Created account: {email} / {chosen_username}")
            dob_str = f"{dob_year:04d}-{dob_month:02d}-{dob_day:02d}"
            save_account(email, full_name, chosen_username, password, dob_str)
            return True
        else:
            logging.error(f"Signup failed for {email} - {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        logging.error(f"Error creating account {email}: {e}")
        return False

# ---------------- Main runner ----------------
def run():
    ensure_files()
    emails = read_emails()
    proxies = read_proxies()
    rotator = ProxyRotator(proxies)

    created = 0
    for idx, (email, passwd) in enumerate(emails, start=1):
        proxy = rotator.next()
        passwd = passwd or gen_password()
        print(f"\n[{idx}/{len(emails)}] Creating account for {email} using proxy: {proxy or 'None'}")
        ok = create_account(email, passwd, proxy)
        if ok:
            created += 1
        time.sleep(DELAY_BETWEEN_ACCOUNTS)

        if created > 0 and created % COOLDOWN_AFTER == 0:
            cooldown_time = random.randint(COOLDOWN_MIN_SEC, COOLDOWN_MAX_SEC)
            print(f"[!] Cooldown {cooldown_time}s...")
            time.sleep(cooldown_time)

if __name__ == "__main__":
    run()
