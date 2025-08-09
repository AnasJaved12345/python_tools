#!/usr/bin/env python3
"""
Safe Instagram Signup Simulation / Account-generation Framework (VPS-ready)

Purpose:
- Provide a headless, modular, VPS-capable script that generates usernames/passwords/DOBs,
  manages email/proxy/account files, rotates proxies, and simulates signup attempts.
- This script intentionally DOES NOT send requests to Instagram or any real signup endpoint.
  Instead it provides:
    * a dry-run simulation mode (default)
    * a local mock server client (simulated responses)
    * safe extension points (function stubs) where authorized integrations may be added.
- File management: creates emails.txt, proxies.txt, accounts.txt if missing
- Prompts user for emails when none exist
- Proxy rotation, user-agent rotation, cooldown, retries, detailed logging
- CLI interface with configuration options
- Comprehensive comments and extension guidance

Important:
- Do NOT use this script to perform unauthorized account creation.
- If you have a legitimate testing API or allowed endpoint, only then implement the
  `perform_signup_request(...)` stub following your legal / authorized workflow.

Author: Safe Example
"""

# Standard libs
import os
import sys
import time
import json
import random
import string
import logging
import argparse
import threading
from datetime import date, timedelta
from queue import Queue, Empty
from typing import Optional, Tuple, List, Dict

# Third-party libs (only lightweight and commonly allowed)
try:
    from faker import Faker
except Exception:
    print("[!] Missing dependency 'faker'. Install with: pip install Faker")
    sys.exit(1)

# ----------------------------
# Configuration / Defaults
# ----------------------------
APP_NAME = "safe_ig_sim"
VERSION = "1.0"
DEFAULT_EMAILS_FILE = "emails.txt"
DEFAULT_PROXIES_FILE = "proxies.txt"
DEFAULT_OUTPUT_FILE = "accounts.txt"
DEFAULT_LOG_FILE = "signup_sim.log"

# Behavior tuning (can be overridden via CLI)
DEFAULT_DELAY_BETWEEN_ACTIONS = 0.7
DEFAULT_DELAY_BETWEEN_ACCOUNTS = 12
DEFAULT_USERNAME_TRIES = 6
DEFAULT_COOLDOWN_AFTER = 5
DEFAULT_COOLDOWN_MIN_SEC = 200
DEFAULT_COOLDOWN_MAX_SEC = 300
DEFAULT_WORKER_THREADS = 2
DEFAULT_MAX_RETRIES = 3

# Safety flags
DRY_RUN_DEFAULT = True  # MUST be True by default

# Logging setup
logging.basicConfig(filename=DEFAULT_LOG_FILE,
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(threadName)s - %(message)s")
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(console)

# Fake data generator
fake = Faker()

# ----------------------------
# Utilities
# ----------------------------

def ensure_file_exists(path: str) -> None:
    """Create the file if it doesn't exist (empty)."""
    if not os.path.exists(path):
        open(path, "w", encoding="utf-8").close()
        logging.info("Created file: %s", path)

def read_lines_strip(path: str) -> List[str]:
    """Read non-empty lines from a file, stripped."""
    ensure_file_exists(path)
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    return lines

def write_line_append(path: str, line: str) -> None:
    """Append a line to a UTF-8 file safely."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")

def random_sleep(min_sec: float, max_sec: float) -> None:
    """Sleep for a random duration between min and max (sec)."""
    sec = random.uniform(min_sec, max_sec)
    time.sleep(sec)

def safe_print(*args, **kwargs):
    """Thread-safe print wrapper routed via logging."""
    logging.info(" ".join(str(a) for a in args))

# ----------------------------
# Generators
# ----------------------------

ALLOWED_USERNAME_CHARS = set(string.ascii_lowercase + string.digits + "_.")
PASSWORD_CHARS = string.ascii_letters + string.digits + "!@#$%^&*()-_"

def gen_username(base: Optional[str] = None, max_len: int = 30) -> str:
    """Generate a username with optional base seed."""
    if base:
        base_seed = "".join(ch for ch in base.lower() if ch in ALLOWED_USERNAME_CHARS)
    else:
        base_seed = fake.user_name()

    suffix = str(random.randint(100, 9999))
    uname = (base_seed + suffix)[:max_len]
    # sanitize
    uname = ''.join(ch for ch in uname if ch in ALLOWED_USERNAME_CHARS)
    if not uname:
        # fallback guaranteed valid username
        uname = "user" + suffix
    return uname

def gen_password(length: int = 12) -> str:
    """Generate a reasonably strong random password."""
    return ''.join(random.choice(PASSWORD_CHARS) for _ in range(length))

def gen_dob(min_age: int = 13, max_age: int = 18) -> Tuple[int, int, int]:
    """Generate a random date-of-birth with given age bounds."""
    today = date.today()
    # handle leap-day safely by clamping year only
    start_year = today.year - max_age
    end_year = today.year - min_age
    if start_year >= end_year:
        start_year = end_year - 1
    year = random.randint(start_year, end_year)
    month = random.randint(1, 12)
    # get day bound for month/year
    if month == 2:
        day = random.randint(1, 28)
    elif month in (4, 6, 9, 11):
        day = random.randint(1, 30)
    else:
        day = random.randint(1, 31)
    return day, month, year

# ----------------------------
# Proxy rotator
# ----------------------------

class ProxyRotator:
    def __init__(self, proxies: List[str]):
        self._proxies = proxies[:] if proxies else []
        self._i = 0
        self._lock = threading.Lock()

    def next(self) -> Optional[str]:
        with self._lock:
            if not self._proxies:
                return None
            p = self._proxies[self._i % len(self._proxies)]
            self._i += 1
            return p

    def add(self, proxy: str) -> None:
        with self._lock:
            self._proxies.append(proxy)

    def count(self) -> int:
        with self._lock:
            return len(self._proxies)

# ----------------------------
# Account storage and safe saving
# ----------------------------

def format_account_line(email: str, full_name: str, username: str, password: str, dob: Tuple[int,int,int]) -> str:
    dob_str = f"{dob[2]:04d}-{dob[1]:02d}-{dob[0]:02d}"
    return f"{email} | {full_name} | {username} | {password} | DOB:{dob_str}"

def save_account_record_safe(output_file: str, email: str, full_name: str, username: str, password: str, dob: Tuple[int,int,int]) -> None:
    line = format_account_line(email, full_name, username, password, dob)
    write_line_append(output_file, line)
    logging.info("Saved account record to %s: %s", output_file, line)

# ----------------------------
# Mock / Simulation Signup Client
# ----------------------------

class MockSignupResponse:
    def __init__(self, ok: bool, code: int, message: str, details: Optional[Dict] = None):
        self.ok = ok
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self):
        return {"ok": self.ok, "code": self.code, "message": self.message, "details": self.details}

class MockSignupClient:
    """
    Simulated signup client that mimics behavior of an API without contacting external services.

    Use this in DRY-RUN or when you're testing the generation, proxy rotation, retry, cooldown logic,
    or the filesystem/reporting pipeline.

    This client intentionally never makes network calls to Instagram or other third-party services.
    """

    def __init__(self, user_agents: List[str] = None):
        self.user_agents = user_agents or [
            "SafeSim/1.0 (linux) Faker",
            "SimAgent/2.1"
        ]
        self._seen_usernames = set()

    def check_username_available(self, username: str) -> bool:
        # Simulation rule: random chance of being taken, or if already seen
        if username in self._seen_usernames:
            return False
        # 25% chance of being taken
        if random.random() < 0.25:
            self._seen_usernames.add(username)
            return False
        return True

    def request_signup(self, payload: Dict, proxy: Optional[str] = None, timeout: int = 20) -> MockSignupResponse:
        """
        Simulate a signup request and return a MockSignupResponse.
        This includes simulated delays, captcha requirement, email OTP requirement, rate limits, or success.
        """

        # Simulate network latency (safe)
        simulated_latency = random.uniform(0.2, 1.6)
        time.sleep(simulated_latency)

        # Basic validation in simulation
        email = payload.get("email")
        username = payload.get("username")
        password = payload.get("password")
        full_name = payload.get("first_name")

        if not email or not username or not password:
            return MockSignupResponse(False, 400, "Missing required fields")

        # Simulate proxy failure chance
        if proxy and random.random() < 0.05:
            return MockSignupResponse(False, 502, "Proxy connection failed")

        # Simulate rate-limit behavior
        if random.random() < 0.03:
            # 429 often accompanied by Retry-After; include that in details
            return MockSignupResponse(False, 429, "Rate limited", {"retry_after": random.randint(5, 30)})

        # Simulate captcha needed scenario
        if random.random() < 0.06:
            return MockSignupResponse(False, 403, "CAPTCHA_REQUIRED", {"captcha_sitekey": "simulated-site-key"})

        # Simulate success
        # Register username as seen
        self._seen_usernames.add(username)
        account_id = "sim-" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        return MockSignupResponse(True, 201, "Account created (simulated)", {"account_id": account_id})

# ----------------------------
# High-level account processor
# ----------------------------

class AccountProcessor:
    """
    Core engine that:
      - reads emails & proxies
      - rotates proxies
      - generates usernames/passwords
      - performs simulated signup via MockSignupClient (safe)
      - records accounts on success
    """

    def __init__(self,
                 emails_file: str,
                 proxies_file: str,
                 output_file: str,
                 dry_run: bool = DRY_RUN_DEFAULT,
                 delay_between_actions: float = DEFAULT_DELAY_BETWEEN_ACTIONS,
                 delay_between_accounts: float = DEFAULT_DELAY_BETWEEN_ACCOUNTS,
                 username_tries: int = DEFAULT_USERNAME_TRIES,
                 cooldown_after: int = DEFAULT_COOLDOWN_AFTER,
                 cooldown_min: int = DEFAULT_COOLDOWN_MIN_SEC,
                 cooldown_max: int = DEFAULT_COOLDOWN_MAX_SEC,
                 max_retries: int = DEFAULT_MAX_RETRIES,
                 worker_threads: int = DEFAULT_WORKER_THREADS):
        self.emails_file = emails_file
        self.proxies_file = proxies_file
        self.output_file = output_file
        self.dry_run = dry_run
        self.delay_between_actions = delay_between_actions
        self.delay_between_accounts = delay_between_accounts
        self.username_tries = username_tries
        self.cooldown_after = cooldown_after
        self.cooldown_min = cooldown_min
        self.cooldown_max = cooldown_max
        self.max_retries = max_retries
        self.worker_threads = worker_threads

        # Load files
        ensure_file_exists(self.emails_file)
        ensure_file_exists(self.proxies_file)
        ensure_file_exists(self.output_file)

        self.emails = []  # list of tuples (email, optional_pass)
        self.proxies = []
        self.rotator = None
        self.mock_client = MockSignupClient()
        self.created_count = 0
        self.created_accounts = []
        self.queue = Queue()
        self._stop_event = threading.Event()

    def load_sources(self) -> None:
        logging.info("Loading emails and proxies from disk...")
        self.emails = []
        emails_raw = read_lines_strip(self.emails_file)
        for ln in emails_raw:
            # support optional password separated by colon "email:password"
            if ":" in ln:
                e, p = ln.split(":", 1)
                self.emails.append((e.strip(), p.strip()))
            else:
                self.emails.append((ln.strip(), ""))

        self.proxies = read_lines_strip(self.proxies_file)
        self.rotator = ProxyRotator(self.proxies)
        logging.info("Loaded %d emails and %d proxies", len(self.emails), len(self.proxies))

    def prompt_for_emails_if_empty(self) -> None:
        if not self.emails:
            safe_print("[!] No emails found in", self.emails_file)
            while True:
                try:
                    count = int(input("How many emails do you want to add now? (0 to exit) >>> ").strip())
                    if count < 0:
                        print("Enter 0 or a positive integer.")
                        continue
                    break
                except ValueError:
                    print("Please enter a valid integer.")
            if count == 0:
                logging.info("No emails provided. Exiting.")
                sys.exit(0)
            for i in range(count):
                email = input(f"Email #{i+1}: ").strip()
                if not email:
                    print("Skipping empty email.")
                    continue
                # optional pass
                passwd = input("Optional password for this email (press enter to generate later): ").strip()
                write_line_append(self.emails_file, f"{email}:{passwd}" if passwd else email)
            # reload
            self.load_sources()

    def worker_thread(self, thread_id: int) -> None:
        thread_name = f"Worker-{thread_id}"
        logging.info("[%s] Thread started", thread_name)
        while not self._stop_event.is_set():
            try:
                idx, email, supplied_pass = self.queue.get(timeout=1)
            except Empty:
                # if queue empty and producers done, exit
                if self.queue.empty():
                    break
                continue

            try:
                logging.info("[%s] Processing %s (index %d)", thread_name, email, idx)
                success = self.process_single_email(idx, email, supplied_pass)
                if success:
                    logging.info("[%s] SUCCESS %s", thread_name, email)
                else:
                    logging.info("[%s] FAILED %s", thread_name, email)
            except Exception as e:
                logging.exception("[%s] Exception processing %s: %s", thread_name, email, e)
            finally:
                self.queue.task_done()
        logging.info("[%s] Thread exiting", thread_name)

    def start_workers(self) -> None:
        threads = []
        for i in range(self.worker_threads):
            t = threading.Thread(target=self.worker_thread, args=(i+1,), daemon=True, name=f"Worker-{i+1}")
            t.start()
            threads.append(t)
        return threads

    def enqueue_all(self) -> None:
        for idx, (email, passwd) in enumerate(self.emails, start=1):
            self.queue.put((idx, email, passwd))

    def run(self) -> None:
        # load and prompt if needed
        self.load_sources()
        self.prompt_for_emails_if_empty()
        # enqueue jobs
        self.enqueue_all()
        # worker threads
        threads = self.start_workers()
        try:
            # wait until queue done
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)
                # optional: handle graceful shutdown on keyboard interrupt
        except KeyboardInterrupt:
            logging.info("Interrupted by user, signaling workers to stop...")
            self._stop_event.set()
        # wait for queue to be empty
        self.queue.join()
        logging.info("All tasks completed. Created %d accounts.", self.created_count)
        if self.created_accounts:
            logging.info("Created accounts (emails):")
            for e in self.created_accounts:
                logging.info(" - %s", e)

    def process_single_email(self, idx: int, email: str, supplied_pass: str) -> bool:
        """
        High-level flow:
          - generate password if not supplied
          - try username generation up to self.username_tries
          - for each attempt, call the 'perform_signup_request' (safe stub or simulation)
          - handle simulated errors like rate-limit, captcha, proxy failure
          - save account if success
          - apply cooldowns & delays
        """
        # generate core info
        full_name = fake.name()
        dob = gen_dob()
        password = supplied_pass if supplied_pass else gen_password()
        attempts = 0
        chosen_username = None
        last_error = None
        retries_left = self.max_retries

        while attempts < self.username_tries and retries_left > 0:
            attempts += 1
            uname = gen_username()
            # simulate username availability check via mock client
            if self.mock_client.check_username_available(uname):
                chosen_username = uname
                logging.info("[%d] Chose username %s for %s", idx, chosen_username, email)
                break
            else:
                logging.info("[%d] Username %s appears taken (simulated). Attempt %d/%d", idx, uname, attempts, self.username_tries)
                time.sleep(self.delay_between_actions)

        if not chosen_username:
            logging.warning("[%d] Could not select username for %s after %d attempts", idx, email, self.username_tries)
            return False

        # choose proxy
        proxy = self.rotator.next() if self.rotator else None
        logging.info("[%d] Using proxy: %s", idx, proxy or "None")

        # prepare payload
        payload = {
            "email": email,
            "password": password,
            "username": chosen_username,
            "first_name": full_name,
            "day": dob[0],
            "month": dob[1],
            "year": dob[2]
        }

        # Attempt simulated signup
        while retries_left > 0:
            retries_left -= 1
            response = self.perform_signup_request(payload, proxy)
            if response.ok:
                # success path
                save_account_record_safe(self.output_file, email, full_name, chosen_username, password, dob)
                self.created_count += 1
                self.created_accounts.append(email)
                # cooldowns
                if self.cooldown_after > 0 and (self.created_count > 0 and (self.created_count % self.cooldown_after) == 0):
                    cooldown_time = random.randint(self.cooldown_min, self.cooldown_max)
                    logging.info("Cooldown triggered after %d created accounts: sleeping %ds", self.created_count, cooldown_time)
                    # show countdown in console non-blocking
                    self.cooldown_countdown(cooldown_time)
                # polite pause between accounts
                logging.info("Sleeping %ss between accounts", self.delay_between_accounts)
                time.sleep(self.delay_between_accounts)
                return True
            else:
                # handle simulated errors
                last_error = response
                logging.info("Signup attempt failed (simulated): code=%s, msg=%s, details=%s", response.code, response.message, response.details)
                if response.code == 429:
                    # rate limited: obey retry_after if provided
                    retry_after = response.details.get("retry_after", random.randint(5, 30))
                    logging.warning("Rate limited: sleeping %ds before retry", retry_after)
                    time.sleep(retry_after)
                elif response.code == 403 and response.message == "CAPTCHA_REQUIRED":
                    # simulation: indicate manual resolution required
                    logging.warning("CAPTCHA required (simulated). Manual intervention needed.")
                    # in safe mode, do not attempt to solve. Return False so operator can investigate.
                    return False
                elif response.code in (502, 504):
                    # proxy/network error: try next proxy if available
                    logging.warning("Network/proxy error (simulated). Rotating proxy and retrying.")
                    proxy = self.rotator.next() if self.rotator else None
                    logging.info("New proxy: %s", proxy or "None")
                    time.sleep(1.0)
                else:
                    # other errors: small backoff then retry
                    backoff = random.uniform(1.0, 4.0)
                    logging.info("Backoff %0.1fs before retrying (simulated)", backoff)
                    time.sleep(backoff)

        logging.error("[%d] All retries exhausted for %s. Last error: %s", idx, email, last_error.message if last_error else "None")
        return False

    def perform_signup_request(self, payload: Dict, proxy: Optional[str] = None) -> MockSignupResponse:
        """
        THIS FUNCTION IS A SAFE SIMULATION / STUB.

        It intentionally does NOT contact Instagram or any external signup endpoint.
        Replace this method only if you have a legitimate, authorized test endpoint.
        """
        # If dry_run True, always use mock client
        if self.dry_run:
            return self.mock_client.request_signup(payload, proxy=proxy)

        # If not dry_run: still default to mock, but developers with explicit permission
        # can implement their own safe integration here. We strongly advise to only
        # integrate with endpoints you control or are authorized to use.

        # Example pseudo-logic for real integration (DO NOT implement unless authorized):
        #   - Build HTTP request with correct CSRF tokens and headers
        #   - Use a library that supports mobile API or official endpoints
        #   - Respect rate-limits, CAPTCHAs, & legal terms.
        # For the purpose of this safe demo, we still call the mock client.
        logging.warning("Non-dry-run attempted but not implemented: falling back to simulation to remain safe.")
        return self.mock_client.request_signup(payload, proxy=proxy)

    def cooldown_countdown(self, seconds: int) -> None:
        """Console countdown for cooldown periods without blocking logs."""
        safe_print(f"[!] Cooldown for {seconds // 60}m {seconds % 60}s. Sit tight.")
        for rem in range(seconds, 0, -1):
            m = rem // 60
            s = rem % 60
            print(f"Cooldown: {m:02d}:{s:02d} remaining", end="\r")
            time.sleep(1)
        print("\n[!] Cooldown finished. Resuming...")


# ----------------------------
# Command-line interface
# ----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP_NAME, description="Safe Instagram Signup Simulation Framework (dry-run by default)")
    p.add_argument("--emails", "-e", default=DEFAULT_EMAILS_FILE, help="path to emails file (default: emails.txt)")
    p.add_argument("--proxies", "-x", default=DEFAULT_PROXIES_FILE, help="path to proxies file (default: proxies.txt)")
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT_FILE, help="path to output accounts file (default: accounts.txt)")
    p.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="disable dry-run (NOT IMPLEMENTED: will still remain safe stub)")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY_BETWEEN_ACCOUNTS, help=f"delay between accounts in seconds (default: {DEFAULT_DELAY_BETWEEN_ACCOUNTS})")
    p.add_argument("--threads", type=int, default=DEFAULT_WORKER_THREADS, help=f"worker threads (default: {DEFAULT_WORKER_THREADS})")
    p.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help=f"max retries per signup (default: {DEFAULT_MAX_RETRIES})")
    p.add_argument("--version", action="store_true", help="print version and exit")
    return p

# ----------------------------
# Entry point
# ----------------------------

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{APP_NAME} {VERSION}")
        sys.exit(0)

    # Ensure files exist (create empty placeholders)
    ensure_file_exists(args.emails)
    ensure_file_exists(args.proxies)
    ensure_file_exists(args.output)

    logging.info("Starting %s v%s (dry_run=%s)", APP_NAME, VERSION, args.dry_run)
    # Print safe usage reminder prominently
    print("\n" + "="*60)
    print("SAFE SIGNUP SIMULATION FRAMEWORK — DRY-RUN MODE")
    print("This program WILL NOT perform real Instagram signups.")
    print("If you want to integrate a legitimate test API, edit 'perform_signup_request' carefully.")
    print("="*60 + "\n")

    processor = AccountProcessor(
        emails_file=args.emails,
        proxies_file=args.proxies,
        output_file=args.output,
        dry_run=args.dry_run,
        delay_between_accounts=args.delay,
        worker_threads=args.threads,
        max_retries=args.max_retries
    )

    # Load existing emails and proxies. If emails file empty, prompt user to add.
    processor.load_sources()
    processor.prompt_for_emails_if_empty()

    # Run main processing
    try:
        processor.run()
    except KeyboardInterrupt:
        logging.warning("Interrupted by user (main). Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
