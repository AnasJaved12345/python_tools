#!/usr/bin/env python3
"""
https443_proxy_generator.py

Generates a list of working HTTPS proxies on port 443 only.
- Scrapes multiple free proxy-list sources (HTML table parsers + text lists)
- Strict validation:
    * HTTPS protocol only
    * Port == 443 only
    * Latency < max_latency_ms (default 300ms)
- Concurrent testing via aiohttp
- Rotating user agents
- Exponential backoff for retries
- Exports results to TXT and JSON
- Logging and configurable parameters via CLI
- Basic anonymity check and IP reputation scoring (local heuristics; optional external API hooks)

Usage:
    python https443_proxy_generator.py --concurrency 100 --max-latency 300 --out-json good_proxies.json --out-txt good_proxies.txt

Author: (Generated) - adapt and extend as needed
"""
import asyncio
import aiohttp
import argparse
import logging
import random
import time
import json
import re
import sys
import socket
from typing import List, Dict, Any, Optional
import requests

# ------------------------------
# Config & Defaults
# ------------------------------
DEFAULT_TIMEOUT = 8  # seconds per request to proxy
DEFAULT_CONCURRENCY = 80
DEFAULT_MAX_LATENCY_MS = 300
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_FACTOR = 1.5
TEST_URL = "https://httpbin.org/get"  # returns origin + headers (good for anonymity checks)
LOCAL_IP_CHECK_URL = "https://api.ipify.org"  # to learn our outward IP
USER_AGENTS = [
    # A short rotating list; expand as needed
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)",
]

# Sites to scrape (public free lists). They sometimes change structure; code aims to handle common structures.
PROXY_SOURCES = [
    "https://www.sslproxies.org/",          # table of ssl proxies (HTTPS)
    "https://free-proxy-list.net/https",    # table filtered for HTTPS
    "https://www.proxy-list.download/HTTPS",# text/CSV style
    # Add other known sources if needed
]

# ------------------------------
# Utilities
# ------------------------------
logger = logging.getLogger("proxygen")
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

def parse_ip_port(line: str) -> Optional[Dict[str,str]]:
    """
    Attempt to parse "ip:port" string from a line.
    """
    line = line.strip()
    m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})\s*[:,]\s*(\d{1,5})", line)
    if m:
        ip = m.group(1).strip()
        port = m.group(2).strip()
        return {"ip": ip, "port": port}
    return None

def is_valid_ipv4(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        parts = list(map(int, ip.split(".")))
        return all(0 <= p <= 255 for p in parts)
    except Exception:
        return False

# ------------------------------
# Scrapers
# ------------------------------
def scrape_source_requests(url: str, timeout: int = 10) -> List[Dict[str,str]]:
    """
    Fetch a source and extract ip:port pairs using common table parsing heuristics or raw text.
    This is a best-effort scraper for public free lists. Sites vary in layout; extend parsers if necessary.
    """
    logger.debug(f"Scraping {url}")
    try:
        resp = requests.get(url, headers=get_headers(), timeout=timeout)
        text = resp.text
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return []

    proxies = []

    # Attempt: HTML table rows with ip & port in separate <td>
    # A simple regex to capture table rows with <td>ip</td><td>port</td>
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", text, flags=re.S | re.I)
    for r in rows:
        # find all <td>...</td>
        tds = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", r, flags=re.S | re.I)
        if len(tds) >= 2:
            ip_candidate = re.sub(r"<.*?>", "", tds[0]).strip()
            port_candidate = re.sub(r"<.*?>", "", tds[1]).strip()
            if is_valid_ipv4(ip_candidate) and port_candidate.isdigit():
                proxies.append({"ip": ip_candidate, "port": port_candidate})
    if proxies:
        logger.info(f"Scraped {len(proxies)} proxies (table parser) from {url}")
        return proxies

    # Fallback: find ip:port anywhere in page
    pairs = re.findall(r"((?:\d{1,3}\.){3}\d{1,3})[:,]\s*(\d{1,5})", text)
    for ip, port in pairs:
        if is_valid_ipv4(ip) and port.isdigit():
            proxies.append({"ip": ip, "port": port})
    if proxies:
        logger.info(f"Scraped {len(proxies)} proxies (fallback regex) from {url}")
    else:
        logger.info(f"No proxies found on {url}")
    return proxies

def aggregate_proxies_from_sources(sources: List[str]) -> List[Dict[str,str]]:
    found = []
    seen = set()
    for url in sources:
        try:
            scraped = scrape_source_requests(url)
            for p in scraped:
                key = f"{p['ip']}:{p['port']}"
                if key not in seen:
                    seen.add(key)
                    found.append(p)
        except Exception as e:
            logger.debug(f"Error while scraping {url}: {e}")
    logger.info(f"Total scraped unique proxies: {len(found)}")
    return found

# ------------------------------
# Reputation & scoring (basic)
# ------------------------------
def basic_reputation_score(ip: str) -> float:
    """
    Basic heuristic reputation:
    - Private/bogon IPs => 0
    - Otherwise start at 50 and add small bonus for being likely good (placeholder)
    Replace/extend with calls to external IP reputation APIs (abuseipdb, ipqualityscore) if wanted.
    """
    # Exclude private ranges quickly
    private_blocks = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
    ]
    for pat in private_blocks:
        if pat.search(ip):
            return 0.0
    # Otherwise basic neutral score
    return 50.0

# ------------------------------
# Async testing
# ------------------------------
class ProxyTester:
    def __init__(self,
                 proxies: List[Dict[str,str]],
                 concurrency: int = DEFAULT_CONCURRENCY,
                 timeout: int = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES,
                 backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
                 max_latency_ms: int = DEFAULT_MAX_LATENCY_MS,
                 test_url: str = TEST_URL,
                 strict_port: int = 443):
        self.proxies = proxies
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.backoff_factor = backoff_factor
        self.max_latency_ms = max_latency_ms
        self.test_url = test_url
        self.strict_port = strict_port
        self.good_proxies: List[Dict[str, Any]] = []
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self) -> str:
        try:
            r = requests.get(LOCAL_IP_CHECK_URL, timeout=6)
            ip = r.text.strip()
            logger.debug(f"Detected local IP: {ip}")
            return ip
        except Exception:
            logger.debug("Could not fetch local IP (api may be blocked). Using '0.0.0.0'")
            return "0.0.0.0"

    async def test_single(self, session: aiohttp.ClientSession, ip: str, port: int) -> Optional[Dict[str, Any]]:
        proxy_url = f"http://{ip}:{port}"  # use http scheme for CONNECT proxies (typical)
        # Strict check: port must be exactly strict_port
        if port != self.strict_port:
            logger.debug(f"Discard {ip}:{port} because port != {self.strict_port}")
            return None

        attempt = 0
        delay = 0.1
        while attempt <= self.retries:
            attempt += 1
            start = time.time()
            try:
                # Each request uses a rotating user agent header to reduce chance of being blocked
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                # perform https GET via proxy (aiohttp supports proxy argument)
                async with session.get(self.test_url, proxy=proxy_url, timeout=self.timeout, headers=headers, ssl=True) as resp:
                    elapsed_ms = (time.time() - start) * 1000
                    status = resp.status
                    text = await resp.text()
                    if status != 200:
                        logger.debug(f"{ip}:{port} returned HTTP {status}, attempt {attempt}")
                        raise aiohttp.ClientResponseError(status=status, request_info=resp.request_info, history=resp.history)
                    # Parse httpbin response for 'origin' and 'headers'
                    try:
                        data = json.loads(text)
                        origin = data.get("origin", "")
                        headers_resp = data.get("headers", {})
                    except Exception:
                        # If response not JSON, fallback: do not accept
                        logger.debug(f"{ip}:{port} returned non-json response; discarding")
                        return None

                    # Enforce anonymity: the origin should not match our local IP (i.e., our IP must be hidden).
                    # httpbin's "origin" may show proxy IP (or multiple IPs). If our local IP appears, it's transparent.
                    if self.local_ip != "0.0.0.0" and self.local_ip in origin:
                        logger.debug(f"{ip}:{port} transparent proxy (local IP leaked) -> discard")
                        return None

                    # Also reject if request took too long
                    if elapsed_ms > self.max_latency_ms:
                        logger.debug(f"{ip}:{port} latency {int(elapsed_ms)}ms > {self.max_latency_ms}ms -> discard")
                        return None

                    # Heuristic anonymity: check forwarded headers
                    forwarded_header = headers_resp.get("X-Forwarded-For") or headers_resp.get("X-Forwarded") or headers_resp.get("Forwarded")
                    anonymity = "anonymous"
                    if forwarded_header:
                        # If header contains our local IP, transparent; otherwise maybe anonymous or elite
                        if self.local_ip != "0.0.0.0" and self.local_ip in forwarded_header:
                            anonymity = "transparent"
                        else:
                            anonymity = "anonymous (has forwarding header)"
                    # Determine proxy-reported origin IP (take first IP)
                    proxy_origin_ip = origin.split(",")[0].strip()

                    # Basic reputation score
                    rep_score = basic_reputation_score(proxy_origin_ip)
                    # Boost score for good latency
                    rep_score += max(0, (100 - int(elapsed_ms/ (self.max_latency_ms/100))))  # small boost

                    # Build result record
                    result = {
                        "ip": ip,
                        "port": port,
                        "proxy_url": proxy_url,
                        "latency_ms": int(elapsed_ms),
                        "origin_returned": proxy_origin_ip,
                        "anonymity": anonymity,
                        "reputation_score": round(rep_score, 2),
                        "tested_at": int(time.time())
                    }
                    logger.info(f"VALID {ip}:{port} latency={int(elapsed_ms)}ms anonymity={anonymity} score={round(rep_score,2)}")
                    return result

            except asyncio.TimeoutError:
                logger.debug(f"Timeout for {ip}:{port} attempt {attempt}")
            except aiohttp.ClientConnectorError as e:
                logger.debug(f"Conn error for {ip}:{port} attempt {attempt}: {e}")
            except aiohttp.ClientResponseError as e:
                logger.debug(f"Bad HTTP response for {ip}:{port} attempt {attempt}: {e}")
            except Exception as e:
                logger.debug(f"Unhandled error testing {ip}:{port} attempt {attempt}: {e}")

            # Exponential backoff before retry
            await asyncio.sleep(delay)
            delay *= self.backoff_factor

        # After retries, failed
        logger.debug(f"{ip}:{port} FAILED all attempts")
        return None

    async def run_tests(self):
        connector = aiohttp.TCPConnector(limit=0, ssl=False)  # disable ssl verification? we use ssl=True per request
        # Note: we pass ssl=True to session.get and let aiohttp verify TLS certs.
        sem = asyncio.Semaphore(self.concurrency)
        tasks = []
        async with aiohttp.ClientSession(connector=connector) as session:
            for p in self.proxies:
                ip = p.get("ip")
                try:
                    port = int(p.get("port"))
                except Exception:
                    continue
                # enforce port 443 locally before scheduling
                if port != self.strict_port:
                    continue

                async def bounded_test(ip=ip, port=port):
                    async with sem:
                        try:
                            return await self.test_single(session, ip, port)
                        except Exception as e:
                            logger.debug(f"Error in bounded_test {ip}:{port}: {e}")
                            return None

                tasks.append(asyncio.create_task(bounded_test()))

            logger.info(f"Testing {len(tasks)} candidates with concurrency={self.concurrency} timeout={self.timeout}s")
            results = await asyncio.gather(*tasks, return_exceptions=False)
            # filter valid
            for r in results:
                if r and isinstance(r, dict):
                    self.good_proxies.append(r)
        # sort by latency
        self.good_proxies.sort(key=lambda x: x["latency_ms"])
        logger.info(f"Found {len(self.good_proxies)} valid HTTPS:443 proxies under {self.max_latency_ms}ms")

    def get_results(self) -> List[Dict[str,Any]]:
        return self.good_proxies

# ------------------------------
# Export helpers
# ------------------------------
def export_txt(filename: str, proxies: List[Dict[str,Any]]):
    with open(filename, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(f"{p['ip']}:{p['port']}\n")
    logger.info(f"Wrote {len(proxies)} proxies to {filename}")

def export_json(filename: str, proxies: List[Dict[str,Any]]):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({"generated_at": int(time.time()), "count": len(proxies), "proxies": proxies}, f, indent=2)
    logger.info(f"Wrote JSON with {len(proxies)} proxies to {filename}")

# ------------------------------
# Main CLI
# ------------------------------
def main(argv):
    parser = argparse.ArgumentParser(description="HTTPS(443) Proxy Generator & Validator (strict)")
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent tests")
    parser.add_argument("--timeout", "-t", type=int, default=DEFAULT_TIMEOUT, help="Per-proxy request timeout (sec)")
    parser.add_argument("--retries", "-r", type=int, default=DEFAULT_RETRIES, help="Retries per proxy")
    parser.add_argument("--max-latency", "-l", type=int, default=DEFAULT_MAX_LATENCY_MS, help="Maximum latency in ms (strict)")
    parser.add_argument("--out-txt", type=str, default="good_proxies.txt", help="Output file for proxy list (ip:port)")
    parser.add_argument("--out-json", type=str, default="good_proxies.json", help="Output JSON file with metadata")
    parser.add_argument("--sources", nargs="*", default=PROXY_SOURCES, help="Optional override list of proxy sources (URLs)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"], help="Logging level")
    parser.add_argument("--limit", type=int, default=0, help="Optional: limit number of scraped candidates (0 = all)")
    args = parser.parse_args(argv)

    logger.setLevel(getattr(logging, args.log_level.upper()))

    logger.info("Starting HTTPS:443 Proxy Generator (STRICT)")
    # 1) Scrape sources
    candidates = aggregate_proxies_from_sources(args.sources)
    if args.limit > 0:
        candidates = candidates[:args.limit]
        logger.info(f"Limited candidate pool to {len(candidates)}")

    # 2) Filter only port 443 candidates early to save time
    candidates_443 = [p for p in candidates if int(p.get("port", 0)) == 443]
    logger.info(f"{len(candidates_443)} candidates on port 443 after initial filter")

    if not candidates_443:
        logger.warning("No port 443 proxies found in scraped sources. Exiting.")
        sys.exit(1)

    # 3) Run concurrency tests
    tester = ProxyTester(proxies=candidates_443,
                         concurrency=args.concurrency,
                         timeout=args.timeout,
                         retries=args.retries,
                         max_latency_ms=args.max_latency,
                         backoff_factor=DEFAULT_BACKOFF_FACTOR,
                         test_url=TEST_URL,
                         strict_port=443)
    asyncio.run(tester.run_tests())

    good = tester.get_results()

    # 4) Strict final filter (re-check that each result meets all criteria)
    strict_good = []
    for p in good:
        if p["port"] != 443 and int(p["port"]) != 443:
            continue
        if p["latency_ms"] > args.max_latency:
            continue
        # We already ensured anonymity earlier; keep only those whose origin != local IP
        if tester.local_ip != "0.0.0.0" and tester.local_ip in p.get("origin_returned", ""):
            continue
        strict_good.append(p)

    # 5) Export
    if strict_good:
        export_txt(args.out_txt, strict_good)
        export_json(args.out_json, strict_good)
        # print top 10
        logger.info("Top results (lowest latency):")
        for p in strict_good[:10]:
            logger.info(f"{p['ip']}:{p['port']} latency={p['latency_ms']}ms anon={p['anonymity']} score={p['reputation_score']}")
    else:
        logger.warning("No proxies passed ALL strict checks (HTTPS + port 443 + latency + anonymity).")

if __name__ == "__main__":
    main(sys.argv[1:])
