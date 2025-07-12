#!/usr/bin/env python3

import requests
import socket
import re
import sys
import time
from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# ========== CONFIG ==========
# Add risky brand keywords to avoid phishing domains
RISKY_KEYWORDS = ["facebook", "paypal", "google", "instagram", "microsoft", "apple"]

# ========== SESSION SETUP ==========
def setup_session():
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=5,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# ========== PHISHING FILTER ==========
def is_suspicious(sub):
    if any(keyword in sub.lower() for keyword in RISKY_KEYWORDS):
        # Only allow exact match (e.g., google.com is OK, but google----fake.com is not)
        parts = sub.lower().split('.')
        for part in parts:
            if any(k in part and not part.endswith(k) for k in RISKY_KEYWORDS):
                return True
    if sub.count('-') > 3 or len(sub) > 100:
        return True
    return False

# ========== SUBDOMAIN FETCH ==========
def get_crtsh_subdomains(domain, session):
    print(f"[+] Gathering subdomains for {domain} from crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        response = session.get(url, timeout=30)
        data = response.json()
        for entry in data:
            names = entry.get('name_value', '').split('\n')
            for name in names:
                name = name.strip()
                if '*' in name or is_suspicious(name):
                    continue
                if domain in name:
                    subdomains.add(name)
    except Exception as e:
        print(f"[!] Error fetching subdomains: {e}")
    
    return list(subdomains)

# ========== DNS RESOLUTION ==========
def is_live(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

# ========== JS EXTRACT ==========
def extract_js(subdomain, session):
    js_files = set()
    try:
        url = f"http://{subdomain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"
        }
        response = session.get(url, headers=headers, timeout=30)
        matches = re.findall(r'src=["\'](.*?\.js)["\']', response.text)
        for match in matches:
            if match.startswith("http"):
                js_files.add(match)
            else:
                js_files.add(f"http://{subdomain}/{match.lstrip('/')}")
        time.sleep(3)  # Avoid detection
    except:
        pass
    return js_files

# ========== SAVE ==========
def save_to_file(filepath, data):
    with open(filepath, 'w') as f:
        for item in sorted(set(data)):
            f.write(item + '\n')

# ========== MAIN ==========
def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} domain.com")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    folder_name = domain.split('.')[0]  # For directory like 'tesla'
    output_dir = Path(folder_name)
    output_dir.mkdir(exist_ok=True)

    subs_file = output_dir / "subs.txt"
    live_file = output_dir / "live.txt"
    js_file = output_dir / "js.txt"

    session = setup_session()

    # Step 1: Subdomain discovery
    subdomains = get_crtsh_subdomains(domain, session)
    save_to_file(subs_file, subdomains)

    # Step 2: Check which subdomains are live
    print("[+] Checking live subdomains...")
    live_subs = [sub for sub in subdomains if is_live(sub)]
    save_to_file(live_file, live_subs)

    # Step 3: Extract JS files
    print("[+] Extracting JavaScript file links...")
    js_links = []
    for sub in live_subs:
        js_links.extend(extract_js(sub, session))
    save_to_file(js_file, js_links)

    print(f"\n[✓] Done. Output saved in ./{folder_name}/")

if __name__ == "__main__":
    main()
