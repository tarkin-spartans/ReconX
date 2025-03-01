import requests
import re
import argparse
import time
import os
from concurrent.futures import ThreadPoolExecutor

# Headers to avoid blocking
HEADERS = {"User-Agent": "ReconX-Scanner"}

# Sensitive data patterns (API keys, tokens, etc.)
SENSITIVE_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google_API_Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack_Token": r"xox[baprs]-[0-9A-Za-z]{10,48}",
    "Generic_Token": r"(?i)(token|api|key|secret)[\s=:'\"]+([0-9a-zA-Z]{32,45})",
    "JWT_Token": r"eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}",
}

# Function to clean the target name for file naming
def clean_filename(target):
    return target.replace(".", "_").replace("/", "_")

# Function to fetch URLs from different sources and save them
def scan_urls(target):
    print(f"[*] Fetching URLs for: {target}")
    sources = {
        "AlienVault": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list",
        "URLScan": f"https://urlscan.io/api/v1/search/?q=domain:{target}",
        "Wayback Machine": f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original",
    }

    urls = set()
    for name, url in sources.items():
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                data = response.json() if "json" in response.headers.get("Content-Type", "") else response.text
                if name == "AlienVault":
                    urls.update([entry["url"] for entry in data.get("url_list", [])])
                elif name == "URLScan":
                    urls.update([result["task"]["url"] for result in data.get("results", [])])
                elif name == "Wayback Machine":
                    urls.update([entry[0] for entry in data[1:]])
            print(f"[+] {name}: {len(urls)} URLs found")
        except Exception as e:
            print(f"[-] Error fetching from {name}: {e}")

    urls_file = f"{clean_filename(target)}_urls.txt"
    with open(urls_file, "w") as file:
        for url in urls:
            file.write(url + "\n")
    
    print(f"[+] All URLs saved to: {urls_file}")
    return list(urls)

# Function to extract JavaScript, JSON, and sensitive files
def extract_sensitive_files(urls, target):
    file_patterns = r'https?://\S+\.(js|json|zip|tar|db|bak)'
    sensitive_files = set()

    for url in urls:
        matches = re.findall(file_patterns, url)
        if matches:
            sensitive_files.add(url)

    sensitive_files_file = f"{clean_filename(target)}_sensitive_files.txt"
    with open(sensitive_files_file, "w") as file:
        for file_url in sensitive_files:
            file.write(file_url + "\n")

    print(f"[+] Extracted sensitive files saved to: {sensitive_files_file}")
    return list(sensitive_files)

# Function to scan for secrets in JS/JSON files
def secret_finding(url, target):
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            content = response.text
            found_secrets = {}

            for secret_name, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    found_secrets[secret_name] = matches

            if found_secrets:
                print(f"[!] Secrets found in {url}")
                save_secrets(url, found_secrets, target)

    except Exception:
        pass

# Function to save secrets in a structured format
def save_secrets(url, secrets, target):
    output_file = f"{clean_filename(target)}_results.txt"
    with open(output_file, "a") as file:
        file.write("\n" + "="*60 + "\n")
        file.write(f"Secrets found in: {url}\n")
        file.write("="*60 + "\n")

        for secret_type, values in secrets.items():
            for value in values:
                file.write(f"{secret_type}: {value}\n")

    print(f"[+] Secrets saved to {output_file}")

# Main function
def main(target, threads, rate_limit):
    urls = scan_urls(target)
    if not urls:
        print("[-] No URLs found.")
        return

    print(f"[*] Extracting sensitive files (JS, JSON, ZIP, TAR, DB, BAK)...")
    sensitive_files = extract_sensitive_files(urls, target)
    print(f"[+] Found {len(sensitive_files)} sensitive files.")

    print(f"[*] Scanning for sensitive data...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in executor.map(lambda url: secret_finding(url, target), sensitive_files):
            time.sleep(rate_limit)

    print("[+] Scan complete.")

# CLI Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReconX - OSINT & Secret Finder")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--threads", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Rate limit in seconds (default: 0.1)")

    args = parser.parse_args()
    main(args.target, args.threads, args.rate_limit)
