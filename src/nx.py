import os
import json
import requests
import time
from urllib.parse import urlparse
import dns.resolver
import hashlib
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
from typing import Set, Dict, Any, Tuple, List
import concurrent.futures
import logging

# Constants
WAREHOUSE_FILENAME = "warehouse.json"
HISTORY_FILENAME = "history.json"
CACHE_FILENAME = "cache.json"
FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt"
]
FEED_FILENAMES = [
    "openphish_feed.txt",
    "phishunt_feed.txt",
    "whitelist_urlshortener.txt",
    "whitelist_referral.txt"
]
TIME_THRESHOLD = 48 * 3600
DNS_CHECK_THRESHOLD = 6 * 3600
NUM_WORKERS = 10  # Number of workers for parallel processing

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load cache
def load_cache() -> Dict[str, Any]:
    if os.path.exists(CACHE_FILENAME):
        with open(CACHE_FILENAME, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}

cache = load_cache()

def save_cache(cache: Dict[str, Any]) -> None:
    serializable_cache = {key: (value.decode() if isinstance(value, bytes) else value) for key, value in cache.items()}
    with open(CACHE_FILENAME, "w") as file:
        json.dump(serializable_cache, file)

# File downloading
def download_file(url: str, filename: str) -> None:
    logging.info(f"Downloading {url}")
    if url in cache:
        content = cache[url]
    else:
        try:
            response = requests.get(url)
            response.raise_for_status()
            content = response.content  # Ensure content is bytes
            cache[url] = content
            save_cache(cache)
        except requests.RequestException as e:
            logging.error(f"Error downloading {url}: {e}")
            return
    with open(filename, "wb") as file:
        if isinstance(content, str):
            content = content.encode('utf-8')  # Convert string to bytes if necessary
        file.write(content)
    logging.info(f"Saved {filename}")

# Extract domains from feed
def extract_domains_from_feed(feed_filename: str) -> Set[str]:
    domains = set()
    with open(feed_filename, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                parsed_domain = urlparse(domain).netloc.split(':')[0] if '://' in domain else domain
                if parsed_domain and not parsed_domain.endswith(('.pages.dev', '.github.io')):
                    domains.add(parsed_domain)
    return domains

# Create file if not exists
def create_file_if_not_exists(filename: str) -> None:
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump([], file)

# Update JSON with domains
def update_json_with_domains(domains: Set[str], filename: str) -> int:
    current_time = int(time.time())
    with open(filename, "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []
        domain_dict = {entry["domain"]: entry for entry in data}
        for domain in domains:
            if domain in domain_dict:
                domain_dict[domain]["last_seen"] = current_time
            else:
                domain_dict[domain] = {
                    "domain": domain,
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "dns_status": "OK",
                    "dns_check_date": 0,
                    "whitelisted": 0
                }
        updated_data = [
            entry for entry in domain_dict.values()
            if entry["dns_status"] == "OK" or entry["whitelisted"] == 1 or current_time - entry["last_seen"] <= TIME_THRESHOLD
        ]
        file.seek(0)
        file.truncate()
        json.dump(updated_data, file, indent=4)
    return len(updated_data)

# Mark whitelisted domains
def mark_whitelisted_domains(whitelist_domains: Set[str], filename: str) -> None:
    with open(filename, "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []
        for domain in whitelist_domains:
            for entry in data:
                if domain == entry["domain"] or domain.startswith("*.") and entry["domain"].endswith(domain[1:]):
                    entry["whitelisted"] = 1
        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

# Check DNS status
def check_dns_status(domain: str) -> str:
    if domain in cache:
        return cache[domain]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        ipv4_response = resolver.resolve(domain, 'A')
        ipv4_addresses = [r.address for r in ipv4_response]
        ipv6_response = resolver.resolve(domain, 'AAAA')
        ipv6_addresses = [r.address for r in ipv6_response]
        status = "OK" if ipv4_addresses or ipv6_addresses else "NO_ANSWER"
    except dns.resolver.NXDOMAIN:
        status = "NXDOMAIN"
    except dns.resolver.Timeout:
        status = "TIMEOUT"
    except dns.resolver.NoAnswer:
        status = "NO_ANSWER"
    except dns.resolver.NoNameservers:
        status = "NO_NAMESERVERS"
    except Exception as e:
        logging.error(f"DNS check error for {domain}: {e}")
        status = "ERROR"
    cache[domain] = status
    save_cache(cache)
    return status

# Update DNS status with parallel processing
def update_dns_status(filename: str) -> None:
    current_time = int(time.time())
    try:
        with open(filename, "r+") as file:
            data = json.load(file)
            domains_to_check = [
                entry["domain"] for entry in data
                if current_time - entry["dns_check_date"] >= DNS_CHECK_THRESHOLD
            ]
            with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
                results = list(executor.map(check_dns_status, domains_to_check))
            for domain, status in zip(domains_to_check, results):
                for entry in data:
                    if entry["domain"] == domain:
                        entry["dns_status"] = status
                        entry["dns_check_date"] = current_time
            updated_data = [
                entry for entry in data
                if entry["dns_status"] == "OK" or entry["whitelisted"] == 1 or current_time - entry["last_seen"] <= TIME_THRESHOLD
            ]
            file.seek(0)
            file.truncate()
            json.dump(updated_data, file, indent=4)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

# Read JSON file
def read_json_file(filename: str) -> List[Dict[str, Any]]:
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# Calculate SHA1 hash
def calculate_sha1_hash(data: Any) -> str:
    try:
        return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()
    except Exception as e:
        logging.error(f"Hash calculation error: {e}")
        return ""

# Get existing hash
def get_existing_hash(filename: str) -> str:
    try:
        with open(filename, "r") as file:
            for line in file:
                if line.startswith("# Database Hash:"):
                    return line.split(":")[1].strip()
    except FileNotFoundError:
        return None

# Collect OK domains
def collect_ok_domains(data: List[Dict[str, Any]]) -> Tuple[Set[str], Counter]:
    ok_domains = {entry["domain"] for entry in data if entry["dns_status"] == "OK" and entry["whitelisted"] == 0}
    tld_counts = Counter(domain.split(".")[-1] for domain in ok_domains)
    return ok_domains, tld_counts

# Write output file
def write_output_file(filename: str, json_hash: str, ok_domains: Set[str], tld_counts: Counter) -> int:
    generation_time = int(datetime.now().timestamp())
    try:
        with open(filename, "w") as file:
            file.write("# Title: NXPhish\n")
            file.write("# Author: xRuffKez\n")
            file.write(f"# Version: {generation_time}\n")
            file.write(f"# Database Hash: {json_hash}\n")
            file.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"# Expires: 1 day\n\n")
            file.write("# Top-level domain statistics:\n")
            for tld, count in tld_counts.items():
                percentage = (count / len(ok_domains)) * 100
                file.write(f"# - .{tld}: {count} ({percentage:.2f}%)\n")
            file.write("\n")
            for domain in sorted(ok_domains):
                file.write(f"0.0.0.0 {domain}\n")
    except Exception as e:
        logging.error(f"Error writing output file: {e}")
    return len(ok_domains)

# Plot TLD counts
def plot_tld_counts(tld_counts: Counter) -> None:
    tlds, counts = zip(*tld_counts.most_common(10))
    plt.bar(tlds, counts)
    plt.title("Top 10 Abused TLDs")
    plt.xlabel("TLD")
    plt.ylabel("Count")
    plt.savefig("tld_counts.png")
    plt.close()

# Update history
def update_history(history_filename: str, num_phishing_domains: int) -> None:
    current_date = datetime.now().strftime('%Y-%m-%d')
    try:
        with open(history_filename, "r+") as file:
            try:
                history = json.load(file)
            except json.JSONDecodeError:
                history = []
            if history and history[-1]["date"] == current_date:
                history[-1]["count"] = num_phishing_domains
            else:
                history.append({"date": current_date, "count": num_phishing_domains})
            file.seek(0)
            file.truncate()
            json.dump(history, file, indent=4)
    except FileNotFoundError:
        with open(history_filename, "w") as file:
            json.dump([{"date": current_date, "count": num_phishing_domains}], file, indent=4)

# Plot history
def plot_history(history_filename: str) -> None:
    try:
        with open(history_filename, "r") as file:
            history = json.load(file)
        if not history:
            logging.info("No history to plot")
            return
        dates = [entry["date"] for entry in history]
        counts = [entry["count"] for entry in history]
        plt.plot(dates, counts, marker='o')
        plt.title("Number of Phishing Domains Over Time")
        plt.xlabel("Date")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()  # Ensure labels fit into the plot area
        plt.savefig("history.png")
        plt.close()
    except (FileNotFoundError, json.JSONDecodeError):
        logging.error("Error reading history file for plotting")

# Main function
def main() -> None:
    logging.info("Script started")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            executor.map(download_file, FEED_URLS, FEED_FILENAMES)
        all_domains = set()
        whitelist_domains = set()
        for filename in FEED_FILENAMES:
            if 'whitelist' in filename:
                whitelist_domains.update(extract_domains_from_feed(filename))
            else:
                all_domains.update(extract_domains_from_feed(filename))
        create_file_if_not_exists(WAREHOUSE_FILENAME)
        create_file_if_not_exists(HISTORY_FILENAME)
        update_json_with_domains(all_domains, WAREHOUSE_FILENAME)
        mark_whitelisted_domains(whitelist_domains, WAREHOUSE_FILENAME)
        update_dns_status(WAREHOUSE_FILENAME)
        data = read_json_file(WAREHOUSE_FILENAME)
        json_hash = calculate_sha1_hash(data)
        existing_hash = get_existing_hash("nxphish.agh")
        if existing_hash != json_hash:
            ok_domains, tld_counts = collect_ok_domains(data)
            num_phishing_domains = write_output_file("nxphish.agh", json_hash, ok_domains, tld_counts)
            plot_tld_counts(tld_counts)
            update_history(HISTORY_FILENAME, num_phishing_domains)
            plot_history(HISTORY_FILENAME)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    logging.info("Script finished")

if __name__ == "__main__":
    main()
