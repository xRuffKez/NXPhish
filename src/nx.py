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

def load_cache():
    if os.path.exists(CACHE_FILENAME):
        with open(CACHE_FILENAME, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}

def save_cache(cache):
    serializable_cache = {}
    for key, value in cache.items():
        if isinstance(value, bytes):
            serializable_cache[key] = value.decode()
        else:
            serializable_cache[key] = value
    
    with open(CACHE_FILENAME, "w") as file:
        json.dump(serializable_cache, file)

cache = load_cache()

def download_file(url, filename):
    if url in cache:
        content = cache[url]
    else:
        response = requests.get(url)
        response.raise_for_status()
        content = response.content
        cache[url] = content
        save_cache(cache)
    with open(filename, "wb") as file:
        file.write(content)

def extract_domains_from_feed(feed_filename):
    domains = set()
    with open(feed_filename, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                parsed_domain = urlparse(domain).netloc.split(':')[0] if '://' in domain else domain
                if parsed_domain:
                    if not parsed_domain.endswith('.pages.dev') and not parsed_domain.endswith('.github.io'):
                        domains.add(parsed_domain)
    return domains

def create_file_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump([], file)

def update_json_with_domains(domains, filename):
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

def mark_whitelisted_domains(whitelist_domains, filename):
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

def check_dns_status(domain):
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
    except Exception:
        status = "ERROR"
    cache[domain] = status
    save_cache(cache)
    return status

def update_dns_status(filename):
    current_time = int(time.time())
    try:
        with open(filename, "r+") as file:
            data = json.load(file)
            for entry in data:
                if current_time - entry["dns_check_date"] >= DNS_CHECK_THRESHOLD:
                    entry["dns_status"] = check_dns_status(entry["domain"])
                    entry["dns_check_date"] = current_time
            updated_data = [
                entry for entry in data
                if entry["dns_status"] == "OK" or entry["whitelisted"] == 1 or current_time - entry["last_seen"] <= TIME_THRESHOLD
            ]
            file.seek(0)
            file.truncate()
            json.dump(updated_data, file, indent=4)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        pass

def read_json_file(filename):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []

def calculate_sha1_hash(data):
    try:
        return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()
    except Exception:
        return ""

def get_existing_hash(filename):
    try:
        with open(filename, "r") as file:
            for line in file:
                if line.startswith("# Database Hash:"):
                    return line.split(":")[1].strip()
    except FileNotFoundError:
        return None

def collect_ok_domains(data):
    ok_domains = set()
    tld_counts = Counter()
    for entry in data:
        if entry["dns_status"] == "OK" and entry["whitelisted"] == 0:
            domain = entry["domain"]
            ok_domains.add(domain)
            tld_counts[domain.split(".")[-1]] += 1
    return ok_domains, tld_counts

def write_output_file(filename, json_hash, ok_domains, tld_counts):
    generation_time = int(datetime.now().timestamp())
    try:
        with open(filename, "w") as file:
            file.write("# Title: NXPhish\n")
            file.write("# Author: xRuffKez\n")
            file.write(f"# Version: {generation_time}\n")
            file.write(f"# Database Hash: {json_hash}\n")
            file.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write(f"# Expires: 1 day\n")
            file.write(f"# Number of phishing domains: {len(ok_domains)}\n")
            file.write("# Top 10 Abused TLDs:\n")
            for tld, count in tld_counts.most_common(10):
                percentage = (count / len(ok_domains)) * 100
                file.write(f"# {tld}: {count} ({percentage:.2f}%)\n")
            file.write("\n")
            for domain in sorted(ok_domains):
                file.write(f"||{domain}^\n")
    except Exception:
        pass
    return len(ok_domains)

def plot_tld_counts(tld_counts):
    try:
        tlds, counts = zip(*tld_counts.most_common(10))
        plt.figure(figsize=(10, 6))
        plt.bar(tlds, counts, color='skyblue')
        plt.xlabel('Top Level Domains (TLDs)')
        plt.ylabel('Count')
        plt.title('Top 10 Abused TLDs')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('tld_counts.png')
    except Exception:
        pass

def plot_history(filename):
    try:
        with open(filename, "r") as file:
            history = json.load(file)
        timestamps = [entry['timestamp'] for entry in history]
        phishing_domains = [entry['num_phishing_domains'] for entry in history]
        plt.figure(figsize=(10, 6))
        plt.plot(timestamps, phishing_domains, marker='o', linestyle='-', color='b')
        plt.xlabel('Timestamp')
        plt.ylabel('Number of Phishing Domains')
        plt.title('History of Phishing Domains')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('history_plot.png')
    except Exception:
        pass

def update_history(filename, num_phishing_domains):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_entry = {"timestamp": current_time, "num_phishing_domains": num_phishing_domains}
    try:
        with open(filename, "r+") as file:
            try:
                history = json.load(file)
            except json.JSONDecodeError:
                history = []
            history.append(new_entry)
            file.seek(0)
            file.truncate()
            json.dump(history, file, indent=4)
    except Exception:
        pass

def main():
    for url, filename in zip(FEED_URLS, FEED_FILENAMES):
        download_file(url, filename)
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

if __name__ == "__main__":
    main()
