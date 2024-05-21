import os
import json
import requests
import time
from urllib.parse import urlparse
import dns.resolver
import hashlib
from datetime import datetime
from collections import Counter
import logging

WAREHOUSE_FILENAME = "warehouse.json"
FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt"
]
FEED_FILENAMES = [
    "openphish_feed.txt",
    "phishunt_feed.txt"
]
TIME_THRESHOLD = 48 * 3600
DNS_CHECK_THRESHOLD = 6 * 3600

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def download_file(url, filename):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, "wb") as file:
            file.write(response.content)
        logging.info(f"Downloaded {url} to {filename}")
    except requests.RequestException as e:
        logging.error(f"Failed to download {url}: {e}")

def extract_domains_from_feed(feed_filename):
    domains = set()
    with open(feed_filename, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:
                parsed_domain = urlparse(domain).netloc.split(':')[0]
                if parsed_domain:
                    domains.add(parsed_domain)
    return domains

def create_warehouse_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump([], file)
        logging.info(f"Created '{filename}' file.")

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
            if entry["dns_status"] == "OK" or current_time - entry["last_seen"] <= TIME_THRESHOLD
        ]

        file.seek(0)
        file.truncate()
        json.dump(updated_data, file, indent=4)
    logging.info(f"Updated '{filename}' with new domains.")

def check_dns_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        ipv4_response = resolver.resolve(domain, 'A')
        ipv4_addresses = [r.address for r in ipv4_response]
        ipv6_response = resolver.resolve(domain, 'AAAA')
        ipv6_addresses = [r.address for r in ipv6_response]
        if ipv4_addresses or ipv6_addresses:
            return "OK"
        else:
            return "NO_ANSWER"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.Timeout:
        return "TIMEOUT"
    except dns.resolver.NoAnswer:
        return "NO_ANSWER"
    except dns.resolver.NoNameservers:
        return "NO_NAMESERVERS"
    except Exception as e:
        logging.error(f"DNS resolution error for domain {domain}: {e}")
        return "ERROR"

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
                if entry["dns_status"] == "OK" or current_time - entry["last_seen"] <= TIME_THRESHOLD
            ]

            file.seek(0)
            file.truncate()
            json.dump(updated_data, file, indent=4)
        logging.info("DNS status updated successfully.")
    except FileNotFoundError:
        logging.error(f"Error: '{filename}' not found.")
    except json.JSONDecodeError:
        logging.error(f"Error: Failed to decode JSON from '{filename}'.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

def read_json_file(filename):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"File '{filename}' not found.")
        return []
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from '{filename}'.")
        return []

def calculate_sha1_hash(data):
    try:
        return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()
    except Exception as e:
        logging.error(f"Error calculating SHA1 hash: {e}")
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
    except Exception as e:
        logging.error(f"Error writing to '{filename}': {e}")

def main():
    for url, filename in zip(FEED_URLS, FEED_FILENAMES):
        download_file(url, filename)

    all_domains = set()
    for filename in FEED_FILENAMES:
        all_domains.update(extract_domains_from_feed(filename))

    create_warehouse_if_not_exists(WAREHOUSE_FILENAME)

    update_json_with_domains(all_domains, WAREHOUSE_FILENAME)

    update_dns_status(WAREHOUSE_FILENAME)

    data = read_json_file(WAREHOUSE_FILENAME)

    json_hash = calculate_sha1_hash(data)
    existing_hash = get_existing_hash("nxphish.agh")

    if existing_hash != json_hash:
        ok_domains, tld_counts = collect_ok_domains(data)
        write_output_file("nxphish.agh", json_hash, ok_domains, tld_counts)
        logging.info("nxphish.agh has been updated.")
    else:
        logging.info("No changes detected. nxphish.agh is up to date.")

if __name__ == "__main__":
    main()
