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
import matplotlib.pyplot as plt

# Configuration
WAREHOUSE_FILENAME = "warehouse.json"
HISTORY_FILENAME = "history.json"
FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt",
    "https://raw.githubusercontent.com/duggytuxy/phishing_scam_domains/main/phishing_scam_domains.txt",
    "http://www.botvrij.eu/data/ioclist.domain.raw",
    "http://www.joewein.net/dl/bl/dom-bl.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt"
]
FEED_FILENAMES = [
    "openphish_feed.txt",
    "phishunt_feed.txt",
    "phishing_scam_domains.txt",
    "ioclist.domain.raw.txt",
    "dom-bl.txt",
    "whitelist_urlshortener.txt",
    "whitelist_referral.txt"
]
TIME_THRESHOLD = 48 * 3600
DNS_CHECK_THRESHOLD = 6 * 3600

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def download_file(url, filename):
    """Download the file from the specified URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, "wb") as file:
            file.write(response.content)
        logging.info(f"Downloaded {url} to {filename}")
    except requests.RequestException as e:
        logging.error(f"Failed to download {url}: {e}")


def extract_domains_from_feed(feed_filename):
    """Extract domains from the specified feed file."""
    domains = set()
    try:
        with open(feed_filename, 'r') as file:
            for line in file:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    parsed_domain = urlparse(domain).netloc.split(':')[0] if '://' in domain else domain
                    if parsed_domain:
                        domains.add(parsed_domain)
    except FileNotFoundError:
        logging.error(f"Feed file {feed_filename} not found.")
    return domains


def create_file_if_not_exists(filename, initial_data=[]):
    """Create a JSON file with initial data if it does not exist."""
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump(initial_data, file, indent=4)
        logging.info(f"Created '{filename}' file.")


def update_json_with_domains(domains, filename):
    """Update the warehouse JSON file with the new domains."""
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
    logging.info(f"Updated '{filename}' with new domains.")
    return len(updated_data)


def mark_whitelisted_domains(whitelist_domains, filename):
    """Mark the domains as whitelisted in the warehouse JSON file."""
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
    logging.info(f"Marked whitelisted domains in '{filename}'.")


def check_dns_status(domain):
    """Check the DNS status of the domain."""
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
    """Update the DNS status for each domain in the warehouse JSON file."""
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
        logging.info("DNS status updated successfully.")
    except FileNotFoundError:
        logging.error(f"Error: '{filename}' not found.")
    except json.JSONDecodeError:
        logging.error(f"Error: Failed to decode JSON from '{filename}'.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def read_json_file(filename):
    """Read and return data from a JSON file."""
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
    """Calculate the SHA1 hash of the JSON data."""
    try:
        return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()
    except Exception as e:
        logging.error(f"Error calculating SHA1 hash: {e}")
        return ""


def get_existing_hash(filename):
    """Retrieve the existing hash from the output file."""
    try:
        with open(filename, "r") as file:
            for line in file:
                if line.startswith("# Database Hash:"):
                    return line.split(":")[1].strip()
    except FileNotFoundError:
        return None


def collect_ok_domains(data):
    """Collect domains with 'OK' DNS status and count their TLDs."""
    ok_domains = set()
    tld_counts = Counter()
    for entry in data:
        if entry["dns_status"] == "OK" and entry["whitelisted"] == 0:
            domain = entry["domain"]
            ok_domains.add(domain)
            tld_counts[domain.split(".")[-1]] += 1
    return ok_domains, tld_counts


def write_output_file(filename, json_hash, ok_domains, tld_counts):
    """Write the final output file with phishing domains and metadata."""
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


def plot_tld_counts(tld_counts):
    """Create a bar plot for the top 10 abused TLDs."""
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
        logging.info("TLD counts plot saved as 'tld_counts.png'.")
    except Exception as e:
        logging.error(f"Error plotting TLD counts: {e}")


def plot_history(filename):
    """Create a plot for the number of phishing domains over time."""
    try:
        with open(filename, "r") as file:
            history = json.load(file)

        timestamps = [entry['timestamp'] for entry in history]
        phishing_domains = [entry['phishing_domains'] for entry in history]

        plt.figure(figsize=(12, 6))
        plt.plot(timestamps, phishing_domains, marker='o', linestyle='-', color='b')
        plt.xlabel('Time')
        plt.ylabel('Number of Phishing Domains')
        plt.title('Phishing Domains Over Time')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('phishing_domains_over_time.png')
        logging.info("Phishing domains over time plot saved as 'phishing_domains_over_time.png'.")
    except Exception as e:
        logging.error(f"Error plotting history: {e}")


def update_history(filename, num_phishing_domains):
    """Update the history file with the current timestamp and number of phishing domains."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(filename, "r+") as file:
            try:
                history = json.load(file)
            except json.JSONDecodeError:
                history = []

            history.append({
                "timestamp": current_time,
                "phishing_domains": num_phishing_domains
            })

            file.seek(0)
            file.truncate()
            json.dump(history, file, indent=4)
    except Exception as e:
        logging.error(f"Error updating history: {e}")


def main():
    """Main function to coordinate the downloading, processing, and updating steps."""
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

    num_phishing_domains = update_json_with_domains(all_domains, WAREHOUSE_FILENAME)
    
    mark_whitelisted_domains(whitelist_domains, WAREHOUSE_FILENAME)

    update_dns_status(WAREHOUSE_FILENAME)

    data = read_json_file(WAREHOUSE_FILENAME)

    json_hash = calculate_sha1_hash(data)
    existing_hash = get_existing_hash("nxphish.agh")

    if existing_hash != json_hash:
        ok_domains, tld_counts = collect_ok_domains(data)
        write_output_file("nxphish.agh", json_hash, ok_domains, tld_counts)
        logging.info("nxphish.agh has been updated.")

        plot_tld_counts(tld_counts)
        update_history(HISTORY_FILENAME, num_phishing_domains)
        plot_history(HISTORY_FILENAME)
    else:
        logging.info("No changes detected. nxphish.agh is up to date.")


if __name__ == "__main__":
    main()
