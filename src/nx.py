import os
import json
import requests
import time
from urllib.parse import urlparse
import dns.resolver
import hashlib
from datetime import datetime
from collections import Counter

# Constants
WAREHOUSE_FILENAME = "warehouse.json"
FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt"
]
FEED_FILENAMES = [
    "openphish_feed.txt",
    "phishunt_feed.txt"
]

# Function to download a file from a URL
def download_file(url, filename):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we catch HTTP errors
    with open(filename, "wb") as file:
        file.write(response.content)
    print(f"Downloaded {url} to {filename}")

# Function to extract domains from a feed file
def extract_domains_from_feed(feed_filename):
    with open(feed_filename, 'r') as file:
        return {domain.strip() for domain in file if domain.strip()}

# Function to create warehouse file if it doesn't exist
def create_warehouse_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump([], file)
        print(f"Created '{filename}' file.")

# Function to update warehouse JSON with new domains
def update_json_with_domains(domains, filename):
    current_time = int(time.time())
    unique_domains = {urlparse(domain).netloc.split(':')[0] for domain in domains if domain}

    with open(filename, "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []

        domain_dict = {entry["domain"]: entry for entry in data}
        
        for domain in unique_domains:
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

        updated_data = list(domain_dict.values())
        file.seek(0)
        file.truncate()
        json.dump(updated_data, file, indent=4)
    print(f"Updated '{filename}' with new domains.")

# Function to check DNS status of a given domain
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
        return "ERROR"

# Function to update DNS status in warehouse.json
def update_dns_status(filename):
    current_time = int(time.time())
    try:
        with open(filename, "r+") as file:
            data = json.load(file)

            for entry in data:
                if entry["dns_check_date"] == 0 or current_time - entry["dns_check_date"] >= 48 * 3600:
                    entry["dns_status"] = check_dns_status(entry["domain"])
                    entry["dns_check_date"] = current_time

            file.seek(0)
            file.truncate()
            json.dump(data, file, indent=4)
        print("DNS status updated successfully.")
    except FileNotFoundError:
        print(f"Error: '{filename}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from '{filename}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Function to read JSON file
def read_json_file(filename):
    with open(filename, "r") as file:
        return json.load(file)

# Function to calculate SHA1 hash of data
def calculate_sha1_hash(data):
    return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()

# Function to get existing hash from output file
def get_existing_hash(filename):
    try:
        with open(filename, "r") as file:
            for line in file:
                if line.startswith("# Database Hash:"):
                    return line.split(":")[1].strip()
    except FileNotFoundError:
        return None

# Function to collect OK domains and their TLD counts
def collect_ok_domains(data):
    ok_domains = set()
    tld_counts = Counter()

    for entry in data:
        if entry["dns_status"] == "OK" and entry["whitelisted"] == 0:
            domain = entry["domain"]
            ok_domains.add(domain)
            tld_counts[domain.split(".")[-1]] += 1
    
    return ok_domains, tld_counts

# Function to write output file with updated domain data
def write_output_file(filename, json_hash, ok_domains, tld_counts):
    generation_time = int(datetime.now().timestamp())
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

# Main function to orchestrate the entire process
def main():
    # Step 1: Download phishing feeds
    for url, filename in zip(FEED_URLS, FEED_FILENAMES):
        download_file(url, filename)

    # Step 2: Extract domains from feeds
    all_domains = set()
    for filename in FEED_FILENAMES:
        all_domains.update(extract_domains_from_feed(filename))

    # Step 3: Create warehouse.json if it doesn't exist
    create_warehouse_if_not_exists(WAREHOUSE_FILENAME)

    # Step 4: Update JSON with domains
    update_json_with_domains(all_domains, WAREHOUSE_FILENAME)

    # Step 5: Update DNS status in warehouse.json
    update_dns_status(WAREHOUSE_FILENAME)

    # Step 6: Read JSON file
    data = read_json_file(WAREHOUSE_FILENAME)

    # Step 7: Calculate SHA1 hash of the current data
    json_hash = calculate_sha1_hash(data)
    existing_hash = get_existing_hash("nxphish.agh")

    # Step 8: Collect OK domains and their TLD counts
    if existing_hash != json_hash:
        ok_domains, tld_counts = collect_ok_domains(data)
        
        # Step 9: Write the output file with updated information
        write_output_file("nxphish.agh", json_hash, ok_domains, tld_counts)
        print("nxphish.agh has been updated.")
    else:
        print("No changes detected. nxphish.agh is up to date.")

if __name__ == "__main__":
    main()
