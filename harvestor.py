import os
import json
import requests
import time
from urllib.parse import urlparse

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

def download_file(url, filename):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we catch HTTP errors
    with open(filename, "wb") as file:
        file.write(response.content)
    print(f"Downloaded {url} to {filename}")

def extract_domains_from_feed(feed_filename):
    with open(feed_filename, 'r') as file:
        return {domain.strip() for domain in file if domain.strip()}

def create_warehouse_if_not_exists(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as file:
            json.dump([], file)
        print(f"Created '{filename}' file.")

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

def main():
    # Download phishing feeds
    for url, filename in zip(FEED_URLS, FEED_FILENAMES):
        download_file(url, filename)

    # Extract domains from feeds
    all_domains = set()
    for filename in FEED_FILENAMES:
        all_domains.update(extract_domains_from_feed(filename))

    # Create warehouse.json if it doesn't exist
    create_warehouse_if_not_exists(WAREHOUSE_FILENAME)

    # Update JSON with domains
    update_json_with_domains(all_domains, WAREHOUSE_FILENAME)

if __name__ == "__main__":
    main()
