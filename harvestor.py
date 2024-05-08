import os
import json
import requests
import zipfile
import csv
import time
from urllib.parse import urlparse

def download_file(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as file:
        file.write(response.content)

def extract_domains_from_feed(feed_filename):
    with open(feed_filename, 'r') as file:
        return {domain.strip() for domain in file if domain.strip()}

def create_warehouse_if_not_exists():
    if not os.path.exists("warehouse.json"):
        with open("warehouse.json", "w") as file:
            file.write("[]")
        print("Created 'warehouse.json' file.")

def update_json_with_domains(domains):
    current_time = int(time.time())
    unique_domains = set()

    with open("warehouse.json", "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for domain in domains:
            if not domain:
                continue
            
            domain_without_path = urlparse(domain).netloc.split(':')[0]
            unique_domains.add(domain_without_path)

            found = False
            for item in data:
                if item["domain"] == domain_without_path:
                    item["last_seen"] = current_time
                    found = True
                    break
            if not found:
                data.append({
                    "domain": domain_without_path,
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "dns_status": "OK",
                    "dns_check_date": 0,
                    "whitelisted": 0
                })

        data = [entry for entry in data if entry["domain"] in unique_domains]

        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

# URLs and filenames for downloads
feed_urls = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt"
]
feed_filenames = [
    "openphish_feed.txt",
    "phishunt_feed.txt"
]

# Download phishing feeds
for url, filename in zip(feed_urls, feed_filenames):
    download_file(url, filename)

# Extract domains from feeds
openphish_domains = extract_domains_from_feed(feed_filenames[0])
phishunt_domains = extract_domains_from_feed(feed_filenames[1])

# Create warehouse.json if it doesn't exist
create_warehouse_if_not_exists()

# Update JSON with domains
update_json_with_domains(openphish_domains.union(phishunt_domains))
