import os
import json
import requests
import zipfile
import csv
import time
from urllib.parse import urlparse
from tld import get_tld

def download_file(url, filename):
    response = requests.get(url)
    with open(filename, "wb") as file:
        file.write(response.content)

def extract_domains_from_feed(feed_filename):
    with open(feed_filename, 'r') as file:
        domains = file.readlines()
    return [domain.strip() for domain in domains if domain.strip()]

def extract_domains_from_umbrella_csv(csv_filename):
    with open(csv_filename, newline='') as file:
        reader = csv.reader(file)
        return [row[1] for row in reader]

def extract_tld_sld(domain):
    if not domain.startswith("http"):
        domain = "http://" + domain  # Füge ein Protokoll hinzu, um eine gültige URL zu erstellen
    parsed_url = urlparse(domain)
    if not parsed_url.netloc:
        return None, None
    
    # Überprüfe, ob die Domain eine IP-Adresse ist
    if parsed_url.netloc.replace(".", "").isdigit():
        return None, None
    
    try:
        tld = get_tld(domain, as_object=True).tld
        sld = get_tld(domain, as_object=True).domain
    except tld.exceptions.TldDomainNotFound:
        return None, None
    return tld, sld

def create_warehouse_if_not_exists():
    if not os.path.exists("warehouse.json"):
        with open("warehouse.json", "w") as file:
            file.write("[]")  # Write an empty JSON array to the file
        print("Created 'warehouse.json' file.")

def update_json_with_domains(domains):
    current_time = int(time.time())
    unique_domains = set()  # Use a set to remove duplicates

    with open("warehouse.json", "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for domain in domains:
            # Skip empty domain entries
            if not domain:
                continue
            
            found = False
            domain_without_path = urlparse(domain).netloc.split(':')[0]  # Extract domain from URL
            unique_domains.add(domain_without_path)

            # Check if the domain is in the Umbrella list
            tld, sld = extract_tld_sld(domain_without_path)
            if tld and sld and (sld + "." + tld) in umbrella_domains:
                continue  # Skip the domain if it's in the Umbrella list
            
            # Check if the domain is already in the JSON
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
                    "dns_check_date": 0  # Set dns_check_date to 0 for new domains
                })

        # Remove duplicates from the JSON
        data = [entry for entry in data if entry["domain"] in unique_domains]

        file.seek(0)
        file.truncate()  # Clear the file content to rewrite it
        json.dump(data, file, indent=4)

# Download phishing feeds
download_file("https://openphish.com/feed.txt", "openphish_feed.txt")
download_file("https://phishunt.io/feed.txt", "phishunt_feed.txt")

# Extract domains from phishing feeds
openphish_domains = extract_domains_from_feed("openphish_feed.txt")
phishunt_domains = extract_domains_from_feed("phishunt_feed.txt")

# Download and extract umbrella list
download_file("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", "umbrella_list.zip")
with zipfile.ZipFile("umbrella_list.zip", "r") as zip_ref:
    zip_ref.extractall("umbrella_list")
umbrella_domains = extract_domains_from_umbrella_csv("umbrella_list/top-1m.csv")[:10000]

# Create warehouse.json if it doesn't exist
create_warehouse_if_not_exists()

# Update JSON with domains
update_json_with_domains(openphish_domains + phishunt_domains)
