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

import json
import time
from urllib.parse import urlparse

def update_json_with_domains(domains):
    current_time = int(time.time())
    unique_domains = set()  # Verwende eine Menge, um Duplikate zu entfernen

    with open("warehouse.json", "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for domain in domains:
            found = False
            domain_without_path = urlparse(domain).netloc.split(':')[0]  # Extrahiere die Domain aus der URL
            unique_domains.add(domain_without_path)

            # Überprüfe, ob die Domain in der Umbrella-Liste vorhanden ist
            tld, sld = extract_tld_sld(domain_without_path)
            if tld and sld and (sld + "." + tld) in umbrella_domains:
                continue  # Überspringe die Domain, wenn sie in der Umbrella-Liste vorhanden ist
            
            # Überprüfe, ob die Domain bereits im JSON vorhanden ist
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
                    "dns_check_date": 0  # Setze dns_check_date auf 0 für neue Domains
                })

        # Entferne Duplikate aus dem JSON
        data = [entry for entry in data if entry["domain"] in unique_domains]

        file.seek(0)
        file.truncate()  # Lösche den Inhalt der Datei, um sie neu zu schreiben
        json.dump(data, file, indent=4)

# Download phishing feeds
download_file("https://openphish.com/feed.txt", "openphish_feed.txt")
download_file("https://phishunt.io/feed.txt", "phishunt_feed.txt")
download_file("https://raw.githubusercontent.com/phishfort/phishfort-lists/master/blacklists/domains.json", "phishfort.txt")
download_file("https://raw.githubusercontent.com/Zaczero/pihole-phishtank/main/hosts.txt", "phishtank.txt")

# Extract domains from phishing feeds
openphish_domains = extract_domains_from_feed("openphish_feed.txt")
phishunt_domains = extract_domains_from_feed("phishunt_feed.txt")
phishfort_domains = extract_domains_from_feed("phishfort.txt")
phishtank_domains = extract_domains_from_feed("phishtank.txt")

# Download and extract umbrella list
download_file("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", "umbrella_list.zip")
with zipfile.ZipFile("umbrella_list.zip", "r") as zip_ref:
    zip_ref.extractall("umbrella_list")
umbrella_domains = extract_domains_from_umbrella_csv("umbrella_list/top-1m.csv")

# Create warehouse.json if it doesn't exist
create_warehouse_if_not_exists()

# Update JSON with domains
update_json_with_domains(openphish_domains + phishunt_domains + phishfort_domains + phishtank_domains)
