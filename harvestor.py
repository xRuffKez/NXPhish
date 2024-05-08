import json
import time
from urllib.parse import urlparse

def update_json_with_domains(domains):
    current_time = int(time.time())
    domain_data = {}  # Use a dictionary for faster lookups
    unique_domains = set()  # Use a set to track unique domains

    try:
        with open("warehouse.json", "r") as file:
            domain_data = json.load(file)
    except FileNotFoundError:
        pass

    for domain in domains:
        if not domain:
            continue
        
        domain_without_path = urlparse(domain).netloc.split(':')[0]
        unique_domains.add(domain_without_path)

        if domain_without_path in domain_data:
            domain_data[domain_without_path]["last_seen"] = current_time
        else:
            domain_data[domain_without_path] = {
                "domain": domain_without_path,
                "first_seen": current_time,
                "last_seen": current_time,
                "dns_status": "OK",
                "dns_check_date": 0,
                "whitelisted": 0
            }

    # Remove duplicates from the JSON
    domain_data = list(domain_data.values())

    with open("warehouse.json", "w") as file:
        json.dump(domain_data, file, indent=4)
