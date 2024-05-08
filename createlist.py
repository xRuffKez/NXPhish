import json
import hashlib
from datetime import datetime
from collections import Counter

# Read the JSON file
with open("warehouse.json", "r") as file:
    data = json.load(file)

# Calculate SHA-1 hash of the JSON data
json_hash = hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()

# Check if the database hash is different from the hash value in nxphish.agh
existing_hash = None
try:
    with open("nxphish.agh", "r") as file:
        for line in file:
            if line.startswith("# Database Hash:"):
                existing_hash = line.split(":")[1].strip()
                break
except FileNotFoundError:
    pass

if existing_hash != json_hash:
    # Use a set to store unique OK domains
    ok_domains = set()

    # Counter for TLDs
    tld_counts = Counter()

    # Process data
    for entry in data:
        if entry["dns_status"] == "OK":
            domain = entry["domain"]
            ok_domains.add(domain)
            tld_counts[domain.split(".")[-1]] += 1

    # Get current Unix timestamp
    generation_time = int(datetime.now().timestamp())

    # Write data to nxphish.agh
    with open("nxphish.agh", "w") as file:
        file.write("# Title: NXPhish\n")
        file.write("# Author: xRuffKez\n")
        file.write(f"# Version: {generation_time}\n")  # Write Unix timestamp as version
        file.write(f"# Database Hash: {json_hash}\n")  # Write SHA-1 hash of JSON data
        file.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \n")
        file.write(f"# Expires: 1 day\n")
        file.write(f"# Number of phishing domains: {len(ok_domains)}\n")

        # Write top 10 abused TLDs to the file
        file.write("# Top 10 Abused TLDs:\n")
        for tld, count in tld_counts.most_common(10):
            percentage = (count / len(ok_domains)) * 100
            file.write(f"# {tld}: {count} ({percentage:.2f}%)\n")
        file.write(f"\n")
        # Write the OK domains to the file with the specified format
        for domain in sorted(ok_domains):
            file.write(f"||{domain}^\n")
