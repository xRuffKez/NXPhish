import json
import hashlib
from datetime import datetime, timedelta
from collections import Counter

# Read the JSON file
with open("warehouse.json", "r") as file:
    data = json.load(file)

# Create a list to store the domains with DNS status "OK"
ok_domains = []

# Extract domains and count excluded responses
excluded_servfail = 0
excluded_nxdomain = 0

for entry in data:
    if entry["dns_status"] == "SERVFAIL":
        excluded_servfail += 1
    elif entry["dns_status"] == "NXDOMAIN":
        excluded_nxdomain += 1
    elif entry["dns_status"] == "OK":
        ok_domains.append(entry["domain"])

# Remove duplicates
ok_domains = sorted(set(ok_domains))

# Calculate top 10 abused TLDs for OK domains only
tlds = [domain.split(".")[-1] for domain in ok_domains]
tld_counts = Counter(tlds).most_common(10)
total_domains = len(ok_domains)

# Get current Unix timestamp
generation_time = int(datetime.now().timestamp())

# Calculate SHA-1 hash of the JSON data
json_hash = hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()

# Write the list to nxphish.agh
with open("nxphish.agh", "w") as file:
    file.write("# Title: NXPhish\n")
    file.write("# Author: xRuffKez\n")
    file.write(f"# Version: {generation_time}\n")  # Write Unix timestamp as version
    file.write(f"# Database Hash: {json_hash}\n")  # Write SHA-1 hash of JSON data
    file.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \n")
    file.write(f"# Expires: 1 day\n")
    file.write("# Statistics:\n")
    file.write(f"# Number of phishing domains: {len(ok_domains)}\n")
    file.write(f"# Number of excluded SERVFAIL responses: {excluded_servfail}\n")
    file.write(f"# Number of excluded NXDOMAIN responses: {excluded_nxdomain}\n")

    # Write top 10 abused TLDs to the comment section
    file.write("# Top 10 Abused TLDs for OK domains:\n")
    for tld, count in tld_counts:
        percentage = (count / total_domains) * 100
        file.write(f"# {tld}: {count} ({percentage:.2f}%)\n")

    file.write("\n")

    # Write the OK domains to the file with the specified format
    for domain in ok_domains:
        file.write(f"||{domain}^\n")
