import json
import hashlib
from datetime import datetime
from collections import Counter

def read_json_file(filename):
    with open(filename, "r") as file:
        return json.load(file)

def calculate_sha1_hash(data):
    return hashlib.sha1(json.dumps(data, sort_keys=True).encode()).hexdigest()

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

def main():
    data = read_json_file("warehouse.json")
    json_hash = calculate_sha1_hash(data)
    existing_hash = get_existing_hash("nxphish.agh")

    if existing_hash != json_hash:
        ok_domains, tld_counts = collect_ok_domains(data)
        write_output_file("nxphish.agh", json_hash, ok_domains, tld_counts)
        print("nxphish.agh has been updated.")
    else:
        print("No changes detected. nxphish.agh is up to date.")

if __name__ == "__main__":
    main()
