import sqlite3
import requests
import dns.resolver
from datetime import datetime
import os
import re

# Function to check if a domain is valid
def is_valid_domain(domain):
    # Regular expression to match domain name format
    domain_regex = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$'
    return bool(re.match(domain_regex, domain))

# Function to check DNS status for a domain
def check_dns_status(domain):
    try:
        resolver = dns.resolver.Resolver()
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "SERVFAIL"
    except Exception as e:
        print("Error resolving domain {}: {}".format(domain, e))
        return "ERROR"

# Function to process domains from the given URL
def process_domains():
    url = "https://raw.githubusercontent.com/Zaczero/pihole-phishtank/main/hosts.txt"
    try:
        response = requests.get(url)
        response.raise_for_status()
        domains = response.text.splitlines()
        # Ignore empty lines and lines starting with '#'
        domains = [domain.strip() for domain in domains if domain.strip() and not domain.strip().startswith('#')]
        return domains
    except requests.RequestException as e:
        print("Failed to fetch domains from {}: {}".format(url, e))
        return []

# Function to update the database with new domains
def update_database(domains):
    db_path = "cache.db"
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        for domain in domains:
            if is_valid_domain(domain):
                status = check_dns_status(domain)
                if status == "OK":
                    cursor.execute("INSERT OR IGNORE INTO domains (domain, age, status) VALUES (?, ?, ?)", (domain, datetime.now(), status))
        conn.commit()
        conn.close()
        print("Database updated successfully.")
    except Exception as e:
        print("Failed to update database: {}".format(e))

# Function to push the cache.db file to the repository
def push_cache_db():
    os.system("git add cache.db")
    os.system("git commit -m 'Update cache.db'")
    os.system("git push")

# Main function
def main():
    domains = process_domains()
    if domains:
        update_database(domains)
        push_cache_db()

if __name__ == "__main__":
    main()
