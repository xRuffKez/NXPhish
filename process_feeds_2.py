import sqlite3
import requests
import dns.resolver
from datetime import datetime
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to check DNS status for a domain
def check_dns_status(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "SERVFAIL"
    except Exception as e:
        logging.error("Error resolving domain %s: %s", domain, e)
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
        logging.error("Failed to fetch domains from %s: %s", url, e)
        return []

# Function to update the database with new domains
def update_database():
    db_path = "cache.db"
    domains = process_domains()
    if not domains:
        logging.info("No domains to process.")
        return

    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        # Register the custom adapter for datetime objects
        sqlite3.register_adapter(datetime, lambda val: val.isoformat())
        cursor = conn.cursor()
        for domain in domains:
            status = check_dns_status(domain)
            if status == "OK":
                cursor.execute("INSERT OR IGNORE INTO domains (domain, last_seen, status) VALUES (?, ?, ?)", (domain, datetime.now(), status))
        conn.commit()
        logging.info("Database updated successfully.")
    except Exception as e:
        logging.error("Failed to update database: %s", e)
    finally:
        # Close the database connection
        conn.close()

# Main function
def main():
    update_database()

if __name__ == "__main__":
    main()
