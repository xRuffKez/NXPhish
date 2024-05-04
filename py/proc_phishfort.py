import sqlite3
import requests
import dns.resolver
from datetime import datetime
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def process_domains_not_in_database():
    url = "https://raw.githubusercontent.com/phishfort/phishfort-lists/master/blacklists/domains.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        domains = response.json()
        
        conn = sqlite3.connect("cache.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT domain FROM domains")
        existing_domains = set(row[0] for row in cursor.fetchall())
        
        domains_not_in_database = [domain for domain in domains if domain not in existing_domains]
        
        conn.close()
        
        return domains_not_in_database
    except requests.RequestException as e:
        logging.error("Failed to fetch domains from %s: %s", url, e)
        return []

def update_database():
    db_path = "cache.db"
    domains = process_domains_not_in_database()
    if not domains:
        logging.info("No new domains to process.")
        return

    try:
        conn = sqlite3.connect(db_path)
        sqlite3.register_adapter(datetime, lambda val: val.isoformat())
        cursor = conn.cursor()
        for domain in domains:
            cursor.execute("SELECT COUNT(*) FROM domains WHERE domain = ?", (domain,))
            result = cursor.fetchone()
            if result[0] == 0:
                status = check_dns_status(domain)
                if status in ["OK", "NXDOMAIN", "SERVFAIL", "ERROR"]:
                    cursor.execute("INSERT INTO domains (domain, last_seen, status) VALUES (?, ?, ?)", (domain, datetime.now(), status))
            else:
                logging.info("Domain %s already exists in the database, skipping DNS check.", domain)
        conn.commit()
        logging.info("Database updated successfully.")
    except Exception as e:
        logging.error("Failed to update database: %s", e)
    finally:
        conn.close()

def main():
    update_database()

if __name__ == "__main__":
    main()
