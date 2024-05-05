import sqlite3
import requests
import dns.resolver
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_dns_status(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['76.76.2.0', '76.76.10.0']
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except (dns.resolver.NoAnswer, dns.resolver.Timeout):
        try:
            # If resolver timed out, try resolving with Google's DNS servers
            resolver_google = dns.resolver.Resolver()
            resolver_google.nameservers = ['8.8.8.8', '8.8.4.4']  # Google's DNS servers
            resolver_google.timeout = 10  # Set timeout to 10 seconds for Google DNS
            response_google = resolver_google.resolve(domain)
            return "OK"
        except (dns.resolver.Timeout, dns.resolver.NoAnswer):
            return "SERVFAIL"
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"
    except Exception as e:
        return "SERVFAIL"

def process_domains_not_in_database():
    url = "https://raw.githubusercontent.com/Zaczero/pihole-phishtank/main/hosts.txt"
    try:
        response = requests.get(url)
        response.raise_for_status()
        domains = response.text.splitlines()
        domains = [domain.strip() for domain in domains if domain.strip() and not domain.strip().startswith('#')]
        
        conn = sqlite3.connect("stor/cache.db")
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
    db_path = "stor/cache.db"
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
