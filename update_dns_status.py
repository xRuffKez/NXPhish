import sqlite3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

def resolve_domain(domain):
    resolver = dns.resolver.Resolver()
    try:
        # Resolve the domain
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "SERVFAIL"
    except Exception as e:
        print(f"Error resolving domain {domain}: {e}")
        return "ERROR"

def update_dns_status():
    # Path to the cache.db file
    db_path = "cache.db"

    # Maximum age for domains to be considered
    max_age = datetime.now() - timedelta(days=60)

    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Retrieve domains from the database
    cursor.execute("SELECT domain FROM domains")
    domains = cursor.fetchall()

    # Close connection
    conn.close()

    # Multithreading DNS resolution
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = executor.map(resolve_domain, (domain[0] for domain in domains))

    # Connect again to update database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Update status for each domain in the database
    for domain, result in zip(domains, results):
        domain = domain[0]
        cursor.execute("UPDATE domains SET status=? WHERE domain=?", (result, domain))

    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_dns_status()
