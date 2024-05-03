import sqlite3
import dns.resolver
import os
from datetime import datetime, timedelta

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

    # Resolver object for DNS resolution
    resolver = dns.resolver.Resolver()

    # Update status for each domain
    for domain in domains:
        domain = domain[0]
        try:
            # Resolve the domain
            response = resolver.resolve(domain)
            status = "OK"
        except dns.resolver.NXDOMAIN:
            status = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            status = "SERVFAIL"
        except Exception as e:
            print(f"Error resolving domain {domain}: {e}")
            status = "ERROR"

        # Update status in the database
        cursor.execute("UPDATE domains SET status=? WHERE domain=?", (status, domain))

    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_dns_status()
