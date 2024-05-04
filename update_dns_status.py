import sqlite3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

def resolve_domain(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
    try:
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
    db_path = "cache.db"
    max_age = datetime.now() - timedelta(days=60)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM domains ORDER BY RANDOM() LIMIT 2000")
    domains = cursor.fetchall()
    conn.close()
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(resolve_domain, (domain[0] for domain in domains))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for domain, result in zip(domains, results):
        domain = domain[0]
        cursor.execute("UPDATE domains SET status=? WHERE domain=?", (result, domain))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_dns_status()
