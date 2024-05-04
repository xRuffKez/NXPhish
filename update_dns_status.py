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
        return None
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        print(f"Error resolving domain {domain}: {e}")
        return None

def update_dns_status():
    db_path = "cache.db"
    max_age = datetime.now() - timedelta(days=60)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, status FROM domains ORDER BY RANDOM() LIMIT 2000")
    domains = cursor.fetchall()
    conn.close()

    domains_to_check = [(domain, status) for domain, status in domains if status not in ["NXDOMAIN", "SERVFAIL"]]

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(resolve_domain, [domain for domain, _ in domains_to_check])
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for (domain, status), result in zip(domains_to_check, results):
        if result is not None:
            cursor.execute("UPDATE domains SET status=? WHERE domain=?", (result, domain))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    update_dns_status()
