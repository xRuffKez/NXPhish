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
        return str(e)

def update_dns_status():
    db_path = "stor/cache.db"
    max_age = datetime.now() - timedelta(days=60)

    # Open database connection
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, status FROM domains WHERE status NOT IN (?, ?) ORDER BY RANDOM() LIMIT 2000",
                       ("NXDOMAIN", "SERVFAIL"))
        domains_to_check = cursor.fetchall()

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(resolve_domain, [domain for domain, _ in domains_to_check])
    
    # Open database connection again for updating
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        update_values = [(result, domain) for (domain, _), result in zip(domains_to_check, results) if result is not None]
        cursor.executemany("UPDATE domains SET status=? WHERE domain=?", update_values)
        conn.commit()

if __name__ == "__main__":
    update_dns_status()
