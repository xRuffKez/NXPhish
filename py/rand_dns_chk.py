import sqlite3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

def resolve_domain(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return str(e)

def update_dns_status(verbose=True):
    db_path = "stor/cache.db"
    max_age = datetime.now() - timedelta(days=60)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, status FROM domains WHERE status NOT IN (?, ?) ORDER BY RANDOM() LIMIT 5000",
                       ("NXDOMAIN", "SERVFAIL"))
        domains_to_check = cursor.fetchall()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = []
        for domain, existing_status in domains_to_check:
            if verbose:
                print("Processing domain:", domain)
            new_status = resolve_domain(domain)
            results.append((domain, new_status))
            if verbose:
                print("Result for", domain, ":", new_status)

    # Update only if the status has changed
    updated_domains = [(new_status, domain) for domain, new_status in results if new_status is not None and new_status != existing_status]

    if updated_domains:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany("UPDATE domains SET status=? WHERE domain=?", updated_domains)
            conn.commit()

if __name__ == "__main__":
    update_dns_status()
