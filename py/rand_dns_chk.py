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
        return "NXDOMAIN"
    except (dns.resolver.NoAnswer, dns.resolver.Timeout):
        return "SERVFAIL"
    except Exception as e:
        return str(e)

def update_dns_status(verbose=True):
    db_path = "stor/cache.db"
    max_age = datetime.now() - timedelta(days=60)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM domains WHERE status = 'OK' ORDER BY RANDOM() LIMIT 500")
        domains_to_check = cursor.fetchall()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = []
        for domain in domains_to_check:
            domain = domain[0]
            if verbose:
                print("Processing domain:", domain)
            new_status = resolve_domain(domain)
            results.append((new_status, domain))
            if verbose:
                print("Result for", domain, ":", new_status)

    # Update only if the status has changed
    updated_domains = [(status, domain) for status, domain in results if status != "OK"]

    if updated_domains:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany("UPDATE domains SET status=? WHERE domain=?", updated_domains)
            conn.commit()

if __name__ == "__main__":
    update_dns_status()
