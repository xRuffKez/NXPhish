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
    except dns.resolver.SERVFAIL:
        return None
    except dns.resolver.REFUSED:
        return None
    except Exception as e:
        return str(e)

def update_dns_status(verbose=True):
    db_path = "stor/cache.db"
    max_age = datetime.now() - timedelta(days=60)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, status FROM domains WHERE status NOT IN (?, ?) ORDER BY RANDOM() LIMIT 5000",
                       ("NXDOMAIN", "SERVFAIL", "REFUSED"))
        domains_to_check = cursor.fetchall()

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = []
        for domain, _ in domains_to_check:
            if verbose:
                print("Processing domain:", domain)
            result = resolve_domain(domain)
            results.append(result)
            if verbose:
                print("Result for", domain, ":", result)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        update_values = [(result, domain) for (domain, _), result in zip(domains_to_check, results) if result is not None]
        cursor.executemany("UPDATE domains SET status=? WHERE domain=?", update_values)
        conn.commit()

if __name__ == "__main__":
    update_dns_status()
