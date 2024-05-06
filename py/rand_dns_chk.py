import sqlite3
import dns.resolver
import asyncio
import logging
from datetime import datetime, timedelta

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize DNS resolvers
resolver_custom = dns.resolver.Resolver()
resolver_custom.nameservers = ['76.76.2.0', '76.76.10.0']
resolver_google = dns.resolver.Resolver()
resolver_google.nameservers = ['8.8.8.8', '8.8.4.4']

async def resolve_domains(domains):
    results = {}
    for domain in domains:
        try:
            response = resolver_custom.resolve(domain)
            results[domain] = "OK"
            logging.debug(f"Resolved {domain}: OK")
        except dns.resolver.NXDOMAIN:
            results[domain] = "NXDOMAIN"
            logging.debug(f"Resolved {domain}: NXDOMAIN")
        except dns.resolver.NoNameservers:
            results[domain] = "SERVFAIL"
            logging.debug(f"Resolved {domain}: SERVFAIL - No nameservers available")
        except dns.resolver.LifetimeTimeout:
            results[domain] = "SERVFAIL"
            logging.debug(f"Resolved {domain}: SERVFAIL - Resolution lifetime expired")
        except (dns.resolver.NoAnswer, dns.resolver.Timeout) as ex:
            try:
                response = resolver_google.resolve(domain)
                results[domain] = "OK"
                logging.debug(f"Resolved {domain}: OK")
            except (dns.resolver.Timeout, dns.resolver.NoAnswer) as ex:
                results[domain] = "SERVFAIL"
                logging.debug(f"Resolved {domain}: SERVFAIL - {ex}")
            except dns.resolver.NXDOMAIN as ex:
                results[domain] = "NXDOMAIN"
                logging.debug(f"Resolved {domain}: NXDOMAIN - {ex}")
        except Exception as e:
            results[domain] = "SERVFAIL"
            logging.exception(f"Resolved {domain}: SERVFAIL - {e}")
    return results

async def update_dns_status():
    db_path = "stor/cache.db"
    max_age = datetime.now() - timedelta(days=60)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM domains WHERE status = 'OK' ORDER BY RANDOM() LIMIT 5000")
        domains_to_check = [row[0] for row in cursor.fetchall()]

    # Split domains into chunks for parallel resolution
    chunk_size = 100
    chunks = [domains_to_check[i:i + chunk_size] for i in range(0, len(domains_to_check), chunk_size)]

    results = await asyncio.gather(*(resolve_domains(chunk) for chunk in chunks))

    # Flatten results
    results = {k: v for d in results for k, v in d.items()}

    # Update database
    updated_domains = [(status, domain) for domain, status in results.items() if status != "OK"]
    if updated_domains:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.executemany("UPDATE domains SET status=? WHERE domain=?", updated_domains)
            conn.commit()

async def main():
    await update_dns_status()

if __name__ == "__main__":
    asyncio.run(main())
