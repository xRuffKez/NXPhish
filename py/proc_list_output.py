import sqlite3
import os
import requests
import re
import csv
import zipfile
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
import dns.resolver

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_valid_domain(domain):
    return bool(re.match(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$', domain))

def load_whitelist_domains():
    try:
        response = requests.get("https://raw.githubusercontent.com/xRuffKez/NXPhish/main/stor/white.list")
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException as e:
        logger.error("Failed to load whitelist domains: %s", e)
        return set()

def download_extract_csv(url, destination_folder):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(os.path.join(destination_folder, 'top-1m.csv.zip'), 'wb') as f:
            f.write(response.content)
        with zipfile.ZipFile(os.path.join(destination_folder, 'top-1m.csv.zip'), 'r') as zip_ref:
            zip_ref.extractall(destination_folder)
        return True
    except Exception as e:
        logger.error("Failed to download and extract CSV file: %s", e)
        return False

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'stor/cache.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'nxphish.agh')
    max_age = datetime.now() - timedelta(days=60)

    whitelist_domains = load_whitelist_domains()

    csv_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    if not download_extract_csv(csv_url, workspace):
        return

    csv_file_path = os.path.join(workspace, "top-1m.csv")
    with open(csv_file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        domains_to_remove = {row[1] for row in csv_reader}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, last_seen TEXT, status TEXT)")
        cursor.execute("BEGIN TRANSACTION")
        with open(feed_path, 'r') as feed_file:
            for line in feed_file:
                domain = urlparse(line.strip()).netloc.split(":")[0]
                if domain:
                    if not domain.startswith("http") and "/" in domain:
                        domain = domain.split("/")[0]
                    if domain not in whitelist_domains and domain not in domains_to_remove:
                        cursor.execute("SELECT domain FROM domains WHERE domain=?", (domain,))
                        existing_domain = cursor.fetchone()
                        if existing_domain is None:
                            try:
                                response = resolver.resolve(domain)
                                status = "OK"
                            except dns.resolver.NXDOMAIN:
                                status = "NXDOMAIN"
                            except dns.resolver.NoAnswer:
                                status = "SERVFAIL"
                            except Exception as e:
                                logger.error("Error resolving domain %s: %s", domain, e)
                                status = "ERROR"
                            current_time = datetime.now().isoformat()
                            cursor.execute("INSERT INTO domains VALUES (?, ?, ?)", (domain, current_time, status))
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))
        cursor.execute("COMMIT")
        conn.commit()

        cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
        all_domains = cursor.fetchall()
        phishing_domains = [row[0] for row in all_domains if row[1] != 'NXDOMAIN' and row[1] != 'SERVFAIL']
        tld_counts = {}
        for domain in all_domains:
            tld = domain[0].split('.')[-1]
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
        sorted_tlds = sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        total_domains = sum(count for _, count in sorted_tlds)

        with open(output_path, 'w') as output_file:
            output_file.write("! Title: NXPhish - Active Phishing Domains\n")
            output_file.write("! Description: This file contains a list of known phishing domains from various feeds.\n")
            output_file.write("! URL shorteners have been removed to reduce false positives.\n")
            output_file.write("! Phishing domains have been checked against the top 1 million domains list provided by Umbrella.\n")
            output_file.write("! Author: xRuffKez\n")
            output_file.write("! Repository: github.com/xRuffKez/NXPhish\n")
            output_file.write("! Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_file.write("! Here are some stats (NXDOMAIN and SERVFAIL Domains are not listed in this File):\n")
            output_file.write("! Number of phishing domains: {}\n".format(len(phishing_domains)))
            output_file.write("! Number of NXDOMAIN domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'NXDOMAIN'])))
            output_file.write("! Number of SERVFAIL domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'SERVFAIL'])))
            output_file.write("! Number of domains removed by whitelist: {}\n".format(len(whitelist_domains.intersection(domains_to_remove))))
            output_file.write("! Top 10 abused TLDs:\n")
            for tld, count in sorted_tlds:
                percentage_tld_domains = (count / total_domains) * 100
                output_file.write("! - {}: {} ({}%)\n".format(tld, count, round(percentage_tld_domains, 2)))
            output_file.write("! Domains removed after 60 days if not re-added through feed.\n")
            output_file.write("\n")
            for domain in phishing_domains:
                output_file.write("||{}^\n".format(domain))
    conn.close()
    os.remove(csv_file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        logger.error("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
