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
import shutil

# Configure logging to output to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define function to check if a domain is valid
def is_valid_domain(domain):
    return bool(re.match(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$', domain))

# Define function to load whitelist domains from a URL
def load_whitelist_domains():
    try:
        response = requests.get("https://raw.githubusercontent.com/xRuffKez/NXPhish/main/stor/white.list")
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException as e:
        logger.error("Failed to load whitelist domains: %s", e)
        return set()

# Define function to download and extract a CSV file
def download_extract_csv(url, destination_folder, use_cache=True):
    file_name = url.split('/')[-1]
    file_path = os.path.join(destination_folder, file_name)

    # Check if the file exists in the cache
    if use_cache and os.path.exists(file_path):
        logger.info("Using cached file: %s", file_path)
        return True, file_path

    try:
        # Attempt to download the file
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            f.write(response.content)
        
        if file_name.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(destination_folder)
                # Move the extracted CSV file from the subfolder to the destination folder
                extracted_folder = os.path.join(destination_folder, file_name.split('.')[0])
                extracted_csv_file = os.path.join(extracted_folder, os.listdir(extracted_folder)[0])
                shutil.move(extracted_csv_file, destination_folder)
                # Remove the empty extracted folder
                os.rmdir(extracted_folder)
        elif file_name.endswith('.csv'):
            # No need to extract CSV file
            pass
        else:
            logger.error("Unsupported file format: %s", file_name)
            return False, None

        return True, os.path.join(destination_folder, file_name.split('.')[0] + '.csv')
    except Exception as e:
        logger.error("Failed to download or extract file: %s", e)
        
        # If download fails and the file is Umbrella list, try to retrieve the file from the local repository directory
        if "umbrella" in url:
            local_file_path = os.path.join('stor', 'umbrella', file_name)
            if os.path.exists(local_file_path):
                logger.warning("Using local file from repository: %s", local_file_path)
                shutil.copy(local_file_path, destination_folder)
                return True, os.path.join(destination_folder, file_name)
        
        # If download and local retrieval fail, return False to indicate failure
        return False, None

# Define function to update phishing feed
def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'stor/cache.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'nxphish.agh')
    max_age = datetime.now() - timedelta(days=60)

    whitelist_domains = load_whitelist_domains()

    # Download and extract Umbrella CSV
    umbrella_csv_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    umbrella_success, umbrella_csv_file_path = download_extract_csv(umbrella_csv_url, workspace)
    if not umbrella_success:
        logger.error("Failed to download or extract Umbrella CSV file")
        return

    # Download and extract Tranco CSV
    tranco_csv_url = "https://tranco-list.eu/top-1m.csv.zip"
    tranco_success, tranco_csv_file_path = download_extract_csv(tranco_csv_url, workspace)
    if not tranco_success:
        logger.error("Failed to download or extract Tranco CSV file")
        return

    # Process Umbrella CSV
    umbrella_domains = process_csv(umbrella_csv_file_path)
    if umbrella_domains is None:
        return

    # Process Tranco CSV
    tranco_domains = process_csv(tranco_csv_file_path)
    if tranco_domains is None:
        return

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']

    try:
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
                        if domain not in whitelist_domains:
                            cursor.execute("SELECT domain, status FROM domains WHERE domain=?", (domain,))
                            existing_domain = cursor.fetchone()
                            if existing_domain is None or existing_domain[1] != 'OK':
                                status = resolve_domain_status(resolver, domain)
                                if status is not None:
                                    current_time = datetime.now().isoformat()
                                    cursor.execute("INSERT OR IGNORE INTO domains VALUES (?, ?, ?)", (domain, current_time, status))
            cursor.execute("UPDATE domains SET status='REMOVED' WHERE last_seen < ? AND status != 'OK'", (max_age.isoformat(),))
            cursor.execute("UPDATE domains SET status='WHITELIST' WHERE domain IN (SELECT domain FROM domains WHERE status = 'REMOVED')")
            cursor.execute("COMMIT")
            conn.commit()

            cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
            all_domains = cursor.fetchall()
            phishing_domains = [row[0] for row in all_domains if row[1] not in ('NXDOMAIN', 'SERVFAIL', 'WHITELIST')]

            # Remove domains containing parts of Umbrella and Tranco domains
            phishing_domains = filter_phishing_domains(phishing_domains, umbrella_domains, tranco_domains)

            # Update output file and cleanup
            write_output_file(output_path, phishing_domains, all_domains, umbrella_domains, tranco_domains, whitelist_domains)
            cleanup_files(umbrella_csv_file_path, tranco_csv_file_path)

    except Exception as e:
        logger.error("An error occurred during the update process: %s", e)

def process_csv(csv_file_path):
    try:
        with open(csv_file_path, 'r', encoding='latin-1') as csvfile:
            csv_reader = csv.reader(csvfile)
            return {row[1] for row in csv_reader if len(row) > 1}
    except Exception as e:
        logger.error("Failed to read CSV file '%s': %s", csv_file_path, e)
        return None

def resolve_domain_status(resolver, domain):
    try:
        response = resolver.resolve(domain)
        return "OK"
    except dns.resolver.Timeout:
        try:
            resolver_google = dns.resolver.Resolver()
            resolver_google.nameservers = ['8.8.8.8', '8.8.4.4']
            response_google = resolver_google.resolve(domain)
            if response_google.response.rcode() == dns.rcode.NXDOMAIN:
                return "NXDOMAIN"
            else:
                return "OK"
        except Exception as e:
            logger.error("Error resolving domain %s with Google DNS: %s", domain, e)
            return "SERVFAIL"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    except Exception as e:
        logger.error("Error resolving domain %s: %s", domain, e)
        return "SERVFAIL"

def filter_phishing_domains(phishing_domains, umbrella_domains, tranco_domains):
    filtered_domains = []
    for domain in phishing_domains:
        if not any(umbrella_domain in domain.split(".")[-2:] for umbrella_domain in umbrella_domains) \
                and not any(tranco_domain in domain.split(".")[-2:] for tranco_domain in tranco_domains):
            if not any(domain.endswith("." + subdomain) or subdomain.endswith("." + domain) for subdomain in phishing_domains if subdomain != domain):
                filtered_domains.append(domain)
    return filtered_domains

def write_output_file(output_path, phishing_domains, all_domains, umbrella_domains, tranco_domains, whitelist_domains):
    with open(output_path, 'w') as output_file:
        output_file.write("! Title: NXPhish - Active Phishing Domains\n")
        output_file.write("! Description: This file contains a list of known phishing domains from various feeds.\n")
        output_file.write("! URL shorteners have been removed to reduce false positives.\n")
        output_file.write("! Phishing domains have been checked against the top 1 million domains lists provided by Umbrella and Tranco.\n")
        output_file.write("! Author: xRuffKez\n")
        output_file.write("! Repository: github.com/xRuffKez/NXPhish\n")
        output_file.write("! Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        output_file.write("! Here are some stats (NXDOMAIN and SERVFAIL Domains are not listed in this File):\n")
        output_file.write("! Number of phishing domains: {}\n".format(len(phishing_domains)))
        output_file.write("! Number of NXDOMAIN domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'NXDOMAIN'])))
        output_file.write("! Number of SERVFAIL domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'SERVFAIL'])))
        output_file.write("! Number of domains removed by whitelist: {}\n".format(len(whitelist_domains.intersection(umbrella_domains | tranco_domains))))
        output_file.write("! Number of domains removed older than 60 days: {}\n".format(len([row[0] for row in all_domains if row[1] == 'REMOVED'])))
        output_file.write("! Number of domains removed by Umbrella list: {}\n".format(len(umbrella_domains)))
        output_file.write("! Number of domains removed by Tranco list: {}\n".format(len(tranco_domains)))
        output_file.write("\n")

        for domain in phishing_domains:
            output_file.write("||{}^\n".format(domain))

def cleanup_files(*file_paths):
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            logger.warning("File does not exist: %s", file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        logger.error("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
