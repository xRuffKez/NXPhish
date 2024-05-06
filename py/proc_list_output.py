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
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Domain validation regex 
DOMAIN_REGEX = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[a-Za-z0-9])$'

# DNS cache
dns_cache = {}

# Function to check if a domain is valid
def is_valid_domain(domain):
    return bool(re.match(DOMAIN_REGEX, domain))

# Function to load whitelist domains from a URL
def load_whitelist_domains():
    url = "https://raw.githubusercontent.com/xRuffKez/NXPhish/main/stor/white.list"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException as e:
        logger.error("Failed to load whitelist domains: %s", e)
        return set()

# Function to download and extract a CSV file
def download_extract_csv(url, destination_folder, use_cache=True):
    file_name = url.split('/')[-1]
    file_path = os.path.join(destination_folder, file_name)

    if use_cache and os.path.exists(file_path):
        logger.info("Using cached file: %s", file_path)
        return True, file_path

    try:
        response = requests.get(url, stream=True, allow_redirects=True)
        response.raise_for_status()  

        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:  
                    f.write(chunk)

        if file_name.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(destination_folder)
                extracted_folder = os.path.join(destination_folder, file_name.split('.')[0])
                extracted_csv_file = os.path.join(extracted_folder, os.listdir(extracted_folder)[0])

                # Debugging:
                print("Extracted Folder:", extracted_folder)
                print("Files inside Extracted Folder:", os.listdir(extracted_folder)) 

                shutil.move(extracted_csv_file, destination_folder)
                os.rmdir(extracted_folder)
        elif file_name.endswith('.csv'):
            pass
        else:
            logger.error("Unsupported file format: %s", file_name)
            return False, None

        return True, os.path.join(destination_folder, file_name.split('.')[0] + '.csv')

    except Exception as e:
        logger.error("Failed to download or extract file: %s", e)
        return False, None

# Define function to update phishing feed
def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'stor/cache.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'nxphish.agh')
    max_age = datetime.now() - timedelta(days=60)

    whitelist_domains = load_whitelist_domains()
    white_list_file = os.path.join(workspace, 'white.list')

    # Download and extract Umbrella CSV
    umbrella_csv_url = "https://gist.githubusercontent.com/josedacosta/aeeed2a80e890921d5273da56c50ae41/raw/266219a61a7f3957da183e102ae20f61d654991a/Cisco-Umbrella-TOP-1-Million.csv"
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
                                continue  # Skip if the domain status is not 'OK'
                            status = existing_domain[1]
                            current_time = datetime.now().isoformat()
                            cursor.execute("INSERT OR IGNORE INTO domains VALUES (?, ?, ?)", (domain, current_time, status))
            cursor.execute("UPDATE domains SET status='REMOVED' WHERE last_seen < ? AND status != 'OK'", (max_age.isoformat(),))
            cursor.execute("UPDATE domains SET status='WHITELIST' WHERE domain IN (SELECT domain FROM domains WHERE status = 'REMOVED')")
            cursor.execute("COMMIT")
            conn.commit()

            cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
            all_domains = cursor.fetchall()
            phishing_domains = [row[0] for row in all_domains]

            # Remove domains containing parts of Umbrella and Tranco domains
            phishing_domains = filter_phishing_domains(phishing_domains, umbrella_domains, tranco_domains, whitelist_domains)

            # Update output file and cleanup
            write_output_file(output_path, phishing_domains, all_domains, umbrella_domains, tranco_domains, whitelist_domains)
            cleanup_files(umbrella_csv_file_path, tranco_csv_file_path)

            # Count NXDOMAIN and SERVFAIL domains from cache.db
            nxdomain_count = sum(1 for row in all_domains if row[1] == 'NXDOMAIN')
            servfail_count = sum(1 for row in all_domains if row[1] == 'SERVFAIL')

            # Write statistics to the output file
            with open(output_path, 'a') as output_file:
                output_file.write("! Number of NXDOMAIN domains in cache.db: {}\n".format(nxdomain_count))
                output_file.write("! Number of SERVFAIL domains in cache.db: {}\n".format(servfail_count))

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

def filter_phishing_domains(phishing_domains, umbrella_domains, tranco_domains, whitelist_domains):
    filtered_domains = []
    for domain in phishing_domains:
        if not any(umbrella_domain in domain.split(".")[-2:] for umbrella_domain in umbrella_domains) \
                and not any(tranco_domain in domain.split(".")[-2:] for tranco_domain in tranco_domains):
            if not any(domain.endswith("." + subdomain) or subdomain.endswith("." + domain) for subdomain in phishing_domains if subdomain != domain):
                if not any(domain.endswith("." + subdomain) or subdomain.endswith("." + domain) for subdomain in whitelist_domains if subdomain != domain):
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
        output_file.write("! Number of domains matched and removed by Tranco: {}\n".format(len(tranco_domains)))
        output_file.write("! Number of domains matched and removed by Umbrella: {}\n".format(len(umbrella_domains)))
        output_file.write("! Number of domains matched and removed by white.list: {}\n".format(len(whitelist_domains.intersection(umbrella_domains | tranco_domains))))
        output_file.write("! Number of domains removed older than 60 days: {}\n".format(len([row[0] for row in all_domains if row[1] == 'REMOVED'])))
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
