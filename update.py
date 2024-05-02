import sqlite3
import os
import requests
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
import csv
import zipfile

def is_valid_domain(domain):
    # Improved regular expression for domain validation
    return bool(re.match(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$', domain))

def load_whitelist_domains():
    whitelist_url = "https://raw.githubusercontent.com/xRuffKez/NXPhish/main/white.list"
    try:
        response = requests.get(whitelist_url)
        response.raise_for_status()  # Raise exception for HTTP errors
        return set(response.text.splitlines())
    except requests.RequestException as e:
        print("Failed to load whitelist domains:", e)
        return set()

def download_extract_csv(url, destination_folder):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise exception for HTTP errors

        with open(os.path.join(destination_folder, 'top-1m.csv.zip'), 'wb') as f:
            f.write(response.content)

        # Extract the zip file
        with zipfile.ZipFile(os.path.join(destination_folder, 'top-1m.csv.zip'), 'r') as zip_ref:
            zip_ref.extractall(destination_folder)

        return True
    except Exception as e:
        print("Failed to download and extract CSV file:", e)
        return False

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'openphish.agh')
    max_age = datetime.now() - timedelta(days=180)

    # Load whitelist domains
    whitelist_domains = load_whitelist_domains()

    # Download and extract CSV file
    csv_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    if not download_extract_csv(csv_url, workspace):
        return

    # Read CSV file and extract domains
    csv_file_path = os.path.join(workspace, "top-1m.csv")
    with open(csv_file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        domains_to_remove = {row[1] for row in csv_reader}

    # Connect to SQLite database using context manager
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Start transaction
        cursor.execute("BEGIN TRANSACTION")

        # Update database with new domains
        with open(feed_path, 'r') as feed_file:
            domains = {urlparse(d).netloc.split(":")[0] for d in feed_file}
            domains -= whitelist_domains
            domains -= domains_to_remove

            # Remove subdomains with 'www' and IPv4 addresses
            domains = {re.sub(r'^www\d*\.', '', domain) for domain in domains if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain)}

            if domains:
                current_time = datetime.now().isoformat()
                data = [(domain, current_time) for domain in domains]
                cursor.executemany("INSERT OR REPLACE INTO domains VALUES (?, ?)", data)

        # Remove domains older than 180 days
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

        # Commit transaction
        cursor.execute("COMMIT")

        # Fetch domains with their ages
        cursor.execute("SELECT domain, (julianday('now') - julianday(last_seen)) as age FROM domains ORDER BY domain")
        domains_with_info = [(row[0], int(row[1])) for row in cursor.fetchall()]

        # Write sorted domains with their ages to file
        with open(output_path, 'w') as output_file:
            output_file.write("! Title: OpenPhish Feed - Phishing Domains\n")
            output_file.write("! Description: This file contains a list of known phishing domains from the OpenPhish feed.\n")
            output_file.write("! URL shorteners have been removed to reduce false positives.\n")
            output_file.write("! Phishing domains have been checked against the top 1 million domains list provided by Umbrella.\n")
            output_file.write("! Author: xRuffKez\n")
            output_file.write("! Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_file.write("! Number of phishing domains: {}\n".format(len(domains_with_info)))
            output_file.write("! Removed duplicates: {}\n".format(len(domains_with_info) - len(set(domain for domain, _ in domains_with_info))))
            output_file.write("! Domains removed based on white.list: {}\n".format(len(whitelist_domains)))
            output_file.write("! Domains removed after 180 days if not re-added through feed.\n")
            output_file.write("\n")
            for domain, age in domains_with_info:
                output_file.write("||{}^ # Domain age in Database: {} days\n".format(domain, age))

    # Clean up CSV file
    os.remove(csv_file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
