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
    output_path = os.path.join(workspace, 'nxphish.agh')
    max_age = datetime.now() - timedelta(days=60)

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
        cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, last_seen TEXT, status TEXT)")
        cursor.execute("BEGIN TRANSACTION")

        # Update database with new domains
        with open(feed_path, 'r') as feed_file:
            for line in feed_file:
                domain = urlparse(line.strip()).netloc.split(":")[0]
                if domain not in whitelist_domains and domain not in domains_to_remove:
                    status = "SERVFAIL" if "SERVFAIL" in line else ("NXDOMAIN" if "NXDOMAIN" in line else "OK")
                    current_time = datetime.now().isoformat()
                    cursor.execute("INSERT OR REPLACE INTO domains VALUES (?, ?, ?)", (domain, current_time, status))

        # Remove domains older than 60 days
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

        # Commit transaction
        cursor.execute("COMMIT")

        # Fetch domains for nxphish.agh
        cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
        all_domains = cursor.fetchall()
        phishing_domains = [row[0] for row in all_domains if row[1] == 'OK']
        nxdomains = [row[0] for row in all_domains if row[1] == 'NXDOMAIN']
        servfails = [row[0] for row in all_domains if row[1] == 'SERVFAIL']
        removed_by_whitelist = len(whitelist_domains.intersection(domains_to_remove))

        # Write sorted domains to file
        with open(output_path, 'w') as output_file:
            output_file.write("! Title: OpenPhish and Phishunt Feed - Phishing Domains\n")
            output_file.write("! Description: This file contains a list of known phishing domains from the OpenPhish and Phishunt feed.\n")
            output_file.write("! URL shorteners have been removed to reduce false positives.\n")
            output_file.write("! Phishing domains have been checked against the top 1 million domains list provided by Umbrella.\n")
            output_file.write("! Author: xRuffKez\n")
            output_file.write("! Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_file.write("! Number of phishing domains: {}\n".format(len(phishing_domains)))
            output_file.write("! Number of NXDOMAIN domains: {}\n".format(len(nxdomains)))
            output_file.write("! Number of SERVFAIL domains: {}\n".format(len(servfails)))
            output_file.write("! Number of domains removed by whitelist: {}\n".format(removed_by_whitelist))
            output_file.write("! Domains removed after 60 days if not re-added through feed.\n")
            output_file.write("\n")
            for domain in phishing_domains:
                output_file.write("||{}^\n".format(domain))

    # Clean up CSV file
    os.remove(csv_file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
