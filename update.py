import sqlite3
from datetime import datetime, timedelta
import os
import requests
import re
from urllib.parse import urlparse
import zipfile
import csv

def is_valid_domain(domain):
    return bool(re.match(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$', domain))

def load_whitelist_domains():
    whitelist_url = "https://raw.githubusercontent.com/xRuffKez/NXPhish/main/white.list"
    try:
        response = requests.get(whitelist_url)
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException as e:
        print("Failed to load whitelist domains:", e)
        return set()

def download_extract_csv(url, target_dir):
    try:
        response = requests.get(url)
        response.raise_for_status()
        zip_file_path = os.path.join(target_dir, "top-1m.csv.zip")
        with open(zip_file_path, 'wb') as f:
            f.write(response.content)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(target_dir)
        os.remove(zip_file_path)
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

            if domains:
                current_time = datetime.now().isoformat()
                data = [(domain, current_time) for domain in domains]
                cursor.executemany("INSERT OR REPLACE INTO domains VALUES (?, ?)", data)

        # Remove domains older than 180 days
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

        # Commit transaction
        cursor.execute("COMMIT")

        # Fetch domains
        cursor.execute("SELECT domain FROM domains ORDER BY domain")
        domains = [row[0] for row in cursor.fetchall()]

        # Write sorted domains to file
        with open(output_path, 'w') as output_file:
            output_file.writelines("||" + domain + "^\n" for domain in domains)

    # Clean up CSV file
    os.remove(csv_file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
