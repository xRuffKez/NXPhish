import sqlite3
from datetime import datetime, timedelta
import os
import requests
import re
from urllib.parse import urlparse

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

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'openphish.agh')
    max_age = datetime.now() - timedelta(days=180)

    # Load whitelist domains
    whitelist_domains = load_whitelist_domains()

    # Connect to SQLite database using context manager
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Update database with new domains
        with open(feed_path, 'r') as feed_file:
            domains = set(map(lambda d: urlparse(d).netloc.split(":")[0], feed_file.read().splitlines()))
            domains.difference_update(whitelist_domains)  # Exclude whitelisted domains

            # Bulk insertion into the database
            if domains:
                current_time = datetime.now().isoformat()
                data = [(domain, current_time) for domain in domains]
                cursor.executemany("INSERT OR REPLACE INTO domains VALUES (?, ?)", data)

        # Remove domains older than 180 days
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

        # Fetch domains
        cursor.execute("SELECT domain FROM domains ORDER BY domain")
        domains = [row[0] for row in cursor.fetchall()]

        # Write sorted domains to file
        with open(output_path, 'w') as output_file:
            output_file.writelines("||" + domain + "^\n" for domain in domains)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
