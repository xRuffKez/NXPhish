import sqlite3
from datetime import datetime, timedelta
import os
import requests
import re
from urllib.parse import urlparse

def is_valid_domain(domain):
    # This function checks if the given string is a valid domain name and not an IP address
    # You can add more advanced validation logic if needed
    if re.match(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$', domain):
        return True
    else:
        return False

def load_whitelist_domains():
    whitelist_url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt"
    response = requests.get(whitelist_url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        domains = []
        for line in lines:
            # Remove @@||
            line = line.replace("@@||", "")
            # Remove leading ^
            line = line.lstrip("^")
            # Remove lines starting with [ or !
            if not line.startswith("[") and not line.startswith("!"):
                domains.append(line)
        return domains
    else:
        print("Failed to load whitelist domains:", response.status_code)
        return []

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'openphish.agh')
    max_age = datetime.now() - timedelta(days=180)

    # Load whitelist domains
    whitelist_domains = load_whitelist_domains()

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Update database with new domains
    with open(feed_path, 'r') as feed_file:
        domains = set(feed_file.read().splitlines())
        for domain in domains:
            parsed_domain = urlparse(domain)
            cleaned_domain = parsed_domain.netloc.split(":")[0]  # Remove port if present
            if is_valid_domain(cleaned_domain) and cleaned_domain not in whitelist_domains:
                cursor.execute("INSERT OR REPLACE INTO domains VALUES (?, ?)", (cleaned_domain, datetime.now().isoformat()))

    # Remove domains older than 180 days
    cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

    # Fetch and sort domains
    cursor.execute("SELECT domain FROM domains ORDER BY domain")
    result = cursor.fetchall()
    domains = [row[0] for row in result]

    # Write sorted domains to file with prefix
    with open(output_path, 'w') as output_file:
        for domain in domains:
            output_file.write("||" + domain + "^\n")

    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
