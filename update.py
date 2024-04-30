import sqlite3
from datetime import datetime, timedelta
import os
import requests
from urllib.parse import urlparse

def is_valid_domain(domain):
    # This function checks if the given string is a valid domain name
    # You can add more advanced validation logic if needed
    return '.' in domain

def load_whitelist_domains():
    whitelist_url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt"
    response = requests.get(whitelist_url)
    if response.status_code == 200:
        return response.text.splitlines()
    else:
        print("Failed to load whitelist domains:", response.status_code)
        return []

def load_repository_domains():
    repository_path = "white.list"
    if os.path.exists(repository_path):
        with open(repository_path, 'r') as file:
            return file.read().splitlines()
    else:
        print("Repository domains file not found:", repository_path)
        return []

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'openphish.agh')
    max_age = datetime.now() - timedelta(days=180)

    # Load whitelist domains
    whitelist_domains = load_whitelist_domains()

    # Load domains from repository
    repository_domains = load_repository_domains()

    # Combine whitelist and repository domains
    all_domains = set(whitelist_domains + repository_domains)

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Update database with new domains
    with open(feed_path, 'r') as feed_file:
        domains = set(feed_file.read().splitlines())
        for domain in domains:
            parsed_domain = urlparse(domain)
            cleaned_domain = parsed_domain.netloc.split(":")[0]  # Remove port if present
            if is_valid_domain(cleaned_domain) and cleaned_domain not in all_domains:
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
