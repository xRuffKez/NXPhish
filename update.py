import sqlite3
from datetime import datetime, timedelta
import os

def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'openphish.agh')
    max_age = datetime.now() - timedelta(days=180)

    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS domains
                      (domain TEXT PRIMARY KEY, last_seen TEXT)''')
    
    # Update database with new domains
    with open(feed_path, 'r') as feed_file:
        domains = set(feed_file.read().splitlines())
        for domain in domains:
            cursor.execute("INSERT OR REPLACE INTO domains VALUES (?, ?)", (domain, datetime.now().isoformat()))

    # Remove domains older than 180 days
    cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

    # Fetch and sort domains
    cursor.execute("SELECT domain FROM domains ORDER BY domain")
    result = cursor.fetchall()
    domains = [row[0] for row in result]

    # Write sorted domains to file
    with open(output_path, 'w') as output_file:
        for domain in domains:
            output_file.write(domain + '\n')

    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    import sys
    update_phishfeed(sys.argv[1])
