import sqlite3
import os
import requests
import re
import csv
import zipfile
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Konfiguration des Loggings
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_domain(domain):
    """Überprüft, ob eine Domain gültig ist."""
    return bool(re.match(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$', domain))

def load_whitelist_domains():
    """Lädt die Whitelist-Domänen aus einer URL."""
    whitelist_url = "https://raw.githubusercontent.com/xRuffKez/NXPhish/main/white.list"
    try:
        response = requests.get(whitelist_url)
        response.raise_for_status()  # Raise exception for HTTP errors
        return set(response.text.splitlines())
    except requests.RequestException as e:
        logger.error("Failed to load whitelist domains: %s", e)
        return set()

def download_extract_csv(url, destination_folder):
    """Lädt eine CSV-Datei von einer URL herunter und extrahiert sie."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise exception for HTTP errors

        with open(os.path.join(destination_folder, 'top-1m.csv.zip'), 'wb') as f:
            f.write(response.content)

        # Extrahiert die ZIP-Datei
        with zipfile.ZipFile(os.path.join(destination_folder, 'top-1m.csv.zip'), 'r') as zip_ref:
            zip_ref.extractall(destination_folder)

        return True
    except Exception as e:
        logger.error("Failed to download and extract CSV file: %s", e)
        return False

def update_phishfeed(workspace):
    """Aktualisiert den Phishing-Feed."""
    db_path = os.path.join(workspace, 'database.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'nxphish.agh')
    cache_db_path = os.path.join(workspace, 'cache.db')
    max_age = datetime.now() - timedelta(days=60)

    # Lädt die Whitelist-Domänen
    whitelist_domains = load_whitelist_domains()

    # Lädt und extrahiert die CSV-Datei
    csv_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    if not download_extract_csv(csv_url, workspace):
        return

    # Liest die CSV-Datei und extrahiert die Domänen
    csv_file_path = os.path.join(workspace, "top-1m.csv")
    with open(csv_file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        domains_to_remove = {row[1] for row in csv_reader}

    # Verbindung zur SQLite-Datenbank herstellen
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Transaktion starten
        cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, last_seen TEXT, status TEXT)")
        cursor.execute("BEGIN TRANSACTION")

        # Datenbank mit neuen Domänen aktualisieren
        with open(feed_path, 'r') as feed_file:
            for line in feed_file:
                domain = urlparse(line.strip()).netloc.split(":")[0]
                if domain not in whitelist_domains and domain not in domains_to_remove:
                    status = "SERVFAIL" if "SERVFAIL" in line else ("NXDOMAIN" if "NXDOMAIN" in line else "OK")
                    current_time = datetime.now().isoformat()
                    cursor.execute("INSERT OR REPLACE INTO domains VALUES (?, ?, ?)", (domain, current_time, status))
                    
                    # Falls die Domain NXDOMAIN oder SERVFAIL ist, füge sie auch zur cache.db hinzu
                    if status in ['NXDOMAIN', 'SERVFAIL']:
                        cursor.execute("INSERT OR REPLACE INTO domains_cache VALUES (?, ?)", (domain, status))

        # Domänen entfernen, die älter als 60 Tage sind
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))

        # Transaktion abschließen
        cursor.execute("COMMIT")

        # Domänen für nxphish.agh abrufen
        cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
        all_domains = cursor.fetchall()
        phishing_domains = [row[0] for row in all_domains if row[1] == 'OK']
        nxdomains = [row[0] for row in all_domains if row[1] == 'NXDOMAIN']
        servfails = [row[0] for row in all_domains if row[1] == 'SERVFAIL']
        removed_by_whitelist = len(whitelist_domains.intersection(domains_to_remove))

        # Sortierte Domänen in Datei schreiben
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

    # CSV-Datei bereinigen
    os.remove(csv_file_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logger.error("Usage: python update.py <workspace_directory>")
        sys.exit(1)
    update_phishfeed(sys.argv[1])
