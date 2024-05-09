import json
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import os

with open('warehouse.json', 'r') as file:
    data = json.load(file)

phishing_domains = [entry for entry in data if entry['dns_status'] == 'OK' and entry['whitelisted'] == '0']

now = datetime.now()
twenty_four_hours_ago = now - timedelta(hours=24)
seven_days_ago = now - timedelta(days=7)
one_month_ago = now - timedelta(days=30)
one_year_ago = now - timedelta(days=365)

phishing_domains_last_24_hours = [entry for entry in phishing_domains if datetime.fromisoformat(entry['date']) >= twenty_four_hours_ago]
phishing_domains_last_week = [entry for entry in phishing_domains if datetime.fromisoformat(entry['date']) >= seven_days_ago]
phishing_domains_last_month = [entry for entry in phishing_domains if datetime.fromisoformat(entry['date']) >= one_month_ago]
phishing_domains_last_year = [entry for entry in phishing_domains if datetime.fromisoformat(entry['date']) >= one_year_ago]

def plot_chart_last_24_hours(domains_data, title):
    dates = [datetime.fromisoformat(entry['date']) for entry in domains_data]
    counts = [len(domains_data) for _ in domains_data]

    plt.plot(dates, counts)
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Number of Phishing Domains')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('phishing_domains_last_24_hours.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_7_days(domains_data, title):
    dates = [datetime.fromisoformat(entry['date']) for entry in domains_data]
    counts = [len(domains_data) for _ in domains_data]

    plt.plot(dates, counts)
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Number of Phishing Domains')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('phishing_domains_last_7_days.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_1_month(domains_data, title):
    dates = [datetime.fromisoformat(entry['date']) for entry in domains_data]
    counts = [len(domains_data) for _ in domains_data]

    plt.plot(dates, counts)
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Number of Phishing Domains')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('phishing_domains_last_month.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_1_year(domains_data, title):
    dates = [datetime.fromisoformat(entry['date']) for entry in domains_data]
    counts = [len(domains_data) for _ in domains_data]

    plt.plot(dates, counts)
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Number of Phishing Domains')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('phishing_domains_last_year.png')  # Save the plot as a PNG file
    plt.close()

plot_chart_last_24_hours(phishing_domains_last_24_hours, 'Phishing Domains with DNS Status "OK" - Last 24 Hours')
plot_chart_7_days(phishing_domains_last_week, 'Phishing Domains with DNS Status "OK" - Last 7 Days')
plot_chart_1_month(phishing_domains_last_month, 'Phishing Domains with DNS Status "OK" - Last Month')
plot_chart_1_year(phishing_domains_last_year, 'Phishing Domains with DNS Status "OK" - Last Year')

if not os.path.exists('charts'):
    os.makedirs('charts')

for filename in ['phishing_domains_last_24_hours.png', 'phishing_domains_last_7_days.png', 'phishing_domains_last_month.png', 'phishing_domains_last_year.png']:
    if os.path.exists(filename):
        os.rename(filename, os.path.join('charts', filename))
