import json
import matplotlib.pyplot as plt
import os

with open('warehouse.json', 'r') as file:
    data = json.load(file)

phishing_domains = [entry for entry in data if entry['dns_status'] == 'OK' and entry['whitelisted'] == '0']

phishing_domains_last_24_hours = len(phishing_domains)
phishing_domains_last_week = len(phishing_domains)
phishing_domains_last_month = len(phishing_domains)
phishing_domains_last_year = len(phishing_domains)

def plot_chart_last_24_hours(count, title):
    plt.bar(['Last 24 Hours'], [count])
    plt.title(title)
    plt.ylabel('Number of Phishing Domains')
    plt.tight_layout()
    plt.savefig('charts/phishing_domains_last_24_hours.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_7_days(count, title):
    plt.bar(['Last 7 Days'], [count])
    plt.title(title)
    plt.ylabel('Number of Phishing Domains')
    plt.tight_layout()
    plt.savefig('charts/phishing_domains_last_7_days.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_1_month(count, title):
    plt.bar(['Last Month'], [count])
    plt.title(title)
    plt.ylabel('Number of Phishing Domains')
    plt.tight_layout()
    plt.savefig('charts/phishing_domains_last_month.png')  # Save the plot as a PNG file
    plt.close()

def plot_chart_1_year(count, title):
    plt.bar(['Last Year'], [count])
    plt.title(title)
    plt.ylabel('Number of Phishing Domains')
    plt.tight_layout()
    plt.savefig('charts/phishing_domains_last_year.png')  # Save the plot as a PNG file
    plt.close()

plot_chart_last_24_hours(phishing_domains_last_24_hours, 'Phishing Domains with DNS Status "OK" - Last 24 Hours')
plot_chart_7_days(phishing_domains_last_week, 'Phishing Domains with DNS Status "OK" - Last 7 Days')
plot_chart_1_month(phishing_domains_last_month, 'Phishing Domains with DNS Status "OK" - Last Month')
plot_chart_1_year(phishing_domains_last_year, 'Phishing Domains with DNS Status "OK" - Last Year')
