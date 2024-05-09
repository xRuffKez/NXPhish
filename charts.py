import json
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import os

# Function to load data from JSON file or return an empty list if the file doesn't exist
def load_data():
    try:
        with open('charts/data.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        # Create an empty data list if the file doesn't exist
        with open('charts/data.json', 'w') as file:
            json.dump([], file)
        return []

# Function to save data to JSON file
def save_data(data):
    with open('charts/data.json', 'w') as file:
        json.dump(data, file, indent=4)

# Function to filter phishing domains based on DNS status and whitelisted status
def filter_phishing_domains(data):
    return [entry for entry in domain if entry['dns_status'] == 'OK' and entry['whitelisted'] == '0']

# Function to plot historical trends
def plot_historical_trends(interval, title, data):
    now = datetime.now()
    historical_data = []

    # Collect historical data for the specified time interval
    for i in range(interval):
        start_date = now - timedelta(days=i)
        end_date = now - timedelta(days=i - 1)
        count = sum(1 for entry in data if start_date <= datetime.fromisoformat(entry['date']) < end_date)
        historical_data.append((start_date.strftime('%Y-%m-%d'), count))

    # Plot the historical data
    dates, counts = zip(*historical_data)
    plt.plot(dates, counts, marker='o')
    plt.xlabel('Date')
    plt.ylabel('Number of Phishing Domains')
    plt.title(title)
    plt.xticks(rotation=45)

    # Save the plot as a PNG file
    plt.tight_layout()
    plt.savefig(f'charts/phishing_domains_{title.lower().replace(" ", "_")}.png')
    plt.close()

# Load data
data = load_data()

# Plot historical trends
plot_historical_trends(1, 'Last 24 Hours', data)
plot_historical_trends(7, 'Last 7 Days', data)
plot_historical_trends(30, 'Last Month', data)
plot_historical_trends(365, 'Last Year', data)
