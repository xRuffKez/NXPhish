import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time

# Function to load data from JSON file
def load_data():
    with open('warehouse.json', 'r') as file:
        data = json.load(file)
    return data

# Function to extract required data for line chart
def extract_line_chart_data(data):
    phishing_domains = 0
    all_domains = len(data)
    nxdomain_count = 0
    servfail_count = 0
    
    for entry in data:
        if entry['dns_status'] == 'OK':
            phishing_domains += 1
        if entry['dns_status'] == 'NXDOMAIN':
            nxdomain_count += 1
        elif entry['dns_status'] == 'SERVFAIL':
            servfail_count += 1
            
    return phishing_domains, all_domains, nxdomain_count, servfail_count

# Function to plot line chart
def plot_line_chart(phishing_domains, all_domains, nxdomain_count, servfail_count):
    now = datetime.now()
    x = [now - timedelta(minutes=i*30) for i in range(25)]
    x_labels = [dt.strftime('%H:%M') for dt in x]
    
    phishing_data = [phishing_domains] * len(x)
    all_data = [all_domains] * len(x)
    nxdomain_data = [nxdomain_count] * len(x)
    servfail_data = [servfail_count] * len(x)
    
    plt.figure(figsize=(12, 6))
    plt.plot(x_labels, phishing_data, label='Phishing Domains (OK DNS)')
    plt.plot(x_labels, all_data, label='All Domains')
    plt.plot(x_labels, nxdomain_data, label='NXDOMAIN')
    plt.plot(x_labels, servfail_data, label='SERVFAIL')
    
    plt.title('Domain Statistics Over Time')
    plt.xlabel('Time')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('line_chart.png')
    plt.close()

# Function to extract required data for pie chart
def extract_pie_chart_data(data):
    ok_count = 0
    servfail_count = 0
    nxdomain_count = 0
    
    for entry in data:
        if entry['dns_status'] == 'OK':
            ok_count += 1
        elif entry['dns_status'] == 'SERVFAIL':
            servfail_count += 1
        elif entry['dns_status'] == 'NXDOMAIN':
            nxdomain_count += 1
            
    return ok_count, servfail_count, nxdomain_count

# Function to plot pie chart
def plot_pie_chart(ok_count, servfail_count, nxdomain_count, total_domains):
    labels = ['OK', 'SERVFAIL', 'NXDOMAIN']
    sizes = [ok_count, servfail_count, nxdomain_count]
    colors = ['#ff9999','#66b3ff','#99ff99']
    explode = (0.1, 0, 0)  # explode the 1st slice (OK)

    plt.figure(figsize=(8, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('Distribution of Domain Status')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.tight_layout()
    plt.savefig('pie_chart.png')
    plt.close()

# Main function
def main():
    data = load_data()
    
    # Line chart
    phishing_domains_line, all_domains_line, nxdomain_count_line, servfail_count_line = extract_line_chart_data(data)
    plot_line_chart(phishing_domains_line, all_domains_line, nxdomain_count_line, servfail_count_line)
    
    # Pie chart
    ok_count_pie, servfail_count_pie, nxdomain_count_pie = extract_pie_chart_data(data)
    total_domains = len(data)
    plot_pie_chart(ok_count_pie, servfail_count_pie, nxdomain_count_pie, total_domains)

if __name__ == "__main__":
    main()
