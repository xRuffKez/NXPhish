import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

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
    timeout_count = 0
    no_answer_count = 0
    no_nameservers_count = 0
    no_root_soa_count = 0
    no_root_ns_count = 0
    no_metaqueries_count = 0
    no_metaqueries_no_root_ns_count = 0
    error_count = 0
    
    for entry in data:
        if entry['dns_status'] == 'OK':
            phishing_domains += 1
        elif entry['dns_status'] == 'NXDOMAIN':
            nxdomain_count += 1
        elif entry['dns_status'] == 'TIMEOUT':
            timeout_count += 1
        elif entry['dns_status'] == 'NO_ANSWER':
            no_answer_count += 1
        elif entry['dns_status'] == 'NO_NAMESERVERS':
            no_nameservers_count += 1
        elif entry['dns_status'] == 'NO_ROOT_SOA':
            no_root_soa_count += 1
        elif entry['dns_status'] == 'NO_ROOT_NS':
            no_root_ns_count += 1
        elif entry['dns_status'] == 'NO_METAQUERIES':
            no_metaqueries_count += 1
        elif entry['dns_status'] == 'NO_METAQUERIES_NO_ROOT_NS':
            no_metaqueries_no_root_ns_count += 1
        elif entry['dns_status'] == 'ERROR':
            error_count += 1
            
    return phishing_domains, all_domains, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count

# Function to plot line chart
def plot_line_chart(phishing_domains, all_domains, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count):
    now = datetime.now()
    x = [now - timedelta(minutes=i*30) for i in range(25)]
    x_labels = [dt.strftime('%H:%M') for dt in x]
    
    phishing_data = [phishing_domains] * len(x)
    all_data = [all_domains] * len(x)
    nxdomain_data = [nxdomain_count] * len(x)
    timeout_data = [timeout_count] * len(x)
    no_answer_data = [no_answer_count] * len(x)
    no_nameservers_data = [no_nameservers_count] * len(x)
    no_root_soa_data = [no_root_soa_count] * len(x)
    no_root_ns_data = [no_root_ns_count] * len(x)
    no_metaqueries_data = [no_metaqueries_count] * len(x)
    no_metaqueries_no_root_ns_data = [no_metaqueries_no_root_ns_count] * len(x)
    error_data = [error_count] * len(x)
    
    plt.figure(figsize=(12, 6))
    plt.plot(x_labels, phishing_data, label='Phishing Domains (OK DNS)')
    plt.plot(x_labels, all_data, label='All Domains')
    plt.plot(x_labels, nxdomain_data, label='NXDOMAIN')
    plt.plot(x_labels, timeout_data, label='TIMEOUT')
    plt.plot(x_labels, no_answer_data, label='NO_ANSWER')
    plt.plot(x_labels, no_nameservers_data, label='NO_NAMESERVERS')
    plt.plot(x_labels, no_root_soa_data, label='NO_ROOT_SOA')
    plt.plot(x_labels, no_root_ns_data, label='NO_ROOT_NS')
    plt.plot(x_labels, no_metaqueries_data, label='NO_METAQUERIES')
    plt.plot(x_labels, no_metaqueries_no_root_ns_data, label='NO_METAQUERIES_NO_ROOT_NS')
    plt.plot(x_labels, error_data, label='ERROR')
    
    plt.title('Domain Statistics Over Time')
    plt.xlabel('Time')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('line_chart.png')
    plt.close()

# Main function
def main():
    data = load_data()
    
    # Line chart
    phishing_domains_line, all_domains_line, nxdomain_count_line, timeout_count_line, no_answer_count_line, no_nameservers_count_line, no_root_soa_count_line, no_root_ns_count_line, no_metaqueries_count_line, no_metaqueries_no_root_ns_count_line, error_count_line = extract_line_chart_data(data)
    plot_line_chart(phishing_domains_line, all_domains_line, nxdomain_count_line, timeout_count_line, no_answer_count_line, no_nameservers_count_line, no_root_soa_count_line, no_root_ns_count_line, no_metaqueries_count_line, no_metaqueries_no_root_ns_count_line, error_count_line)

if __name__ == "__main__":
    main()
