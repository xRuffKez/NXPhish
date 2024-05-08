import json
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

# Function to load data from JSON file
def load_data():
    with open('warehouse.json', 'r') as file:
        data = json.load(file)
    return data

# Function to extract required data for pie chart
def extract_pie_chart_data(data):
    ok_count = 0
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
            ok_count += 1
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
            
    return ok_count, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count

# Function to plot pie chart
def plot_pie_chart(ok_count, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count):
    labels = ['OK', 'NXDOMAIN', 'TIMEOUT', 'NO_ANSWER', 'NO_NAMESERVERS', 'NO_ROOT_SOA', 'NO_ROOT_NS', 'NO_METAQUERIES', 'NO_METAQUERIES_NO_ROOT_NS', 'ERROR']
    sizes = [ok_count, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count]
    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0', '#ffb3e6', '#ff6666', '#c2f0c2', '#c2d6d6', '#d9b3ff']

    plt.figure(figsize=(10, 8))  # Increase figure size
    patches, _, _ = plt.pie(sizes, labels=labels, colors=colors, startangle=140, textprops={'fontsize': 12})  # Increase font size
    plt.title('Distribution of Domain Status')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    # Create percentage labels for legend
    percentages = ['{0} - {1:1.1f}%'.format(label, size) for label, size in zip(labels, sizes)]
    
    plt.legend(handles=patches, labels=percentages, loc="upper left", bbox_to_anchor=(1, 0, 0.5, 1))  # Use legend instead of labels
    
    plt.tight_layout()
    plt.savefig('pie_chart.png', bbox_inches='tight')  # Adjusting for legend
    plt.close()

# Function to plot line chart
def plot_line_chart(data):
    timestamps = [entry['timestamp'] for entry in data]
    dns_statuses = [entry['dns_status'] for entry in data]

    # Convert timestamps to datetime objects
    timestamps = [datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') for ts in timestamps]

    # Count occurrences of each status for each timestamp
    status_counts = {}
    for ts, status in zip(timestamps, dns_statuses):
        if ts not in status_counts:
            status_counts[ts] = {'OK': 0, 'NXDOMAIN': 0, 'TIMEOUT': 0, 'NO_ANSWER': 0, 'NO_NAMESERVERS': 0, 'NO_ROOT_SOA': 0, 'NO_ROOT_NS': 0, 'NO_METAQUERIES': 0, 'NO_METAQUERIES_NO_ROOT_NS': 0, 'ERROR': 0}
        status_counts[ts][status] += 1

    # Create arrays for each status count
    counts_per_status = {status: np.zeros(len(status_counts), dtype=int) for status in ['OK', 'NXDOMAIN', 'TIMEOUT', 'NO_ANSWER', 'NO_NAMESERVERS', 'NO_ROOT_SOA', 'NO_ROOT_NS', 'NO_METAQUERIES', 'NO_METAQUERIES_NO_ROOT_NS', 'ERROR']}
    timestamps_sorted = sorted(status_counts.keys())
    for i, ts in enumerate(timestamps_sorted):
        for j, status in enumerate(['OK', 'NXDOMAIN', 'TIMEOUT', 'NO_ANSWER', 'NO_NAMESERVERS', 'NO_ROOT_SOA', 'NO_ROOT_NS', 'NO_METAQUERIES', 'NO_METAQUERIES_NO_ROOT_NS', 'ERROR']):
            counts_per_status[status][i] = status_counts[ts][status]

    # Plot line chart
    plt.figure(figsize=(10, 6))
    for status, color in zip(['OK', 'NXDOMAIN', 'TIMEOUT', 'NO_ANSWER', 'NO_NAMESERVERS', 'NO_ROOT_SOA', 'NO_ROOT_NS', 'NO_METAQUERIES', 'NO_METAQUERIES_NO_ROOT_NS', 'ERROR'], ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']):
        plt.plot(timestamps_sorted, counts_per_status[status], label=status, color=color)

    plt.title('DNS Status Over Time')
    plt.xlabel('Timestamp')
    plt.ylabel('Count')
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    
    # Adjust x-axis limits dynamically based on data
    plt.xlim(timestamps_sorted[0], timestamps_sorted[-1])

    plt.tight_layout()
    plt.savefig('line_chart.png', bbox_inches='tight')
    plt.close()

# Main function
def main():
    data = load_data()
    
    # Pie chart
    ok_count_pie, nxdomain_count_pie, timeout_count_pie, no_answer_count_pie, no_nameservers_count_pie, no_root_soa_count_pie, no_root_ns_count_pie, no_metaqueries_count_pie, no_metaqueries_no_root_ns_count_pie, error_count_pie = extract_pie_chart_data(data)
    plot_pie_chart(ok_count_pie, nxdomain_count_pie, timeout_count_pie, no_answer_count_pie, no_nameservers_count_pie, no_root_soa_count_pie, no_root_ns_count_pie, no_metaqueries_count_pie, no_metaqueries_no_root_ns_count_pie, error_count_pie)
    
    # Line chart
    plot_line_chart(data)

if __name__ == "__main__":
    main()
