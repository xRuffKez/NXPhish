import json
import matplotlib.pyplot as plt

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

def plot_pie_chart(ok_count, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count):
    labels = ['OK', 'NXDOMAIN', 'TIMEOUT', 'NO_ANSWER', 'NO_NAMESERVERS', 'NO_ROOT_SOA', 'NO_ROOT_NS', 'NO_METAQUERIES', 'NO_METAQUERIES_NO_ROOT_NS', 'ERROR']
    sizes = [ok_count, nxdomain_count, timeout_count, no_answer_count, no_nameservers_count, no_root_soa_count, no_root_ns_count, no_metaqueries_count, no_metaqueries_no_root_ns_count, error_count]
    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0', '#ffb3e6', '#ff6666', '#c2f0c2', '#c2d6d6', '#d9b3ff']


    plt.figure(figsize=(10, 8))  # Increase figure size
    _, _, autotexts = plt.pie(sizes, colors=colors, autopct='%1.1f%%', startangle=140, textprops={'fontsize': 12})  # Increase font size
    plt.title('Distribution of Domain Status')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    plt.legend(labels, loc="upper left", bbox_to_anchor=(1, 0, 0.5, 1))  # Use legend instead of labels
    
    # Adjusting autotexts positions to avoid overlapping
    for autotext in autotexts:
        autotext.set_bbox({'edgecolor': 'white', 'alpha': 0.7})
    
    plt.tight_layout()
    plt.savefig('pie_chart.png', bbox_inches='tight')  # Adjusting for legend
    plt.close()

# Main function
def main():
    data = load_data()
    
    # Pie chart
    ok_count_pie, nxdomain_count_pie, timeout_count_pie, no_answer_count_pie, no_nameservers_count_pie, no_root_soa_count_pie, no_root_ns_count_pie, no_metaqueries_count_pie, no_metaqueries_no_root_ns_count_pie, error_count_pie = extract_pie_chart_data(data)
    plot_pie_chart(ok_count_pie, nxdomain_count_pie, timeout_count_pie, no_answer_count_pie, no_nameservers_count_pie, no_root_soa_count_pie, no_root_ns_count_pie, no_metaqueries_count_pie, no_metaqueries_no_root_ns_count_pie, error_count_pie)

if __name__ == "__main__":
    main()
