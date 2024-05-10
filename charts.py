import json
from datetime import datetime, timedelta
import os
import matplotlib.pyplot as plt

def load_data(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as file:
            return json.load(file)
    else:
        return []

def update_chart_data(chart_data, status_counts, time_interval):
    current_time = datetime.now()
    start_time = current_time - time_interval
    end_time = current_time

    chart_data.append({
        "start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "end_time": end_time.strftime('%Y-%m-%d %H:%M:%S'),
        "status_counts": status_counts
    })

def save_chart_data(chart_data, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(os.path.join(output_folder, "data.json"), "w") as file:
        json.dump(chart_data, file, indent=4)

def plot_line_graph(chart_data, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for chart_entry in chart_data:
        start_time = chart_entry["start_time"]
        end_time = chart_entry["end_time"]
        status_counts = chart_entry["status_counts"]

        plt.figure(figsize=(10, 6))
        plt.plot(list(status_counts.keys()), list(status_counts.values()), marker='o')
        plt.xlabel('Time')
        plt.ylabel('Count')
        plt.title(f'Domain counts from {start_time} to {end_time}')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_folder, f'domain_counts_{start_time}_{end_time}.png'))
        plt.close()

def main():
    data = load_data("warehouse.json")
    time_intervals = {"24h": timedelta(hours=24), "1w": timedelta(weeks=1), "1m": timedelta(weeks=4), "1y": timedelta(weeks=52)}
    output_folder = "charts"

    chart_data = load_data(os.path.join(output_folder, "data.json"))

    for interval_name, interval in time_intervals.items():
        start_time = datetime.now() - interval
        end_time = datetime.now()
        filtered_data = [entry for entry in data if entry.get("dns_status") == "OK" and entry.get("whitelisted") == 0 and start_time <= datetime.fromtimestamp(entry["last_seen"]) <= end_time]
        count = len(filtered_data)
        update_chart_data(chart_data, {start_time.strftime('%Y-%m-%d %H:%M:%S'): count}, interval)

    save_chart_data(chart_data, output_folder)
    plot_line_graph(chart_data, output_folder)

if __name__ == "__main__":
    main()
