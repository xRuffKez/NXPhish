import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os

# Connect to the database
conn = sqlite3.connect('stor/cache.db')  # Adjust the path to the database

# Retrieve all data from the database
query = "SELECT * FROM domains"
df = pd.read_sql_query(query, conn)

# Convert 'last_seen' column to datetime
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Filter data for the last 60 days
start_date = datetime.now() - timedelta(days=60)
df = df[df['last_seen'] >= start_date]

# Group by date and calculate counts for different statuses
daily_counts_ok = df[df['status'] == 'OK'].groupby(df['last_seen'].dt.date).size()
daily_counts_nxdomain = df[df['status'] == 'NXDOMAIN'].groupby(df['last_seen'].dt.date).size()
daily_counts_servfail = df[df['status'] == 'SERVFAIL'].groupby(df['last_seen'].dt.date).size()

# Get top 10 abused TLDs with DNS status OK
top_tlds = df[df['status'] == 'OK']['domain'].apply(lambda x: x.split('.')[-1]).value_counts().head(10)

# Create and display the line graph
plt.figure(figsize=(12, 6))
plt.plot(daily_counts_ok.index, daily_counts_ok.values, marker='o', linestyle='-', color='#007ACC', label='OK')
plt.plot(daily_counts_nxdomain.index, daily_counts_nxdomain.values, marker='o', linestyle='-', color='#FF5733', label='NXDOMAIN')
plt.plot(daily_counts_servfail.index, daily_counts_servfail.values, marker='o', linestyle='-', color='#FFC300', label='SERVFAIL')
for tld in top_tlds.index:
    tld_counts = df[(df['status'] == 'OK') & (df['domain'].str.endswith(tld))].groupby(df['last_seen'].dt.date).size()
    plt.plot(tld_counts.index, tld_counts.values, marker='o', linestyle='-', label=tld)

plt.title('Daily Phishing Domain Counts (Last 60 Days)', fontsize=16)  # Customize title font size
plt.xlabel('Date', fontsize=12)  # Customize x-axis label font size
plt.ylabel('Count', fontsize=12)  # Customize y-axis label font size
plt.xticks(fontsize=10, rotation=45)  # Customize x-axis tick font size and rotation
plt.yticks(fontsize=10)  # Customize y-axis tick font size
plt.grid(True, linestyle='--', alpha=0.5)  # Add grid lines with custom style and transparency
plt.legend()
plt.tight_layout()

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
plt.savefig('stor/stats.png')

# Close the database connection
conn.close()
