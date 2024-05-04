import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Connect to the database
conn = sqlite3.connect('stor/cache.db')  # Adjust the path to the database

# Define date range for the last 60 days
start_date = datetime.now() - timedelta(days=60)
end_date = datetime.now()

# Retrieve data from the database within the date range
query = f"SELECT * FROM domains WHERE datetime(last_seen) BETWEEN '{start_date}' AND '{end_date}'"
df_current = pd.read_sql_query(query, conn)

# Retrieve historical data from the database before the last 60 days
query_hist = f"SELECT * FROM domains WHERE datetime(last_seen) < '{start_date}'"
df_hist = pd.read_sql_query(query_hist, conn)

# Concatenate current and historical data
df = pd.concat([df_current, df_hist])

# Calculate statistics
status_counts = df['status'].value_counts()
tld_counts = df['domain'].apply(lambda x: x.split('.')[-1]).value_counts().head(10)

# Create and display the graphs
fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(12, 6))

status_counts.plot(kind='bar', ax=axes[0], color='skyblue')
axes[0].set_title('Domain Status (Last 60 Days)')
axes[0].set_xlabel('Status')
axes[0].set_ylabel('Count')

tld_counts.plot(kind='bar', ax=axes[1], color='lightgreen')
axes[1].set_title('Top 10 TLDs (Last 60 Days)')
axes[1].set_xlabel('TLD')
axes[1].set_ylabel('Count')

plt.tight_layout()

# Save the graph as an image
plt.savefig('stor/stats.png')

# Close the database connection
conn.close()
