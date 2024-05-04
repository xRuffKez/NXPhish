import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os

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

# Convert 'last_seen' column to datetime
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Group by date and calculate counts
daily_counts = df.groupby(df['last_seen'].dt.date).size()

# Create and display the line graph
plt.figure(figsize=(10, 6))
plt.plot(daily_counts.index, daily_counts.values, marker='o', linestyle='-')
plt.title('Daily Domain Counts (Last 60 Days)')
plt.xlabel('Date')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.grid(True)
plt.tight_layout()

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
plt.savefig('stor/stats.png')

# Close the database connection
conn.close()
