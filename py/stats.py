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

# Group by date and calculate counts
daily_counts = df.groupby(df['last_seen'].dt.date).size()

# Create and display the line graph
plt.figure(figsize=(12, 6))
plt.plot(daily_counts.index, daily_counts.values, marker='o', linestyle='-', color='#007ACC')  # Adjust line color and style
plt.title('Daily Phishing Domain Counts (Last 60 Days)', fontsize=16)  # Customize title font size
plt.xlabel('Date', fontsize=12)  # Customize x-axis label font size
plt.ylabel('Count', fontsize=12)  # Customize y-axis label font size
plt.xticks(fontsize=10, rotation=45)  # Customize x-axis tick font size and rotation
plt.yticks(fontsize=10)  # Customize y-axis tick font size
plt.grid(True, linestyle='--', alpha=0.5)  # Add grid lines with custom style and transparency
plt.tight_layout()

# Add branding text
plt.text(daily_counts.index[10], daily_counts.values.max() * 0.9, 'NXPhish', fontsize=14, color='#FF5733', fontweight='bold')  # Adjust position and style

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
plt.savefig('stor/stats.png')

# Close the database connection
conn.close()
