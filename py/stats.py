import sqlite3
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# Connect to the database
conn = sqlite3.connect('stor/cache.db')  # Adjust the path to the database

# Retrieve all data from the database
query = "SELECT * FROM domains"
df = pd.read_sql_query(query, conn)

# Get the total number of domains
total_domains = len(df)

# Convert 'last_seen' column to datetime
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Filter data for the last 60 days
start_date = datetime.now() - timedelta(days=60)
df = df[df['last_seen'] >= start_date]

# Group by hour and calculate counts for different statuses
hourly_counts_ok = df[df['status'] == 'OK'].groupby(df['last_seen'].dt.floor('H')).size()
hourly_counts_nxdomain = df[df['status'] == 'NXDOMAIN'].groupby(df['last_seen'].dt.floor('H')).size()
hourly_counts_servfail = df[df['status'] == 'SERVFAIL'].groupby(df['last_seen'].dt.floor('H')).size()

# Calculate hourly total domains
hourly_total_domains = df.groupby(df['last_seen'].dt.floor('H')).size()

# Create the figure with subplots
fig = go.Figure()

# Add traces for main graph (OK, NXDOMAIN, SERVFAIL)
fig.add_trace(go.Scatter(x=hourly_counts_ok.index, y=hourly_counts_ok.values, mode='lines+markers', name='OK'))
fig.add_trace(go.Scatter(x=hourly_counts_nxdomain.index, y=hourly_counts_nxdomain.values, mode='lines+markers', name='NXDOMAIN'))
fig.add_trace(go.Scatter(x=hourly_counts_servfail.index, y=hourly_counts_servfail.values, mode='lines+markers', name='SERVFAIL'))

# Add trace for hourly total domains
fig.add_trace(go.Scatter(x=hourly_total_domains.index, y=hourly_total_domains.values, mode='lines+markers', name='Total Domains'))

# Update layout for main graph
fig.update_layout(title='Phishing Domain Counts (Last 60 Days)',
                  xaxis_title='Date',
                  yaxis_title='Count',
                  xaxis=dict(tickangle=-45),
                  template='plotly_white')

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
fig.write_image("stor/stats.png")

# Close the database connection
conn.close()
