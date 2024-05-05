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

# Group by date and calculate counts for different statuses
daily_counts_ok = df[df['status'] == 'OK'].groupby(df['last_seen'].dt.date).size()
daily_counts_nxdomain = df[df['status'] == 'NXDOMAIN'].groupby(df['last_seen'].dt.date).size()
daily_counts_servfail = df[df['status'] == 'SERVFAIL'].groupby(df['last_seen'].dt.date).size()

# Create the figure with subplots
fig = go.Figure()

# Add traces for main graph (OK, NXDOMAIN, SERVFAIL)
fig.add_trace(go.Scatter(x=daily_counts_ok.index[::-1], y=daily_counts_ok.values[::-1], mode='lines+markers', name='OK'))
fig.add_trace(go.Scatter(x=daily_counts_nxdomain.index[::-1], y=daily_counts_nxdomain.values[::-1], mode='lines+markers', name='NXDOMAIN'))
fig.add_trace(go.Scatter(x=daily_counts_servfail.index[::-1], y=daily_counts_servfail.values[::-1], mode='lines+markers', name='SERVFAIL'))

# Update layout for main graph
fig.update_layout(title='Daily Phishing Domain Counts (Last 60 Days)',
                  xaxis_title='Date',
                  yaxis_title='Count',
                  xaxis=dict(tickangle=-45),
                  xaxis_range=[start_date, datetime.now()],  # Adjust x-axis range
                  template='plotly_white')

# Add annotation for total number of domains
fig.add_annotation(text=f"Total domains: {total_domains}",
                   xref="paper", yref="paper",
                   x=0.95, y=0.05, showarrow=False)

# Add annotations for daily counts of each status
for idx, counts in enumerate([daily_counts_ok, daily_counts_nxdomain, daily_counts_servfail]):
    status = counts.name
    count = counts.sum()
    fig.add_annotation(text=f"{status}: {count}",
                       x=daily_counts_ok.index[-1], y=counts.values[-1],
                       xshift=-20, yshift=10,
                       xanchor="left", yanchor="bottom",
                       showarrow=False)

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
fig.write_image("stor/stats.png")

# Close the database connection
conn.close()
