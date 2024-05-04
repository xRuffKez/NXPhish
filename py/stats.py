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

# Create a subplot for top 10 abused TLDs
fig.add_trace(go.Bar(x=top_tlds.index[::-1], y=top_tlds.values[::-1], name='TLDs', marker_color='lightsalmon'))

# Update layout for subplot
fig.update_layout(yaxis2_title='TLD Count',  # Y-axis title for subplot
                  yaxis2=dict(anchor='x2', overlaying='y', side='right'),  # Position and overlaying of y-axis
                  template='plotly_white',
                  height=800)  # Adjust height of the plot

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
fig.write_image("stor/stats.png")

# Close the database connection
conn.close()
