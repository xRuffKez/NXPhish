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

# Get data for yesterday
yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
daily_counts_ok_yesterday = df[(df['status'] == 'OK') & (df['last_seen'].dt.date == yesterday)].shape[0]
daily_counts_nxdomain_yesterday = df[(df['status'] == 'NXDOMAIN') & (df['last_seen'].dt.date == yesterday)].shape[0]
daily_counts_servfail_yesterday = df[(df['status'] == 'SERVFAIL') & (df['last_seen'].dt.date == yesterday)].shape[0]

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
                  template='plotly_white',
                  legend=dict(font=dict(size=12)))  # Adjust legend font size

# Create a subplot for top 10 abused TLDs
fig.add_trace(go.Bar(x=top_tlds_today.index[::-1], y=top_tlds_today.values[::-1], name='TLDs', marker_color='lightsalmon', yaxis='y2'))

# Update layout for subplot
fig.update_layout(yaxis2=dict(title='TLD Count', anchor='x2', overlaying='y', side='right'),  # Adjust y-axis2 properties
                  template='plotly_white',
                  height=800)  # Adjust height of the plot

# Add annotations for statistics in text format
stats_text = f"""
Statistics:
- Number of OK domains: {daily_counts_ok.sum()} ({daily_counts_ok.sum() - daily_counts_ok_yesterday} from yesterday)
- Number of NXDOMAIN domains: {daily_counts_nxdomain.sum()} ({daily_counts_nxdomain.sum() - daily_counts_nxdomain_yesterday} from yesterday)
- Number of SERVFAIL domains: {daily_counts_servfail.sum()} ({daily_counts_servfail.sum() - daily_counts_servfail_yesterday} from yesterday)

Top 10 Abused TLDs (Today):
{top_tlds_today.to_string()}

Change from Yesterday:
{top_tlds_change.to_string()}
"""
fig.add_annotation(text=stats_text, xref='paper', yref='paper', x=0.5, y=-0.3, showarrow=False)

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
fig.write_image("stor/stats.png")

# Close the database connection
conn.close()
