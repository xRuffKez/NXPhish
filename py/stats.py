import sqlite3
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# Connect to the database
conn = sqlite3.connect('stor/cache.db')  # Adjust the path to the database

# Define query to retrieve data for the last 60 days
query = """
    SELECT domain, last_seen, status
    FROM domains
    WHERE last_seen >= date('now', '-60 days')
"""
df = pd.read_sql_query(query, conn)

# Close the database connection
conn.close()

# Convert 'last_seen' column to datetime
df['last_seen'] = pd.to_datetime(df['last_seen'])

# Group by date and calculate counts for different statuses
daily_counts = df.groupby([df['last_seen'].dt.date, 'status']).size().unstack(fill_value=0)

# Get data for yesterday
yesterday = datetime.now() - timedelta(days=1)
daily_counts_yesterday = df[df['last_seen'].dt.date == yesterday.date()].groupby('status').size()

# Fill missing values with zeros
daily_counts_yesterday = daily_counts_yesterday.reindex(daily_counts.columns, fill_value=0)

# Calculate changes in counts compared to yesterday
changes_from_yesterday = daily_counts.subtract(daily_counts_yesterday)

# Get top 10 abused TLDs for today and yesterday
top_tlds_today = df[(df['status'] == 'OK') & (df['last_seen'].dt.date == datetime.now().date())]['domain'].apply(lambda x: x.split('.')[-1]).value_counts().head(10)
top_tlds_yesterday = df[(df['status'] == 'OK') & (df['last_seen'].dt.date == yesterday.date())]['domain'].apply(lambda x: x.split('.')[-1]).value_counts().head(10)

# Calculate changes in top TLDs compared to yesterday
top_tlds_change = top_tlds_today.sub(top_tlds_yesterday, fill_value=0)

# Create the figure with subplots
fig = go.Figure()

# Add traces for main graph (OK, NXDOMAIN, SERVFAIL)
for status in daily_counts.columns:
    fig.add_trace(go.Scatter(x=daily_counts.index, y=daily_counts[status], mode='lines+markers', name=status))

# Update layout for main graph
fig.update_layout(title='Daily Phishing Domain Counts (Last 60 Days)',
                  xaxis_title='Date',
                  yaxis_title='Count',
                  template='plotly_white',
                  legend=dict(font=dict(size=12)))  # Adjust legend font size

# Create a subplot for top 10 abused TLDs
fig.add_trace(go.Bar(x=top_tlds_today.index, y=top_tlds_today, name='TLDs', marker_color='lightsalmon', yaxis='y2'))

# Update layout for subplot
fig.update_layout(yaxis2=dict(title='TLD Count', anchor='x2', overlaying='y', side='right'),  # Adjust y-axis2 properties
                  template='plotly_white',
                  height=800,  # Adjust height of the plot
                  barmode='overlay',  # Overlay bars in the subplot
                  margin=dict(b=50, t=50))  # Adjust margin to make room for text annotation

# Add annotations for statistics in text format
stats_text = f"""
Statistics:
- Number of OK domains: {daily_counts['OK'].sum()} ({changes_from_yesterday['OK']} from yesterday)
- Number of NXDOMAIN domains: {daily_counts['NXDOMAIN'].sum()} ({changes_from_yesterday['NXDOMAIN']} from yesterday)
- Number of SERVFAIL domains: {daily_counts['SERVFAIL'].sum()} ({changes_from_yesterday['SERVFAIL']} from yesterday)

Top 10 Abused TLDs (Today):
{top_tlds_today.to_string()}

Change from Yesterday:
{top_tlds_change.to_string()}
"""
fig.add_annotation(text=stats_text, xref='paper', yref='paper', x=0.5, y=-0.3, showarrow=False)

# Save the graph as an image
os.makedirs('stor', exist_ok=True)
fig.write_image("stor/stats.png")
