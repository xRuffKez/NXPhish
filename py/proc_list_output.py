def update_phishfeed(workspace):
    db_path = os.path.join(workspace, 'stor/cache.db')
    feed_path = os.path.join(workspace, 'filtered_feed.txt')
    output_path = os.path.join(workspace, 'nxphish.agh')
    max_age = datetime.now() - timedelta(days=60)

    whitelist_domains = load_whitelist_domains()

    csv_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    if not download_extract_csv(csv_url, workspace):
        return

    csv_file_path = os.path.join(workspace, "top-1m.csv")
    with open(csv_file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        domains_to_remove = {row[1] for row in csv_reader}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, last_seen TEXT, status TEXT)")
        cursor.execute("BEGIN TRANSACTION")
        with open(feed_path, 'r') as feed_file:
            for line in feed_file:
                domain = urlparse(line.strip()).netloc.split(":")[0]
                if domain:
                    if not domain.startswith("http") and "/" in domain:
                        domain = domain.split("/")[0]
                    if domain not in whitelist_domains and domain not in domains_to_remove:
                        cursor.execute("SELECT domain FROM domains WHERE domain=?", (domain,))
                        existing_domain = cursor.fetchone()
                        if existing_domain is None:
                            try:
                                response = resolver.resolve(domain)
                                status = "OK"
                            except dns.resolver.NXDOMAIN:
                                status = "NXDOMAIN"
                            except (dns.resolver.NoAnswer, dns.resolver.Timeout):
                                try:
                                    # If resolver timed out, try resolving with Google's DNS servers
                                    resolver_google = dns.resolver.Resolver()
                                    resolver_google.nameservers = ['8.8.8.8', '8.8.4.4']  # Google's DNS servers
                                    resolver_google.timeout = 10  # Set timeout to 10 seconds for Google DNS
                                    response_google = resolver_google.resolve(domain)
                                    status = "OK"
                                except (dns.resolver.Timeout, dns.resolver.NoAnswer):
                                    status = "SERVFAIL"
                                except dns.resolver.NXDOMAIN:
                                    status = "NXDOMAIN"
                                except Exception as e:
                                    logger.error("Error resolving domain %s: %s", domain, e)
                                    status = "ERROR"
                            current_time = datetime.now().isoformat()
                            cursor.execute("INSERT INTO domains VALUES (?, ?, ?)", (domain, current_time, status))
        cursor.execute("DELETE FROM domains WHERE last_seen < ?", (max_age.isoformat(),))
        cursor.execute("COMMIT")
        conn.commit()

        cursor.execute("SELECT domain, status FROM domains ORDER BY domain")
        all_domains = cursor.fetchall()
        phishing_domains = [row[0] for row in all_domains if row[1] != 'NXDOMAIN' and row[1] != 'SERVFAIL']
        tld_counts = {}
        for domain in phishing_domains:
            tld = domain.split('.')[-1]
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
        sorted_tlds = sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        total_domains = sum(count for _, count in sorted_tlds)

        with open(output_path, 'w') as output_file:
            output_file.write("! Title: NXPhish - Active Phishing Domains\n")
            output_file.write("! Description: This file contains a list of known phishing domains from various feeds.\n")
            output_file.write("! URL shorteners have been removed to reduce false positives.\n")
            output_file.write("! Phishing domains have been checked against the top 1 million domains list provided by Umbrella.\n")
            output_file.write("! Author: xRuffKez\n")
            output_file.write("! Repository: github.com/xRuffKez/NXPhish\n")
            output_file.write("! Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_file.write("! Here are some stats (NXDOMAIN and SERVFAIL Domains are not listed in this File):\n")
            output_file.write("! Number of phishing domains: {}\n".format(len(phishing_domains)))
            output_file.write("! Number of NXDOMAIN domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'NXDOMAIN'])))
            output_file.write("! Number of SERVFAIL domains: {}\n".format(len([row[0] for row in all_domains if row[1] == 'SERVFAIL'])))
            output_file.write("! Number of domains removed by whitelist: {}\n".format(len(whitelist_domains.intersection(domains_to_remove))))
            output_file.write("! Top 10 abused TLDs:\n")
            for tld, count in sorted_tlds:
                percentage_tld_domains = (count / total_domains) * 100
                output_file.write("! - {}: {} ({}%)\n".format(tld, count, round(percentage_tld_domains, 2)))
            output_file.write("! Domains removed after 60 days if not re-added through feed.\n")
            output_file.write("\n")
            for domain in phishing_domains:
                output_file.write("||{}^\n".format(domain))
    os.remove(csv_file_path)
