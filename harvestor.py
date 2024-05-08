def update_json_with_domains(domains):
    current_time = int(time.time())
    unique_domains = set()  # Use a set to remove duplicates

    with open("warehouse.json", "r+") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            data = []

        for domain in domains:
            # Skip empty domain entries
            if not domain:
                continue
            
            found = False
            domain_without_path = urlparse(domain).netloc.split(':')[0]  # Extract domain from URL
            unique_domains.add(domain_without_path)

            # Check if the domain is already in the JSON
            for item in data:
                if item["domain"] == domain_without_path:
                    item["last_seen"] = current_time
                    found = True
                    break
            if not found:
                data.append({
                    "domain": domain_without_path,
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "dns_status": "OK",
                    "dns_check_date": 0  # Set dns_check_date to 0 for new domains
                })

        # Remove duplicates from the JSON
        data = [entry for entry in data if entry["domain"] in unique_domains]

        file.seek(0)
        file.truncate()  # Clear the file content to rewrite it
        json.dump(data, file, indent=4)
