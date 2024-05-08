import json
import time
import dns.resolver

def bulk_dns_resolution(domains):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    results = {}
    try:
        answers = resolver.resolve(domains, ['A', 'AAAA'], search=True)
        for domain in domains:
            ipv4_addresses = [r.address for r in answers if r.name == domain and r.addresses]
            ipv6_addresses = [r.address for r in answers if r.name == domain and r.addresses and r.address.is_ipv6]
            if ipv4_addresses and ipv6_addresses:
                results[domain] = "OK"
            elif ipv4_addresses:
                results[domain] = "OK"
            elif ipv6_addresses:
                results[domain] = "OK"
            else:
                results[domain] = "NO_ANSWER"
    except Exception as e:
        results = {domain: "ERROR" for domain in domains}
    return results

def update_dns_status():
    current_time = int(time.time())
    with open("warehouse.json", "r+") as file:
        data = json.load(file)
        domains_to_check = [entry["domain"] for entry in data if entry["dns_check_date"] == 0 or current_time - entry["dns_check_date"] >= 2 * 3600]
        if domains_to_check:
            dns_results = bulk_dns_resolution(domains_to_check)
            for entry in data:
                if entry["domain"] in dns_results:
                    entry["dns_status"] = dns_results[entry["domain"]]
                    entry["dns_check_date"] = current_time
        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    update_dns_status()
