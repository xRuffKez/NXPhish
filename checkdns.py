import json
import time
import dns.resolver

def check_dns_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        resolver.resolve(domain, 'NS')
        return "OK"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.Timeout:
        return "TIMEOUT"
    except Exception as e:
        return "SERVFAIL"

def update_dns_status():
    current_time = int(time.time())
    with open("warehouse.json", "r+") as file:
        data = json.load(file)
        for entry in data:
            if entry["dns_check_date"] == 0 or current_time - entry["dns_check_date"] >= 24 * 3600:
                dns_status = check_dns_status(entry["domain"])
                entry["dns_status"] = dns_status
                entry["dns_check_date"] = current_time
        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    update_dns_status()
