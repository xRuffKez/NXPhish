import json
import time
import dns.resolver

# Function to check DNS status of a given domain
def check_dns_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        ipv4_response = resolver.resolve(domain, 'A')
        ipv4_addresses = [r.address for r in ipv4_response]

        ipv6_response = resolver.resolve(domain, 'AAAA')
        ipv6_addresses = [r.address for r in ipv6_response]

        if ipv4_addresses or ipv6_addresses:
            return "OK"
        else:
            return "NO_ANSWER"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.Timeout:
        return "TIMEOUT"
    except dns.resolver.NoAnswer:
        return "NO_ANSWER"
    except dns.resolver.NoNameservers:
        return "NO_NAMESERVERS"
    except Exception as e:
        return "ERROR"

# Function to update DNS status in warehouse.json
def update_dns_status():
    current_time = int(time.time())
    try:
        with open("warehouse.json", "r+") as file:
            data = json.load(file)

            for entry in data:
                if entry["dns_check_date"] == 0 or current_time - entry["dns_check_date"] >= 48 * 3600:
                    entry["dns_status"] = check_dns_status(entry["domain"])
                    entry["dns_check_date"] = current_time

            file.seek(0)
            file.truncate()
            json.dump(data, file, indent=4)
        print("DNS status updated successfully.")
    except FileNotFoundError:
        print("Error: 'warehouse.json' not found.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from 'warehouse.json'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    update_dns_status()
