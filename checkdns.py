import json
import time
import dns.resolver

def check_dns_status(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['76.76.2.0', '76.76.10.0']
    try:
        ipv4_response = resolver.resolve(domain, 'A')
        ipv4_addresses = [r.address for r in ipv4_response]

        ipv6_response = resolver.resolve(domain, 'AAAA')
        ipv6_addresses = [r.address for r in ipv6_response]

        if ipv4_addresses and ipv6_addresses:
            return "OK"
        elif ipv4_addresses:
            return "OK"
        elif ipv6_addresses:
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
    except dns.resolver.NoRootSOA:
        return "NO_ROOT_SOA"
    except dns.resolver.NoRootNS:
        return "NO_ROOT_NS"
    except dns.resolver.NoMetaqueries:
        return "NO_METAQUERIES"
    except dns.resolver.NoMetaqueriesNoRootNS:
        return "NO_METAQUERIES_NO_ROOT_NS"
    except Exception as e:
        return "ERROR"

def update_dns_status():
    current_time = int(time.time())
    with open("warehouse.json", "r+") as file:
        data = json.load(file)
        for entry in data:
            if entry["dns_check_date"] == 0 or current_time - entry["dns_check_date"] >= 48 * 3600:
                dns_status = check_dns_status(entry["domain"])
                entry["dns_status"] = dns_status
                entry["dns_check_date"] = current_time
        file.seek(0)
        file.truncate()
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    update_dns_status()
