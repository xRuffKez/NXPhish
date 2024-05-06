import sys

def process_feed(file_path):
    domains = set()
    with open(file_path, 'r') as file:
        for line in file:
            if not line.startswith("#") and line.strip():  # Skip comments and empty lines
                parts = line.split()  # Split line by whitespace
                domain = parts[1] if len(parts) > 1 else parts[0]  # Use the second part if available
                domains.add(domain)

    return domains

def main():
    combined_domains = set()

    for file_path in sys.argv[1:]:
        combined_domains.update(process_feed(file_path))

    with open("filtered_feed.txt", "w") as output_file:
        for domain in sorted(combined_domains):
            output_file.write(domain + "\n")

if __name__ == "__main__":
    main()
