import argparse
import dns.resolver

def get_domain_records(url, record_types):
    try:
        resolver = dns.resolver.Resolver()
        result = resolver.query(url)

        records = {}
        for rdata in result:
            record_type = dns.rdatatype.to_text(rdata.rdtype)
            if not record_types or record_type in record_types:
                if record_type not in records:
                    records[record_type] = []
                records[record_type].append(str(rdata))
        
        return records
    except dns.exception.DNSException as e:
        print(f"Error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="DNS Inventory Tool")
    parser.add_argument("--url", required=True, help="The domain to query")
    parser.add_argument("--type", nargs="+", help="Filter by record types (e.g., A, CNAME)")

    args = parser.parse_args()
    url = args.url.lower()
    record_types = [rtype.upper() for rtype in args.type] if args.type else []

    records = get_domain_records(url, record_types)

    if records:
        print(f"DNS Records for {url}:")
        for record_type, data in records.items():
            print(f"{record_type}:")
            for item in data:
                print(f"  {item}")

if __name__ == "__main__":
    main()

