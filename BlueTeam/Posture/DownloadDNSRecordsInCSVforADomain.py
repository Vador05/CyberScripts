#Script originally created by ChatGPT
import dnslib
import socket

def get_dns_records(domain):
    # Define the DNS server to use
    DNS_SERVER = '8.8.8.8'
    
    # Define the types of DNS records to query
    DNS_RECORD_TYPES = ['A','ALIAS', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
    
    # Create an empty list to store the DNS records
    dns_records = []
    
    # Loop through each record type and query for records
    for record_type in DNS_RECORD_TYPES:
        query = dnslib.DNSRecord.question(domain, record_type)
        response = dnslib.DNSRecord.parse(query.send(DNS_SERVER))
        
        # Add the records to the list
        for rr in response.rr:
            dns_records.append((rr.rname, rr.rtype, rr.rdata))
    
    return dns_records

# Example usage
domain = 'example.com'
records = get_dns_records(domain)

# Print the results
for record in records:
    print(record)
