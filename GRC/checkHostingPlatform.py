import socket
from ipwhois import IPWhois

def get_ip_from_url(url):
    """Resolve a URL to an IP address."""
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.gaierror:
        print("Error: Unable to resolve the URL.")
        return None

def get_asn_info(ip_address):
    """Retrieve ASN information including the company name that owns the ASN."""
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        asn = results.get("asn", "Unknown ASN")
        asn_description = results.get("asn_description", "Unknown Company")
        return asn, asn_description
    except Exception as e:
        print(f"Error retrieving ASN info: {e}")
        return None, None

if __name__ == "__main__":
    url = input("Enter a URL (without https:// or www.): ").strip()
    ip_address = get_ip_from_url(url)

    if ip_address:
        print(f"Resolved IP: {ip_address}")
        asn, company = get_asn_info(ip_address)
        
        if asn and company:
            print(f"ASN: {asn}")
            print(f"Company: {company}")
