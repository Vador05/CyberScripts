import csv
import socket
import argparse
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

def processURL(url):
    ip_address = get_ip_from_url(url)

    if ip_address:
        print(f"Resolved IP: {ip_address}")
        asn, company = get_asn_info(ip_address)
        
        if asn and company:
            print(f"ASN: {asn}")
            print(f"Company: {company}")
            if args.out:
                writeOutput(args.out, ip_address, company)
            return(ip_address, company)
        else: 
            if args.out:
                writeOutput(args.out,ip_address, "ERROR")
def writeOutput(fname, str1, str2):
    with open(fname, "a") as out_file:
        csv_writer = csv.writer(out_file)
        csv_writer.writerow([str1,str2])



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='CheckHostingPlatform',
                    description='This program will find where a URL is hosted by resolving the DNS to an IP and from there finding the company that manages the AS where the IP lays.')
    parser.add_argument('-f', '--file', help = "file that contains a list of URLs to be processed")
    parser.add_argument('-u', '--url', help = "for processing a single URL")
    parser.add_argument('-o', '--out', help = "file to store the results of the information.")       
    parser.add_argument('-v', '--verbose',
		            action='store_true')  # on/off flag

    args = parser.parse_args()
    csv_writer= None
    if args.url:
        if args.verbose: 
            print("Processing {}".format(args.url))
        processURL(args.url)
    elif args.file:
        if args.verbose: 
            print("Loading File {}".format(args.file))
        with open(args.file, 'r') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                try: 
                    if args.verbose: 
                        print("Processing {}".format(row[0]))
                    processURL(row[0])
                except: 
                    print("Encountered issues when processing {}".format(row[0]))            
    else: 
        url = input("Enter a URL (without https:// or www.): ").strip()
        processURL(url)
