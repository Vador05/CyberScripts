import csv
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm  # Progress bar

from bs4 import XMLParsedAsHTMLWarning
import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def extract_domain(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except:
        return None

def detect_sso_login_url(base_url):
    base_url = normalize_url(base_url)
    try:
        response = requests.get(base_url, allow_redirects=True, timeout=10)
        final_url = response.url

        sso_keywords = ['sso', 'login', 'auth', 'oauth', 'openid']
        if any(keyword in final_url.lower() for keyword in sso_keywords):
            return final_url

        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if any(keyword in href.lower() for keyword in sso_keywords):
                return full_url

        return None
    except:
        return None

def process_csv(input_file, output_file):
    results = []
    with open(input_file, newline='') as csvfile:
        reader = list(csv.reader(csvfile))
        for row in tqdm(reader, desc="Processing domains", unit="domain"):
            if row:
                domain = row[0].strip()
                login_url = detect_sso_login_url(domain)
                login_domain = extract_domain(login_url) if login_url else None
                results.append([domain, login_domain])

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Original Domain', 'Login Domain'])
        writer.writerows(results)

# Example usage
process_csv('domains.csv', 'sso_login_domains.csv')
