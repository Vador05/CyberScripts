import csv
import requests
from urllib.parse import urlparse, urlunparse

# Input and output file paths
input_file = "urls.txt"
output_file = "results.csv"

# Initialize the list to store results
results = []

# Read URLs from the input file
with open(input_file, "r") as file:
    urls = file.read().splitlines()

# Process each URL
for raw_url in urls:
    # Check if the URL has a scheme (http:// or https://), and if not, add "https://"
    parsed_url = urlparse(raw_url)
    if not parsed_url.scheme:
        url = urlunparse(("https",) + parsed_url[1:])
    else:
        url = raw_url

    response = requests.get(url, allow_redirects=False)
    response_code = response.status_code
    redirect_url = None

    if 300 <= response_code < 310:
        # If it's a redirect (status code 300-309), get the redirection target URL
        redirect_url = response.headers.get("Location")

    # Append the result to the list
    results.append([url, response_code, redirect_url])

# Write results to a CSV file
with open(output_file, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["URL", "HTTP Response Code", "Redirect URL"])
    writer.writerows(results)

print(f"Results have been saved to {output_file}")
