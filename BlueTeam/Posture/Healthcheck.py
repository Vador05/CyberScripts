import csv
import requests
import argparse
import os
from urllib.parse import urlparse, urlunparse
from selenium import webdriver
from datetime import datetime

# Input and output file paths
input_file = "urls.txt"
output_file = "results.csv"
screenshot_folder = "Screenshots"  # Folder to store screenshots

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-s", "--screenshot", action="store_true", help="This option takes a screenshot of each of the URLs inspected")

args = parser.parse_args()

# Create the screenshot folder if it doesn't exist
if args.screenshot and not os.path.exists(screenshot_folder):
    os.makedirs(screenshot_folder)

# Initialize the list to store results
results = []

# Function to capture a screenshot
def capture_screenshot(url, filename):
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")  # Run Chrome in headless mode (no GUI)
    driver = webdriver.Chrome(chrome_options=options)
    driver.get(url)
    
    # Save the screenshot with the specified filename
    driver.save_screenshot(filename)
    driver.quit()

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

        # Capture a screenshot of the redirected URL
        if args.screenshot:
            # Generate a filename based on the redirected URL
            redirect_filename = os.path.join(screenshot_folder, f"{redirect_url.replace('/', '_').replace(':', '_')}.png")
            capture_screenshot(redirect_url, redirect_filename)

    # Capture a screenshot if the --screenshot option is provided
    if args.screenshot:
        # Generate a filename based on the original URL
        screenshot_filename = os.path.join(screenshot_folder, f"{url.replace('/', '_').replace(':', '_')}.png")
        capture_screenshot(url, screenshot_filename)

    # Append the result to the list
    results.append([url, response_code, redirect_url])

# Write results to a CSV file
with open(output_file, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["URL", "HTTP Response Code", "Redirect URL"])
    writer.writerows(results)

print(f"Results have been saved to {output_file}")

