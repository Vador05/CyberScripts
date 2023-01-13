#Created by ChatGPT

# Another version of the code that can use your TOR connection. Tor uses 9050 port.
import requests

from bs4 import BeautifulSoup

session = requests.session()
session.proxies["http"] = "XXX://localhost:9050"
session.proxies["https"] = "XXX://localhost:9050"

url = "http://<SOME ONION WEBSITE>.onion/"
response = session.get(url)

soup = BeautifulSoup(response.content, "html.parser")

# title of the webpage
print("Page title: ", soup.title.string)

# get all the links on tha webpage
print("Links on the page: ")
for link in soup.find_all("a"):
    if link.get("href").startswith("/"):
        print(url + link.get("href"))
    else:
        print(link.get("href"))


# extract text from the webpage
print(soup.get_text())

# We can compile a list of a few popular onion websites to our script and 
# extract the links out of it and add those links to our list.
# Use existing search engines as seed lists and pass keywords in their search. 
# For example:
# - https://ahmia.fi/search/?q=a
# - https://ahmia.fi/search/?q=Google
# - https://ahmia.fi/search/?q=<Your company>
# Get the URLs from the above search to grow the seed list of URLs. 