import streamlit as st
import requests
import whois
import pickle
from urllib.parse import urlparse, urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import urllib
import urllib.request
from datetime import datetime



# Load the XGBoost model from .pkl file
with open('xgb_model.pkl', 'rb') as f:
    xgb = pickle.load(f)

# ************ Features ***************


def getDomain(url):
    # url components --> scheme , network location , path , query , fragment
    # extract network location part of the URL (domain + port)
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip


def haveAtSign(url):
    if "@" in url:
        at = 1
    else:
        at = 0
    return at


def getLength(url):
    if len(url) < 54:
        length = 0
    else:
        length = 1
    return length


def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0


def httpDomain(url):
    if 'https' in url:
        return 1
    else:
        return 0


shortening_services = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"tr\.im|link\.zip\.net"
)


def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1  # phishing
    else:
        return 0  # legitimate


# def fetch_links_from_url(url):
#     try:
#         response = requests.get(url)
#         if response.status_code == 200:
#             soup = BeautifulSoup(response.text, 'html.parser')
#             anchor_tags = soup.find_all('a')
#             if anchor_tags:
#                 links = [link.get('href') for link in anchor_tags if link.get(
#                     'href') is not None]
#                 # Filter out relative links and keep only absolute links
#                 links = [link if link.startswith(
#                     'http') else urllib.parse.urljoin(url, link) for link in links]
#                 return links
#             else:
#                 # print("No anchor tags found on the webpage.")
#                 return []
#         else:
#             # print("Error fetching links from URL:", response.status_code)
#             return []
#     except Exception as e:
#         # print("Error fetching links:", e)
#         return []


# def calculate_page_rank(url):
#     # Create a directed graph
#     G = nx.DiGraph()

#     # Add the URL as a node in the graph
#     G.add_node(url)

#     # Fetch links from the URL (You would need to implement this part)
#     links = fetch_links_from_url(url)

#     # Returning 0 if no links can be fetched from the url
#     if not links:
#         return 0

#     # Add edges to the graph from the URL to each linked URL
#     for link in links:
#         G.add_edge(url, link)

#     # Calculate PageRank
#     page_rank = nx.pagerank(G)

#     # Return the PageRank of the URL
#     return page_rank[url]

# # Using google index as a feature


def is_indexed_by_google(url):
    # Replace with your Google Cloud Console API key
    api_key = "AIzaSyBrybuNNGHeV7j4fFC0BvzN-waE9wRnCa4"
    cx = "62d262752064f4500"  # Replace with your Custom Search Engine ID
    try:
        custom_search_url = f"https://www.googleapis.com/customsearch/v1?key={api_key}&cx={cx}&q=site:{url}"
        response = requests.get(custom_search_url)
        if response.status_code == 200:
            data = response.json()
            # Check if any search results contain the specified domain
            if 'items' in data:
                return True
            else:
                return False
        else:
            # print("Error fetching Custom Search results:", response.status_code)
            return False
    except Exception as e:
        # print("Error checking Google index:", e)
        return False

# Example usage
# url = "https://twintchcoupons.com/redeem/52874/?83723"  # Replace with the URL you want to check


def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date

    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        except:
            return 1

    if expiration_date is None or creation_date is None:
        return 1
    elif type(expiration_date) is list or type(creation_date) is list:
        return 1
    else:
        age_of_domain = abs((expiration_date - creation_date).days)
        if age_of_domain / 30 < 6:
            age = 1
        else:
            age = 0
        return age


def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1

    if expiration_date is None:
        return 1
    elif type(expiration_date) is list:
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if end / 30 < 6:
            end = 0
        else:
            end = 1
        return end


def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[|]", response.text):
            return 0
        else:
            return 1


def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("", response.text):
            return 1
        else:
            return 0


def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event\.button ?== ?2", response.text):
            return 0
        else:
            return 1


def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


# Function to extract features from URL
def featureExtraction(url):
    features = []

    # Address bar based features (10)
    # features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain based features (5)
    # page_rank = calculate_page_rank(url)
    # features.append(1 if page_rank < 0.2 else 0)
    indexed_by_google = is_indexed_by_google(url)
    if indexed_by_google:
        features.append(1)
    else:
        features.append(0)

    dns = 0
    try:
        domain_name = whois.whois(url, timeout=1)
    except:
        dns = 1
    features.append(dns)
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # HTML & Javascript based features (4)
    try:
        response = requests.get(url, timeout=0.5)
    except:
        response = ""
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    # Special character count features
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('.'))
    features.append(url.count('='))
    features.append(url.count('http'))
    features.append(url.count('https'))
    features.append(url.count('www'))
    features.append(digit_count(url))
    features.append(letter_count(url))

    return features

# Function to predict whether the URL is phishing or not


def predict_phishing(url):
    features = featureExtraction(url)
    # Reshape the features array to match the model input shape
    features_array = [features]
    # Predict using the loaded XGBoost model
    prediction = xgb.predict(features_array)[0]
    return prediction

# Streamlit app


def main():
    st.title("Phishing URL Detector")
    url = st.text_input("Enter the URL:")
    if st.button("Predict"):
        if url:
            prediction = predict_phishing(url)
            if prediction == 1:
                st.error("This URL is likely to be phishing!")
            else:
                st.success("This URL is not likely to be phishing.")


if __name__ == "__main__":
    main()
