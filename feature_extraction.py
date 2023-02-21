import pandas as pd

# importing required packages for this section
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import requests
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime

"""1.Presence of Special Symbols"""

def special_symbols(url):
    if '@' in url:
        return 1
    else:
        return 0

"""2.Presence of sub-domains"""

def check_subdomain(url):
    count = 0
    for i in url:
        if i == '.':
            count+=1
    if count<=3:
        return 0
    else:
        return 1

"""3.looking for '-' in domain"""

def prefixSuffix(url):
    domain = urlparse(url).netloc
    if '-' in domain or '_' in domain:
        return 1            # phishing
    else:
        return 0

"""4.Using IP instead of URL"""

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip=0
    return ip

"""5.Depth of URL"""

def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

"""6.Redirections in URL"""

def redirect(url):
    pos = url.rfind("//")
    if pos>7:
        return 1
    else:
        return 0

"""7.URL shortening services"""

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0

"""8. Number of digits in URL"""

def DigitCount(url):
  count=0
  for i in url:
    if i.isdigit():
      count+=1
  return count

"""9.Web Traffic"""

def web_traffic(url_in):
  try:
    if 'http' not in url_in and 'https' not in url_in:
      url_in='http://'+url_in
    domain_name = whois.query(urlparse(url_in).netloc).name
    if(type(domain_name) is list ):
      domain_name=domain_name[1].lower()
    if domain_name.isupper():
      domain_name=domain_name.lower()
    r = requests.get('https://siterankdata.com/'+domain_name)
    soup = BeautifulSoup(r.text,'html.parser')
    res = str(soup.find_all('meta')[3])

    a = res.split()[7].split('.')[0]
    rank=int(a)
  except:
      return 1
  if rank > 1000000:
    return 1
  else:
    return 0


"""10.Domain age"""

def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
    try:
      creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
      expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
    try:
      ageofdomain = abs((expiration_date[0]-creation_date[0]).days)
    except:
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
  if ((ageofdomain/30) < 6):
    age = 1
  else:
    age = 0
  return age

"""Processing the URL's"""

#Function to extract features
def featureExtraction(url):
  if 'http' not in url and 'https' not in url:
    url='http://'+url
  v = web_traffic(url)
  dns = 0
  try:
    domain_name = whois.query(urlparse(url).netloc)
  except:
    dns = 1
  
  features = []
  #Address bar based features (11) 
  features.append(v)
  features.append(special_symbols(url))
  features.append(check_subdomain(url))
  features.append(prefixSuffix(url))
  features.append(havingIP(url))
  features.append(getDepth(url))
  features.append(redirect(url))
  features.append(tinyURL(url))
  features.append(DigitCount(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  
  return features
