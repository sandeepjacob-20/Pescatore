import pickle
import feature_extraction as fe
import whois
from urllib.parse import urlparse
import pycountry

#To check if the domain name already exists in the training dataset

def check(url):

    features = [] 

    #extracts the features of the url
    features.append(fe.featureExtraction(url))

    # loading the model to predict
    loaded_model = pickle.load(open('phishing_model.pkl', 'rb'))

    #prediction result is stored in the 'result' variable. 1 for malicious and 0 for benign
    result = loaded_model.predict(features)

    #extracts the details of the url
    site_data = whois.whois(urlparse(url).netloc)

    try:
        domain_name = site_data.domain_name
        if(type(domain_name) is list ):
            domain_name=domain_name[1].lower()
        if domain_name.isupper():
            domain_name=domain_name.lower()
    except:
        domain_name="none"

    registrar = site_data.registrar

    creation_date = site_data.creation_date
    if (type(creation_date) is list):
        creation_date=creation_date[0]

    try:
        country_name = pycountry.countries.get(alpha_2=site_data.country).name
    except:
        country_name = "unavailable"

    if result==0:
        #returns the result to the api 
        return {"result":"safe",
        "registrar":str(registrar),
        "creation":str(creation_date),
        "country":country_name} 

    elif result==1:
        #returns the result to the api 
        return {"result":"Unsafe",
        "registrar":str(registrar),
        "creation":str(creation_date),
        "country":country_name}