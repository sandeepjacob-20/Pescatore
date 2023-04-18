import pickle
import feature_extraction as fe
import whois
from urllib.parse import urlparse
import pycountry
import pandas as pd
from google.cloud import storage
import csv


#To check if the domain name already exists in the training dataset
def databaseCheck(domain_name):
    
    urldata = pd.read_csv(r'/tmp/urldata.csv')
    for i in range(1, len(urldata)):
      if domain_name in str(urldata['Domain'][i]):
        return urldata['Label'][i]  #if the domain does exist it returns the label
    
    return 2 #if the domain does not exist it returns 2

def check(url):

    path_to_private_key = './accessor_key.json'
    client = storage.Client.from_service_account_json(json_credentials_path=path_to_private_key)
    bucket = client.bucket('pescatore_d_b')
    blob = bucket.blob('urldata.csv')
    file = open(r"/tmp/urldata.csv","wb")
    blob.download_to_file(file)

    modelblob = bucket.blob('phishing_model.pkl')
    model_file = open(r"/tmp/phishing_model.pkl","wb")
    modelblob.download_to_file(model_file)

    #extracts the details of the url
    site_data = whois.whois(urlparse(url).netloc)

    try:
        domain_name = site_data.domain_name
        if(type(domain_name) is list):
            domain_name = domain_name[1].lower()
        if domain_name.isupper():
            domain_name = domain_name.lower()
        #checks if the domain name already exists in the training dataset.
        doesExist = databaseCheck(domain_name)
    except:
        domain_name = "none"
        doesExist = 2

    registrar = site_data.registrar

    creation_date = site_data.creation_date
    if (type(creation_date) is list):
        creation_date = creation_date[0]

    try:
        country_name = pycountry.countries.get(alpha_2=site_data.country).name
    except:
        country_name = "unavailable"

    if doesExist==2:
        features = [] 

        #extracts the features of the url
        features.append(fe.featureExtraction(url))

        # loading the model to predict
        loaded_model = pickle.load(open(r'/tmp/phishing_model.pkl', 'rb'))

        #prediction result is stored in the 'result' variable. 1 for malicious and 0 for benign
        result = loaded_model.predict(features)

        features[0].insert(0,domain_name)
        features[0].insert(11,result[0])
        # df = pd.DataFrame(features)
        #if domain name not in the dataset, adds it to the dataset
        with open(r'/tmp/urldata.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(features[0])

        blob = bucket.blob("urldata.csv")
        blob.upload_from_filename(r"/tmp/urldata.csv")
    else:
        result = doesExist

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