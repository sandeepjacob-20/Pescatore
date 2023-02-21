#import required packages and modules
from fastapi import FastAPI
import detection as detect
from urllib.parse import unquote

app = FastAPI()

@app.get("/")
def home():
    return "Welcome to Pescatore API. Pescatore API can be used to detect phishing websites by passing in the URL. Use ../verify?url=[enter your URL here] to check for phishing. For further details please visit ../docs. Follow the project on github : https://github.com/sandeepjacob-20/Pescatore.git . Thank You."

@app.get("/verify")
def home(url: str):
    return detect.check(url)
