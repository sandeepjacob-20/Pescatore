#import required packages and modules
from fastapi import FastAPI
import detection as detect
import training as train
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return "Welcome to Pescatore API. Pescatore API can be used to detect phishing websites by passing in the URL. Use ../verify?url=[enter your URL here] to check for phishing. For further details please visit ../docs. Follow the project on github : https://github.com/sandeepjacob-20/Pescatore.git . Thank You."

@app.get("/train")
def root(key: str):
    if key == "lospolloshermanos":
        return train.train_model()
    else:
        return {"Error":"Password incorrect"}

@app.get("/verify")
def home(url: str):
    return detect.check(url)
