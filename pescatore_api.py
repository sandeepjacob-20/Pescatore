#import required packages and modules
from fastapi import FastAPI
import detection as detect
from urllib.parse import unquote
import training as train

app = FastAPI()

@app.get("/train")
def root(key: str):
    if key == "lospolloshermanos":
        return train.train_model()
    else:
        return {"Error":"Password incorrect"}

@app.get("/verify")
def home(url: str):
    return detect.check(url)
