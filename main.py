from fastapi import FastAPI, Query
import requests

app = FastAPI()
APP_VERSION = "v0.5.4"

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": "sqlite", "version": APP_VERSION}

@app.get("/verify")
def verify(email: str = Query(...)):
    # Example stub: simulate verification
    return {"verified": True, "breaches": [{"name": "Deezer", "domain": "deezer.com"}]}
