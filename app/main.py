from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

VERSION = os.getenv("APP_VERSION", "v0.4.0")
app = FastAPI(title="exposureshield-api", version=VERSION)

# Allow local dev, your Vercel prod, and your domains
origins = [
    "http://localhost:5173",
    "https://frontend-qhoh2jc3i-erics-projects-c7eb48f7.vercel.app",
    "https://exposureshield.com",
    "https://www.exposureshield.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],    # includes OPTIONS
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"service":"exposureshield-api","version":VERSION}

@app.get("/health")
def health():
    return {"status":"ok","service":"exposureshield-api","store":"sqlite","version":VERSION}

class ScanBody(BaseModel):
    email: str
    password: str

@app.post("/scan")
def scan(body: ScanBody):
    # demo response; replace with real logic later
    return {
        "result": "success",
        "email": body.email,
        "status": "exposure_found",
        "breaches": [{"site":"deezer.com","date":"2019-04-22"}]
    }
