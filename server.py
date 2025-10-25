from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from helpers.pwned import pwned_password_count
from helpers.ihavepwned import load_dataset, lookup_email


VERSION = "0.1.2"

origins = [
    "http://localhost:4173",
    "https://www.exposureshield.com",
    "https://exposureshield.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api"}

class ScanIn(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    result: str
    email: str
    status: str
    advice: list[str] | None = None

@app.post("/scan", response_model=ScanOut)
async def scan(payload: ScanIn):
    email = payload.email.strip()
    password = payload.password

    # 1) Pwned Passwords (k-anonymity)
    try:
        count = await pwned_password_count(password)
    except Exception:
        count = 0

    # 2) Local "ihavepwned" dataset
    matches = lookup_email(email)
    exposed = bool(matches) or count > 0

    advice = []
    if count > 0:
        advice.append(f"Your password appears in {count:,} breaches (Pwned Passwords). Change it everywhere you reused it.")
    if matches:
        advice.append(f"Email found in {len(matches)} local exposure record(s). Review your accounts and enable 2FA.")
    if not advice:
        advice = [
            "Use a password manager and unique passwords.",
            "Keep 2FA enabled on important accounts.",
        ]

    return {
        "result": "success",
        "email": email,
        "status": "exposure_found" if exposed else "no_exposure",
        "advice": advice
    }
@app.get("/version")
def version():\n    return {"service": "exposureshield-api", "version": VERSION}
import logging
logger = logging.getLogger("uvicorn.error")

@app.post("/scan", response_model=ScanOut)
async def scan(payload: ScanIn):
    email = payload.email.strip()
    password = payload.password

    # 1) Pwned Passwords (k-anonymity)
    try:
        count = await pwned_password_count(password)
    except Exception:
        count = 0

    # 2) Local "ihavepwned" dataset
    matches = lookup_email(email)
    exposed = bool(matches) or count > 0

    advice = []
    if count > 0:
        advice.append(f"Your password appears in {count:,} breaches (Pwned Passwords). Change it everywhere you reused it.")
    if matches:
        advice.append(f"Email found in {len(matches)} local exposure record(s). Review your accounts and enable 2FA.")
    if not advice:
        advice = [
            "Use a password manager and unique passwords.",
            "Keep 2FA enabled on important accounts.",
        ]

    return {
        "result": "success",
        "email": email,
        "status": "exposure_found" if exposed else "no_exposure",
        "advice": advice
    }
@app.get("/version")
def version():\n    return {"service": "exposureshield-api", "version": VERSION}
import logging
logger = logging.getLogger("uvicorn.error")






