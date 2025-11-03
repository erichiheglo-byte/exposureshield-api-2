import os
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load .env for local dev
load_dotenv()

app = FastAPI(title="ExposureShield API", version="0.5.0")

# CORS
ALLOWED_ORIGINS = [
    "https://www.exposureshield.com",
    "https://exposureshield.com",
    "https://api.exposureshield.com",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HIBP
HIBP_API = "https://haveibeenpwned.com/api/v3"
HIBP_KEY = os.getenv("HIBP_API_KEY")
HIBP_UA  = os.getenv("HIBP_USER_AGENT", "ExposureShield/0.2.0 (contact@exposureshield.com)")

def hibp_headers():
    if not HIBP_KEY:
        raise HTTPException(status_code=500, detail="HIBP API key not configured")
    return {"hibp-api-key": HIBP_KEY, "User-Agent": HIBP_UA, "Accept": "application/json"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": "sqlite", "version": "v0.5.0"}

@app.get("/verify")
def verify_email(
    email: str = Query(..., min_length=5, max_length=200, description="Email to check in HIBP"),
    truncate: bool = Query(False, description="If true, smaller response"),
):
    params = {"truncateResponse": str(truncate).lower()}
    try:
        r = requests.get(f"{HIBP_API}/breachedaccount/{email}", headers=hibp_headers(), params=params, timeout=15)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"HIBP request failed: {e}")
    if r.status_code == 404:
        return {"verified": False, "breaches": []}
    if r.status_code == 429:
        retry_after = r.headers.get("Retry-After", "60")
        raise HTTPException(status_code=429, detail=f"HIBP rate limit. Retry after {retry_after}s")
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail="HIBP error")
    data = r.json()
    mapped = [{
        "name": b.get("Name"),
        "domain": b.get("Domain"),
        "date": b.get("BreachDate"),
        "verified": bool(b.get("IsVerified", False)),
        "pwn_count": b.get("PwnCount"),
        "data_classes": b.get("DataClasses", []),
        "description": b.get("Description"),
        "logo_path": b.get("LogoPath"),
    } for b in data]
    return {"verified": len(mapped) > 0, "breaches": mapped}
