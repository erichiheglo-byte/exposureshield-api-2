import os, time
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(override=True)

app = FastAPI(title="ExposureShield API", version="0.5.3")

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

HIBP_API = "https://haveibeenpwned.com/api/v3"
# STRIP in case of hidden whitespace/newlines
HIBP_KEY = (os.getenv("HIBP_API_KEY") or "").strip()
HIBP_UA  = (os.getenv("HIBP_USER_AGENT") or "ExposureShield/0.5.3 (contact@exposureshield.com)").strip()

def hibp_headers():
    if not HIBP_KEY:
        raise HTTPException(status_code=500, detail="HIBP API key not configured")
    # Match your working PowerShell headers (case/canonical)
    return {
        "hibp-api-key": HIBP_KEY,
        "User-Agent": HIBP_UA,
        "Accept": "application/json",
    }

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": "sqlite", "version": "v0.5.3"}

@app.get("/debug/env")
def debug_env():
    return {"has_key": bool(HIBP_KEY), "key_len": len(HIBP_KEY), "ua": HIBP_UA}

@app.get("/debug/hibp")
def debug_hibp(email: str, truncate: bool = False):
    """Call HIBP from the server and show status + first 500 chars of body + headers used."""
    try:
        params = {"truncateResponse": str(truncate).lower()}
        h = hibp_headers()
        r = requests.get(f"{HIBP_API}/breachedaccount/{email}", headers=h, params=params, timeout=20)
        return {
            "used_headers": h,
            "status": r.status_code,
            "retry_after": r.headers.get("Retry-After"),
            "body_preview": r.text[:500],
        }
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"HIBP request failed: {e}")

def _hibp_breachedaccount(email: str, truncate: bool) -> requests.Response:
    params = {"truncateResponse": str(truncate).lower()}
    return requests.get(f"{HIBP_API}/breachedaccount/{email}", headers=hibp_headers(), params=params, timeout=20)

@app.get("/verify")
def verify_email(
    email: str = Query(..., min_length=5, max_length=200, description="Email to check in HIBP"),
    truncate: bool = Query(False, description="If true, smaller response"),
):
    attempts = 3
    last = None
    for _ in range(attempts):
        try:
            r = _hibp_breachedaccount(email, truncate)
            last = r
            if r.status_code != 429:
                break
            wait = min(int(r.headers.get("Retry-After", "3")), 10)
            time.sleep(wait)
        except requests.RequestException as e:
            raise HTTPException(status_code=502, detail=f"HIBP request failed: {e}")

    if last is None:
        raise HTTPException(status_code=502, detail="No response from HIBP")

    if last.status_code == 404:
        return {"verified": False, "breaches": []}
    if last.status_code == 401:
        raise HTTPException(status_code=401, detail="HIBP unauthorized (check API key)")
    if last.status_code == 403:
        raise HTTPException(status_code=403, detail="HIBP forbidden (check User-Agent or plan)")
    if last.status_code == 429:
        ra = last.headers.get("Retry-After", "60")
        raise HTTPException(status_code=429, detail=f"HIBP rate limited. Retry after {ra}s")
    if last.status_code != 200:
        raise HTTPException(status_code=last.status_code, detail=f"HIBP error ({last.status_code}): {last.text[:200]}")

    data = last.json()
    mapped = [{
        "name": b.get("Name"),
        "title": b.get("Title"),
        "domain": b.get("Domain"),
        "date": b.get("BreachDate"),
        "verified": bool(b.get("IsVerified", False)),
        "pwn_count": b.get("PwnCount"),
        "data_classes": b.get("DataClasses", []),
        "description": b.get("Description"),
        "logo_path": b.get("LogoPath"),
        "added": b.get("AddedDate"),
        "modified": b.get("ModifiedDate"),
    } for b in data]

    return {"verified": len(mapped) > 0, "breaches": mapped}


