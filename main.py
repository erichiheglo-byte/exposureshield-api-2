from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os, time
import httpx
from cachetools import TTLCache

app = FastAPI()
APP_VERSION = "v0.5.4"
START_TS = time.time()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://www.exposureshield.com","https://exposureshield.com","http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["*"],
)

# Small cache: email -> breaches (TTL 300s, 100 items)
verify_cache = TTLCache(maxsize=100, ttl=300)

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
USER_AGENT = "ExposureShield/0.5.4 (contact@exposureshield.com)"

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "exposureshield-api",
        "store": "sqlite",
        "version": APP_VERSION,
        "uptime_sec": round(time.time() - START_TS, 1),
    }

@app.get("/verify")
def verify(email: str = Query(..., min_length=3, max_length=254)):
    # Return cached if present
    if email in verify_cache:
        return {"verified": True if verify_cache[email] else False, "breaches": verify_cache[email]}

    if not HIBP_API_KEY:
        # Fail clearly if missing key in prod
        raise HTTPException(status_code=500, detail="HIBP key not configured")

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": USER_AGENT,
    }
    params = {"truncateResponse": "false"}

    try:
        with httpx.Client(timeout=httpx.Timeout(8.0)) as client:
            r = client.get(url, headers=headers, params=params)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    # HIBP semantics:
    # 200 = found (JSON list)
    # 404 = not found (no breaches)
    # 429 = too many requests
    # 401/403 = auth issues
    # 5xx = upstream errors
    if r.status_code == 200:
        data = r.json()
        breaches = [{"name": b.get("Name") or b.get("name"), "domain": b.get("Domain") or b.get("domain")} for b in data]
        verify_cache[email] = breaches
        return {"verified": True, "breaches": breaches}
    elif r.status_code == 404:
        verify_cache[email] = []
        return {"verified": False, "breaches": []}
    elif r.status_code == 429:
        raise HTTPException(status_code=429, detail="Rate limited by HIBP. Please retry shortly.")
    elif r.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="HIBP authentication failed (check API key).")
    else:
        raise HTTPException(status_code=502, detail=f"HIBP error {r.status_code}")
