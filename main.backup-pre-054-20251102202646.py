import os
import time
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Ensure .env wins over any stale Windows env var
load_dotenv(override=True)

app = FastAPI(title="ExposureShield API", version="0.5.4")

# Strict allowlist + regex to permit any *.vercel.app (preview/prod)
ALLOWED_ORIGINS = [
    "https://www.exposureshield.com",
    "https://exposureshield.com",
    "https://api.exposureshield.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://[a-z0-9\-]+\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HIBP_API = "https://haveibeenpwned.com/api/v3"

def _get_env_key() -> str:
    return (os.getenv("HIBP_API_KEY") or "").strip()

def _get_env_ua() -> str:
    ua = (os.getenv("HIBP_USER_AGENT") or "").strip()
    return ua if ua else "ExposureShield/0.5.4 (contact@exposureshield.com)"

def hibp_headers() -> dict:
    key = _get_env_key()
    if not key:
        raise HTTPException(status_code=500, detail="HIBP API key not configured")
    return {
        "hibp-api-key": key,
        "User-Agent": _get_env_ua(),
        "Accept": "application/json",
    }

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": "sqlite", "version": "v0.5.4"}

@app.get("/debug/env")
def debug_env():
    key = _get_env_key()
    return {"has_key": bool(key), "key_len": len(key), "ua": _get_env_ua()}

@app.get("/debug/hibp")
def debug_hibp(email: str, truncate: bool = False):
    try:
        params = {"truncateResponse": str(truncate).lower()}
        h = hibp_headers()
        r = requests.get(f"{HIBP_API}/breachedaccount/{email}", headers=h, params=params, timeout=20)
        return {
            "used_headers": {"hibp-api-key": h["hibp-api-key"], "User-Agent": h["User-Agent"], "Accept": h["Accept"]},
            "status": r.status_code,
            "retry_after": r.headers.get("Retry-After"),
            "body_preview": r.text[:500],
        }
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"HIBP request failed: {e}")

def _hibp_breachedaccount(email: str, truncate: bool) -> requests.Response:
    params = {"truncateResponse": str(truncate).lower()}
    return requests.get(
        f"{HIBP_API}/breachedaccount/{email}",
        headers=hibp_headers(),
        params=params,
        timeout=20,
    )

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
            if r.status_code == 429:
                wait = r.headers.get("Retry-After")
                try:
                    wait_s = min(int(wait), 10) if wait is not None else 3
                except ValueError:
                    wait_s = 3
                time.sleep(wait_s)
                continue
            break
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
