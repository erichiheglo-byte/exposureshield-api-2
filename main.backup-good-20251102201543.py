import os, time
import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# ensure .env overrides any existing env var
load_dotenv(override=True)

app = FastAPI(title="ExposureShield API", version="0.5.4")

# Strict allowlist + regex to permit any *.vercel.app (preview/prod)
ALLOWED_ORIGINS = [
    "https://www.exposureshield.com",
    "https://exposureshield.com",
    "https://api.exposureshield.com",
]

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://[a-z0-9\-]+\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
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

