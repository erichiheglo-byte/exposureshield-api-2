import os, sys
sys.path.append(os.path.dirname(__file__))

from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Optional helpers
try:
    from helpers.pwned import pwned_password_count
    from helpers.ihavepwned import load_dataset, lookup_email
except Exception:
    # Fallback no-op implementations so app still starts
    async def pwned_password_count(password: str) -> int:
        return 0
    def load_dataset() -> None:
        pass
    def lookup_email(email: str):
        return []

VERSION = "0.1.2"

app = FastAPI(title="ExposureShield API", version=VERSION)

origins = [
    "http://localhost:4173",
    "http://localhost:5173",
    "https://exposureshield.vercel.app",
    "https://www.exposureshield.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

# Load local dataset (safe even if file missing)
try:
    load_dataset()
except Exception:
    pass

class ScanIn(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    result: str
    email: str
    status: str
    advice: Optional[List[str]] = None
    pwned_count: Optional[int] = None
    dataset_matches: Optional[int] = None
    hibp_breaches_count: Optional[int] = None
    hibp_breaches: Optional[List[str]] = None
@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api"}

@app.get("/version")
def version():
    return {"service": "exposureshield-api", "version": VERSION}

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
    try:
        matches = list(lookup_email(email)) or []
    except Exception:
        matches = []

    exposed = bool(matches) or (count and count > 0)

    advice: List[str] = []
    if count and count > 0:
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
        "advice": advice,
        "pwned_count": int(count or 0),
        "dataset_matches": len(matches), "hibp_breaches_count": (len(hb) if hb else 0), "hibp_breaches": ([b.get("Name") for b in hb][:5] if hb else None),
    }

# Keep /admin/* if you have it; ignore if not present
try:
    from admin import router as admin_router
    app.include_router(admin_router, prefix="/admin")
except Exception:
    try:
        from app.admin import router as admin_router  # alt layout
        app.include_router(admin_router, prefix="/admin")
    except Exception:
        pass

