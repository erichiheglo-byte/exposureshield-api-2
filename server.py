import os, sys
sys.path.append(os.path.dirname(__file__))

from typing import List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- Helpers (each has safe fallback so app always starts) ---
try:
    from helpers.pwned import pwned_password_count
except Exception:
    async def pwned_password_count(password: str) -> int:
        return 0

try:
    from helpers.ihavepwned import load_dataset, lookup_email
except Exception:
    def load_dataset() -> None:  # type: ignore
        pass
    def lookup_email(email: str):  # type: ignore
        return []

try:
    from helpers.hibp import hibp_breaches
except Exception:
    async def hibp_breaches(email: str):
        return []

VERSION = "0.1.3"

app = FastAPI(title="ExposureShield API", version=VERSION)

origins = [
    "http://localhost:4173",
    "http://localhost:5173",
    "https://exposureshield.com",
    "https://www.exposureshield.com",
    "https://exposureshield-demo.vercel.app"
]
origins = [
    "http://localhost:4173",
    "http://localhost:5173",
    "https://exposureshield.vercel.app",
    "https://www.exposureshield.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://.*\.vercel\.app$",
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
) or []
    except Exception:
        matches = []

    # 3) HIBP breaches for the email (optional; requires HIBP_API_KEY)
    try:
        hb = await hibp_breaches(email)
    except Exception:
        hb = []

    exposed = bool(matches) or (count and count > 0) or bool(hb)

    advice: List[str] = []
    if count and count > 0:
        advice.append(f"Your password appears in {count:,} breaches (Pwned Passwords). Change it everywhere you reused it.")
    if matches:
        advice.append(f"Email found in {len(matches)} local exposure record(s). Review your accounts and enable 2FA.")
    if hb:
        names = ", ".join([str(b.get("Name")) for b in hb[:5]])
        advice.append(f"Email found in {len(hb)} public breach(es) via HIBP: {names}. Change passwords and enable 2FA.")
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
        "dataset_matches": len(matches),
        "hibp_breaches_count": (len(hb) if hb else 0),
        "hibp_breaches": ([b.get("Name") for b in hb][:5] if hb else None),
    }
@app.get("/feedback/captcha")
def fake_captcha(easy: int | None = None):
    return {"ok": True, "easy": bool(easy)}

