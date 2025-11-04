from __future__ import annotations

from typing import Optional, Dict, Deque, List
from collections import deque
from datetime import datetime, timedelta
import hmac, hashlib, os

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from starlette.responses import JSONResponse, Response

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://www.exposureshield.com",
    "https://exposureshield.com",
]

app = FastAPI(title="ExposureShield API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    email: EmailStr
    password: str

class ScanResponse(BaseModel):
    result: str
    email: EmailStr
    status: str
    advice: Optional[List[str]] = None
    has_exposure: Optional[bool] = None
    breaches: Optional[List[dict]] = None

class VerifyResponse(BaseModel):
    verified: bool
    breaches: List[dict]

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "version": app.version}

# OPTIONS handlers (some proxies are picky; this makes preflight always return 204)
@app.options("/scan")
def scan_preflight():
    return Response(status_code=204)

@app.options("/verify")
def verify_preflight():
    return Response(status_code=204)

# Accept BOTH JSON and form-encoded bodies for /scan
@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
        sr = ScanRequest(**data)
    else:
        form = await request.form()
        sr = ScanRequest(email=form.get("email", ""), password=form.get("password", ""))

    advice = [
        "Turn on 2FA for your email.",
        "Update weak/reused passwords.",
        "Use a password manager.",
    ]

    demo_exposure = any(s in sr.email.lower() for s in ["eric", "test", "demo"])

    return {
        "result": "success",
        "email": sr.email,
        "status": "demo",
        "advice": advice,
        "has_exposure": demo_exposure,
        "breaches": [{"title": "Deezer", "domain": "deezer.com", "date": "2019-04-22", "data_classes": ["Email addresses", "Passwords"]}] if demo_exposure else [],
    }

@app.get("/verify", response_model=VerifyResponse)
async def verify(email: EmailStr):
    has_exposure = "eric" in email.lower()
    if has_exposure:
        breaches = [
            {
                "name": "Deezer",
                "title": "Deezer",
                "domain": "deezer.com",
                "date": "2019-04-22",
                "verified": True,
                "pwn_count": 229_037_936,
                "data_classes": ["Email addresses", "Passwords"],
            },
            {
                "name": "Canva",
                "title": "Canva",
                "domain": "canva.com",
                "date": "2019-05-24",
                "verified": True,
                "pwn_count": 139_000_000,
                "data_classes": ["Email addresses", "Names", "Passwords"],
            },
        ]
    else:
        breaches = []
    return {"verified": True, "breaches": breaches}

# ---------- Feedback (captcha + rate-limit) ----------
SECRET = os.getenv("FEEDBACK_SECRET", "dev-secret-change-me")
CAPTCHA_TTL_SEC = 180
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX = 3

recent: Dict[str, Deque[datetime]] = {}

def sign_token(a: int, b: int, ts: int) -> str:
    msg = f"{a}:{b}:{ts}".encode()
    return hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()

def verify_token(a: int, b: int, ts: int, tok: str) -> bool:
    if abs(int(datetime.utcnow().timestamp()) - ts) > CAPTCHA_TTL_SEC:
        return False
    return hmac.compare_digest(sign_token(a, b, ts), tok)

@app.get("/feedback/captcha")
def feedback_captcha():
    from random import randint
    a, b = randint(2, 9), randint(2, 9)
    ts = int(datetime.utcnow().timestamp())
    token = sign_token(a, b, ts)
    return {"a": a, "b": b, "ts": ts, "token": token}

class FeedbackIn(BaseModel):
    email: EmailStr
    message: str
    a: int
    b: int
    ts: int
    token: str
    answer: int

@app.post("/feedback")
async def feedback(req: Request, payload: FeedbackIn):
    ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "unknown")
    now = datetime.utcnow()
    dq = recent.setdefault(ip, deque())
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SEC)
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many requests, try again later.")
    dq.append(now)

    if not verify_token(payload.a, payload.b, payload.ts, payload.token):
        raise HTTPException(status_code=400, detail="Captcha expired/invalid.")
    if payload.answer != (payload.a + payload.b):
        raise HTTPException(status_code=400, detail="Captcha answer incorrect.")

    print(f"[FEEDBACK] {payload.email}: {payload.message}")
    return JSONResponse({"ok": True, "received": True})
