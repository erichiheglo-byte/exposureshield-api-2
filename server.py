from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Literal
import os
import time

app = FastAPI()

# CORS — allow production frontends
origins = ["https://exposureshield.com","https://www.exposureshield.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://.*\.vercel\.app$",
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)# --- CORS ---
origins = ["https://exposureshield.com","https://www.exposureshield.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https://.*\.vercel\.app$",
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)
# --- end CORS ---

# --- Models ---
ResultLiteral = Literal["success", "error"]
StatusLiteral = Literal["no_exposure", "exposure_found", "error", "loading", "idle"]

class ScanIn(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    result: ResultLiteral
    email: str
    status: StatusLiteral
    advice: List[str]
    # optional extras expected by UI
    pwned_count: Optional[int] = None
    dataset_matches: Optional[int] = None
    hibp_breaches_count: Optional[int] = None
    hibp_breaches: Optional[List[str]] = None

class FeedbackIn(BaseModel):
    message: str
    email: Optional[str] = None

class FeedbackOut(BaseModel):
    ok: bool

# --- Basic endpoints ---
@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": "sqlite"}

@app.get("/")
def root():
    return {"ok": True, "service": "exposureshield-api"}

@app.get("/version")
def version():
    return {"service": "exposureshield-api", "version": app.version}

# --- /scan (simple demo logic; replace with real helpers later) ---
@app.post("/scan", response_model=ScanOut)
def scan(body: ScanIn):
    email = body.email.strip().lower()
    pw = body.password or ""

    advice: List[str] = [
        "Use a password manager and unique passwords.",
        "Keep 2FA enabled.",
    ]

    # Very simple demo heuristic to unblock the UI:
    if len(pw) < 8 or pw.lower() in {"password", "12345678", "qwerty"}:
        # pretend exposure found
        out = ScanOut(
            result="success",
            email=email,
            status="exposure_found",
            advice=[
                "Your password is weak or common. Change it everywhere.",
                "Enable 2FA on important accounts.",
            ],
            pwned_count=1654698,
            dataset_matches=0,
            hibp_breaches_count=3,
            hibp_breaches=["Adobe", "Gawker", "Yahoo"],
        )
        return out

    # otherwise, no exposure (demo)
    out = ScanOut(
        result="success",
        email=email,
        status="no_exposure",
        advice=advice,
        pwned_count=0,
        dataset_matches=0,
        hibp_breaches_count=0,
        hibp_breaches=[],
    )
    return out

# --- /feedback (no captcha) ---
@app.post("/feedback", response_model=FeedbackOut)
async def feedback_submit(data: FeedbackIn):
    print("[feedback]", {"email": data.email, "len": len(data.message)})
    return FeedbackOut(ok=True)


