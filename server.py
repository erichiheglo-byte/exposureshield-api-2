from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="ExposureShield API", version="0.1.0")

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

# ---- Public endpoints (frontend expects these) ----
@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api"}

class ScanIn(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    result: str                  # "success"
    email: str
    status: str                  # "no_exposure" | "exposure_found"
    advice: list[str] | None = None

@app.post("/scan", response_model=ScanOut)
def scan(payload: ScanIn):
    pwd = payload.password.strip().lower()
    if pwd in {"pwned","leak","breach"}:
        return {
            "result": "success",
            "email": payload.email,
            "status": "exposure_found",
            "advice": [
                "Change this password everywhere you used it.",
                "Turn on 2FA for your important accounts.",
                "Run a new scan after changes.",
            ],
        }
    return {
        "result": "success",
        "email": payload.email,
        "status": "no_exposure",
        "advice": [
            "Use a password manager and unique passwords.",
            "Keep 2FA enabled on email and banking.",
        ],
    }

# ---- OPTIONAL: mount your existing admin router at /admin if present ----
try:
    # Try common module names; ignore if not found
    from admin import router as admin_router
    app.include_router(admin_router, prefix="/admin")
except Exception:
    try:
        from app.admin import router as admin_router
        app.include_router(admin_router, prefix="/admin")
    except Exception:
        pass
