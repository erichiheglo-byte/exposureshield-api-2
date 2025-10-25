from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

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

@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api"}

class ScanIn(BaseModel):
    email: str
    password: str

class ScanOut(BaseModel):
    result: str                 # "success"
    email: str
    status: str                 # "no_exposure" | "exposure_found"
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
