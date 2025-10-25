from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# 🔓 Wide-open CORS (for testing only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

class ScanRequest(BaseModel):
    email: str
    password: str

@app.post("/scan")
def scan(req: ScanRequest):
    return {"ok": True, "email": req.email}
