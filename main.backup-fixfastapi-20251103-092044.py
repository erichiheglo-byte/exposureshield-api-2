from pathlib import Path
from dotenv import load_dotenv, find_dotenv
import os

dotenv_path = find_dotenv(filename=".env", usecwd=True)
if not dotenv_path:
    dotenv_path = str((Path(__file__).parent / ".env").resolve())
load_dotenv(dotenv_path=dotenv_path, override=True)

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
USER_AGENT = "ExposureShield/0.5.4 (contact@exposureshield.com)"

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

# Cache: 5 min TTL
verify_cache = TTLCache(maxsize=100, ttl=300)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "exposureshield-api",
        "store": "sqlite",
        "version": APP_VERSION,
        "uptime_sec": round(time.time() - START_TS, 1),
        "has_hibp_key": bool(HIBP_API_KEY)
    }

@app.get("/verify")
def verify(email: str = Query(..., min_length=3, max_length=254)):
    if email in verify_cache:
        return {"verified": True if verify_cache[email] else False, "breaches": verify_cache[email]}

    if not HIBP_API_KEY:
        raise HTTPException(status_code=500, detail="HIBP key not configured")

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": USER_AGENT,
    }

    try:
        with httpx.Client(timeout=httpx.Timeout(8.0)) as client:
            r = client.get(url, headers=headers, params={"truncateResponse": "false"})
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    if r.status_code == 200:
        data = r.json()
        breaches = [{"name": b.get("Name"), "domain": b.get("Domain")} for b in data]
        verify_cache[email] = breaches
        return {"verified": True, "breaches": breaches}
    elif r.status_code == 404:
        verify_cache[email] = []
        return {"verified": False, "breaches": []}
    elif r.status_code == 429:
        raise HTTPException(status_code=429, detail="Rate limited by HIBP")
    elif r.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="HIBP authentication failed")
    else:
        raise HTTPException(status_code=502, detail=f"HIBP error {r.status_code}")

