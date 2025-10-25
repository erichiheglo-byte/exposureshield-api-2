from typing import Optional, Dict, Deque, Literal
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hmac, hashlib, os, random, json, sqlite3, csv, io

from fastapi import FastAPI, Request, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, EmailStr
import httpx

# ---------------- Config ----------------
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "https://www.exposureshield.com",
]

STORE_MODE = os.getenv("STORE_MODE", "sqlite").lower()  # "sqlite" or "file"

DB_PATH = Path(os.getenv("DB_PATH", "./exposureshield.db")).resolve()
FEEDBACK_LOG_PATH = Path(os.getenv("FEEDBACK_LOG_PATH", "./feedback.ndjson")).resolve()
SCANS_LOG_PATH = Path(os.getenv("SCANS_LOG_PATH", "./scans.ndjson")).resolve()

SECRET = os.getenv("FEEDBACK_SECRET", "dev-secret-change-me")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-this-admin-token")
CAPTCHA_TTL_SEC = int(os.getenv("CAPTCHA_TTL_SEC", "300"))     # 5 min
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
RATE_LIMIT_FEEDBACK_MAX = int(os.getenv("RATE_LIMIT_FEEDBACK_MAX", "3"))
RATE_LIMIT_SCAN_MAX = int(os.getenv("RATE_LIMIT_SCAN_MAX", "8"))

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
NOTIFY_TO = os.getenv("NOTIFY_TO")  # e.g., "you@example.com"
NOTIFY_FROM = os.getenv("NOTIFY_FROM", "no-reply@exposureshield.local")

CSP = os.getenv("CSP",
    "default-src 'self'; "
    "connect-src 'self' http://127.0.0.1:8888 http://localhost:8888; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
)
HSTS = os.getenv("HSTS", "max-age=31536000; includeSubDomains; preload")

# ---------------- App ----------------
app = FastAPI(title="ExposureShield API", version="1.0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["Strict-Transport-Security"] = HSTS
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp

# ---------------- Models ----------------
class ScanRequest(BaseModel):
    email: EmailStr
    password: str

class ScanResponse(BaseModel):
    result: str
    email: EmailStr
    status: str
    advice: Optional[list[str]] = None

class FeedbackIn(BaseModel):
    email: EmailStr
    message: str
    a: int
    b: int
    ts: int
    token: str
    answer: int

# ---------------- Utils ----------------
def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sign_token(a: int, b: int, ts: int) -> str:
    msg = f"{a}:{b}:{ts}".encode()
    return hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()

def verify_token(a: int, b: int, ts: int, tok: str) -> bool:
    if abs(int(datetime.now(timezone.utc).timestamp()) - ts) > CAPTCHA_TTL_SEC:
        return False
    return hmac.compare_digest(sign_token(a, b, ts), tok)

def hash_email(email: str) -> str:
    return hashlib.sha256((SECRET + "|" + email.lower()).encode()).hexdigest()

# ---------------- DB & File ----------------
DB_CONN: Optional[sqlite3.Connection] = None

def db_connect() -> sqlite3.Connection:
    global DB_CONN
    if DB_CONN is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        DB_CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
        DB_CONN.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT NOT NULL,
              message TEXT NOT NULL,
              ip TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
        """)
        DB_CONN.execute("""
            CREATE TABLE IF NOT EXISTS scans (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              ip TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
        """)
        DB_CONN.commit()
    return DB_CONN

def save_feedback_sqlite(email: str, message: str, ip: str) -> None:
    con = db_connect()
    con.execute(
        "INSERT INTO feedback (email, message, ip, created_at) VALUES (?, ?, ?, ?)",
        (email, message, ip, utcnow_iso())
    )
    con.commit()

def save_scan_sqlite(email_hash: str, status: str, ip: str) -> None:
    con = db_connect()
    con.execute(
        "INSERT INTO scans (email_hash, status, ip, created_at) VALUES (?, ?, ?, ?)",
        (email_hash, status, ip, utcnow_iso())
    )
    con.commit()

def append_ndjson(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def save_feedback_file(email: str, message: str, ip: str) -> None:
    append_ndjson(FEEDBACK_LOG_PATH, {"email": email, "message": message, "ip": ip, "created_at": utcnow_iso()})

def save_scan_file(email_hash: str, status: str, ip: str) -> None:
    append_ndjson(SCANS_LOG_PATH, {"email_hash": email_hash, "status": status, "ip": ip, "created_at": utcnow_iso()})

def persist_feedback(email: str, message: str, ip: str) -> None:
    try:
        if STORE_MODE == "sqlite":
            save_feedback_sqlite(email, message, ip)
        else:
            save_feedback_file(email, message, ip)
    except Exception as e:
        print(f"[WARN] Feedback primary store failed: {e}; writing to file")
        save_feedback_file(email, message, ip)

def persist_scan(email_hash: str, status: str, ip: str) -> None:
    try:
        if STORE_MODE == "sqlite":
            save_scan_sqlite(email_hash, status, ip)
        else:
            save_scan_file(email_hash, status, ip)
    except Exception as e:
        print(f"[WARN] Scan primary store failed: {e}; writing to file")
        save_scan_file(email_hash, status, ip)

# ---------------- Rate limits ----------------
recent_feedback: Dict[str, Deque[datetime]] = {}
recent_scan: Dict[str, Deque[datetime]] = {}

def check_rate(ip: str, bucket: Literal["feedback","scan"]) -> None:
    now = datetime.now(timezone.utc)
    table = recent_feedback if bucket=="feedback" else recent_scan
    limit = RATE_LIMIT_FEEDBACK_MAX if bucket=="feedback" else RATE_LIMIT_SCAN_MAX
    dq = table.setdefault(ip, deque())
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SEC)
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests, try again shortly.")
    dq.append(now)

# ---------------- Email notify (optional) ----------------
async def notify_feedback(email: str, message: str):
    if not (SENDGRID_API_KEY and NOTIFY_TO):
        return
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            payload = {
                "personalizations": [{"to": [{"email": NOTIFY_TO}]}],
                "from": {"email": NOTIFY_FROM},
                "subject": f"ExposureShield feedback from {email}",
                "content": [{"type": "text/plain", "value": message}],
            }
            r = await client.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
                json=payload,
            )
            if r.status_code >= 300:
                print(f"[WARN] SendGrid failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"[WARN] notify_feedback error: {e}")

# ---------------- Routes ----------------
@app.get("/health")
def health():
    return {"status": "ok", "service": "exposureshield-api", "store": STORE_MODE}

@app.post("/scan", response_model=ScanResponse)
async def scan(req: Request, payload: ScanRequest):
    ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "unknown")
    check_rate(ip, "scan")
    advice = [
        "Turn on 2FA for your email.",
        "Update weak/reused passwords.",
        "Use a password manager.",
    ]
    status = "demo mode"
    persist_scan(hash_email(payload.email), status, ip)
    return {"result": "success", "email": payload.email, "status": status, "advice": advice}

# ---- Captcha (exists here!) ----
@app.get("/feedback/captcha")
def feedback_captcha(easy: int = Query(1, ge=0, le=1)):
    a = random.randint(1, 5) if easy else random.randint(2, 9)
    b = random.randint(1, 5) if easy else random.randint(2, 9)
    s = a + b
    opts = {s}
    while len(opts) < 3:
        delta = random.choice([1, 2])
        cand = s + delta if random.choice([True, False]) else s - delta
        if cand > 0:
            opts.add(cand)
    options = list(opts)
    random.shuffle(options)
    ts = int(datetime.now(timezone.utc).timestamp())
    token = sign_token(a, b, ts)
    return {"a": a, "b": b, "ts": ts, "token": token, "options": options}

@app.post("/feedback")
async def feedback(req: Request, payload: FeedbackIn):
    ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "unknown")
    check_rate(ip, "feedback")
    if not verify_token(payload.a, payload.b, payload.ts, payload.token):
        raise HTTPException(status_code=400, detail="Captcha expired or invalid. Refresh and try again.")
    if payload.answer != (payload.a + payload.b):
        raise HTTPException(status_code=400, detail="Captcha incorrect. Try again.")
    persist_feedback(payload.email, payload.message, ip)
    await notify_feedback(payload.email, payload.message)
    return JSONResponse({"ok": True, "received": True})

def require_admin(request: Request):
    token = request.headers.get("X-Admin-Token")
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/admin/feedback/export")
def export_feedback(request: Request, format: Literal["csv","json"]="csv"):
    require_admin(request)
    if STORE_MODE == "sqlite":
        con = db_connect()
        rows = list(con.execute("SELECT email, message, ip, created_at FROM feedback ORDER BY id DESC"))
        if format == "json":
            return JSONResponse([{"email":e,"message":m,"ip":i,"created_at":c} for (e,m,i,c) in rows])
        output = io.StringIO()
        w = csv.writer(output); w.writerow(["email","message","ip","created_at"])
        for e,m,i,c in rows: w.writerow([e,m,i,c])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")
    else:
        if not FEEDBACK_LOG_PATH.exists():
            return PlainTextResponse("email,message,ip,created_at\n", media_type="text/csv")
        with FEEDBACK_LOG_PATH.open("r", encoding="utf-8") as f:
            lines = [json.loads(x) for x in f if x.strip()]
        if format == "json":
            return JSONResponse(lines)
        output = io.StringIO()
        w = csv.writer(output); w.writerow(["email","message","ip","created_at"])
        for r in lines: w.writerow([r.get("email",""), r.get("message",""), r.get("ip",""), r.get("created_at","")])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

@app.get("/admin/scans/export")
def export_scans(request: Request, format: Literal["csv","json"]="csv"):
    require_admin(request)
    if STORE_MODE == "sqlite":
        con = db_connect()
        rows = list(con.execute("SELECT email_hash, status, ip, created_at FROM scans ORDER BY id DESC"))
        if format == "json":
            return JSONResponse([{"email_hash":h,"status":s,"ip":i,"created_at":c} for (h,s,i,c) in rows])
        output = io.StringIO()
        w = csv.writer(output); w.writerow(["email_hash","status","ip","created_at"])
        for h,s,i,c in rows: w.writerow([h,s,i,c])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")
    else:
        if not SCANS_LOG_PATH.exists():
            return PlainTextResponse("email_hash,status,ip,created_at\n", media_type="text/csv")
        with SCANS_LOG_PATH.open("r", encoding="utf-8") as f:
            lines = [json.loads(x) for x in f if x.strip()]
        if format == "json":
            return JSONResponse(lines)
        output = io.StringIO()
        w = csv.writer(output); w.writerow(["email_hash","status","ip","created_at"])
        for r in lines: w.writerow([r.get("email_hash",""), r.get("status",""), r.get("ip",""), r.get("created_at","")])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

# ---- Admin metrics (last 7 days) ----
def _date_key(iso_ts: str) -> str:
    return iso_ts[:10]

def _last_n_dates(n=7):
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=i)).isoformat() for i in range(n-1, -1, -1)]

@app.get("/admin/metrics")
def admin_metrics(request: Request):
    require_admin(request)
    dates = _last_n_dates(7)
    scans_by_day = {d: 0 for d in dates}
    fdbk_by_day = {d: 0 for d in dates}
    scans_total = 0
    fdbk_total = 0
    if STORE_MODE == "sqlite":
        con = db_connect()
        for (ts,) in con.execute("SELECT created_at FROM scans"):
            d = _date_key(ts); scans_total += 1; 
            if d in scans_by_day: scans_by_day[d] += 1
        for (ts,) in con.execute("SELECT created_at FROM feedback"):
            d = _date_key(ts); fdbk_total += 1;
            if d in fdbk_by_day: fdbk_by_day[d] += 1
    else:
        if SCANS_LOG_PATH.exists():
            with SCANS_LOG_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        obj = json.loads(line); scans_total += 1
                        d = _date_key(obj.get("created_at",""))
                        if d in scans_by_day: scans_by_day[d] += 1
                    except: pass
        if FEEDBACK_LOG_PATH.exists():
            with FEEDBACK_LOG_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        obj = json.loads(line); fdbk_total += 1
                        d = _date_key(obj.get("created_at",""))
                        if d in fdbk_by_day: fdbk_by_day[d] += 1
                    except: pass
    return {
        "totals": {"scans": scans_total, "feedback": fdbk_total},
        "series": {"dates": dates, "scans": [scans_by_day[d] for d in dates], "feedback": [fdbk_by_day[d] for d in dates]}
    }
# ---- Debug: list registered routes
@app.get("/__routes")
def __routes():
    return [
        {"path": r.path, "name": r.name, "methods": sorted(list(r.methods or []))}
        for r in app.routes
    ]
