import time, secrets
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel
from helpers.turnstile import verify_turnstile

router = APIRouter()

_MATH = {}
def _math_new():
    cid = secrets.token_hex(8)
    a = secrets.randbelow(8) + 2
    b = secrets.randbelow(8) + 2
    _MATH[cid] = {"ans": a + b, "ts": time.time()}
    return cid, a, b

def _math_check(cid: str, ans: int) -> bool:
    rec = _MATH.pop(cid, None)
    if not rec:
        return False
    if time.time() - rec["ts"] > 300:
        return False
    try:
        return int(ans) == int(rec["ans"])
    except Exception:
        return False

class FeedbackIn(BaseModel):
    message: str
    email: Optional[str] = None
    turnstile_token: Optional[str] = None
    math_challenge_id: Optional[str] = None
    math_answer: Optional[int] = None

class FeedbackOut(BaseModel):
    ok: bool
    used: str

@router.get("/feedback/captcha")
def feedback_captcha():
    cid, a, b = _math_new()
    return {"id": cid, "a": a, "b": b, "prompt": f"{a} + {b} = ?"}

@router.post("/feedback", response_model=FeedbackOut)
async def feedback_submit(data: FeedbackIn):
    used = "none"
    ok = False
    if data.turnstile_token:
        try:
            if await verify_turnstile(data.turnstile_token, None):
                ok, used = True, "turnstile"
        except Exception:
            ok = False
    if not ok and data.math_challenge_id and data.math_answer is not None:
        if _math_check(data.math_challenge_id, data.math_answer):
            ok, used = True, "math"
    if not ok:
        return FeedbackOut(ok=False, used=used)
    print("[feedback]", {"email": data.email, "used": used, "len": len(data.message)})
    return FeedbackOut(ok=True, used=used)
