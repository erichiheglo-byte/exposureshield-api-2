from typing import Optional
import os, httpx

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

async def verify_turnstile(token: str, remote_ip: Optional[str] = None) -> bool:
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret:
        return False
    data = {"secret": secret, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(TURNSTILE_VERIFY_URL, data=data)
            if r.status_code != 200:
                return False
            js = r.json()
            return bool(js.get("success"))
    except Exception:
        return False
