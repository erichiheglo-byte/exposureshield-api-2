import os, httpx

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

async def verify_turnstile(token: str, remote_ip: str | None = None) -> bool:
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret:
        # No key configured -> treat as not available (caller may use math fallback)
        return False
    data = {"secret": secret, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(TURNSTILE_VERIFY_URL, data=data)
        ok = r.status_code == 200 and r.json().get("success") is True
        return ok
