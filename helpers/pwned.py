import hashlib
import httpx

PP_API = "https://api.pwnedpasswords.com/range/{prefix}"

async def pwned_password_count(password: str) -> int:
    # SHA1
    sha = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    url = PP_API.format(prefix=prefix)
    async with httpx.AsyncClient(timeout=10.0, headers={"Add-Padding": "true"}) as client:
        r = await client.get(url)
        r.raise_for_status()
        for line in r.text.splitlines():
            try:
                sfx, count = line.split(":")
                if sfx.strip().upper() == suffix:
                    return int(count)
            except ValueError:
                continue
    return 0
