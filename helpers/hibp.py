import os, httpx
from typing import List, Dict

API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
KEY = os.environ.get("HIBP_API_KEY", "").strip()

async def hibp_breaches(email: str) -> List[Dict]:
    if not KEY:
        return []
    headers = {
        "hibp-api-key": KEY,
        "user-agent": "exposureshield/1.0",
    }
    params = {"truncateResponse": "false"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(API.format(account=email), headers=headers, params=params)
        if r.status_code == 404:
            return []  # no breaches
        r.raise_for_status()
        data = r.json()
        # Ensure list-of-dicts
        return data if isinstance(data, list) else []
