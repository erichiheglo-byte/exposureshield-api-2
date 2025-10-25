import json
from pathlib import Path
from typing import List, Dict

_DATA: Dict = {}
def load_dataset(path: str = "data/ihavepwned.json") -> None:
    global _DATA
    p = Path(path)
    if p.exists():
        _DATA = json.loads(p.read_text(encoding="utf-8"))
    else:
        _DATA = {"breaches": []}

def lookup_email(email: str) -> List[Dict]:
    if not _DATA:
        load_dataset()
    e = email.strip().lower()
    return [b for b in _DATA.get("breaches", []) if str(b.get("email","")).lower() == e]
