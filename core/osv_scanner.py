import requests
from typing import List, Dict

def get_vulns_osv(name: str, version: str) -> List[Dict]:
    url = "https://api.osv.dev/v1/query"
    payload = {"version": version, "package": {"name": name, "ecosystem": "GitHub"}}
    try:
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return r.json().get("vulns", [])
    except Exception:
        return []
