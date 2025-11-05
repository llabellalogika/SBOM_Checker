import re
import requests
from typing import List, Dict
from core.constants import GITHUB_REPOS, FIRMWARE_LIBRARIES, GITHUB_TOKEN
from core.db_manager import get_latest_db_version

def _normalizza(v):
    return v.lstrip("vV") if isinstance(v, str) else v

def get_latest_github_version(owner: str, repo: str) -> str:
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    # releases/latest
    try:
        r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
                         headers=headers, timeout=10)
        if r.status_code == 200:
            tag = r.json().get("tag_name", "").lstrip("vV")
            if tag:
                return tag
    except Exception:
        pass
    # fallback: /tags
    try:
        r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/tags",
                         headers=headers, timeout=10)
        r.raise_for_status()
        tags = r.json()
        if tags:
            return tags[0].get("name", "").lstrip("vV") or "non rilevata"
    except Exception:
        pass
    return "non rilevata"

def get_latest_touchgfx() -> str:
    try:
        r = requests.get(
            "https://touchgfx.zendesk.com/hc/en-us/categories/360003871171-Downloads",
            timeout=10
        )
        m = re.search(r"TouchGFX\s+(\d+\.\d+\.\d+)", r.text)
        return m.group(1) if m else "non rilevata"
    except Exception:
        return "non rilevata"

def get_latest_fatfs() -> str:
    try:
        r = requests.get("http://elm-chan.org/fsw/ff/00index_e.html", timeout=10)
        m = re.search(r"FatFs\s+R(\d+\.\d+[a-z]?)", r.text)
        return f"R{m.group(1)}" if m else "non rilevata"
    except Exception:
        return "non rilevata"

def get_latest_lwip() -> str:
    try:
        r = requests.get("https://savannah.nongnu.org/news/?group=lwip", timeout=10)
        m = re.search(r"lwIP\s+(\d+\.\d+\.\d+)\s+released", r.text)
        return m.group(1) if m else "non rilevata"
    except Exception:
        return "non rilevata"

def risolvi_versioni(libs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Per ogni libreria in input [{name, version}] calcola:
      - latest
      - fonte
      - stato (aggiornata / da aggiornare / sconosciuto)
    """
    result = []
    for lib in libs:
        name = lib["name"]
        cur = _normalizza(lib["version"])
        lat = "non rilevata"
        fonte = ""

        if name in {"FAT-FS", "TouchGFX", "USB-HOST"}:
            v = get_latest_db_version(name)
            if v != "non rilevata":
                lat, fonte = _normalizza(v), "Library DB"

        elif name in GITHUB_REPOS:
            owner, repo = GITHUB_REPOS[name]
            v = get_latest_github_version(owner, repo)
            if v != "non rilevata":
                lat, fonte = _normalizza(v), "GitHub"

        elif name == "LwIP":
            v = get_latest_lwip()
            if v != "non rilevata":
                lat, fonte = _normalizza(v), "Savannah"

        status = "sconosciuto" if lat == "non rilevata" else ("aggiornata" if cur == lat else "da aggiornare")
        result.append({
            "name": name,
            "current": cur,
            "latest": lat,
            "source": fonte,
            "status": status
        })
    return result
