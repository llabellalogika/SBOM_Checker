from urllib.parse import urlparse
import requests
from typing import Iterable, List, Dict, Optional

from core.constants import OSV_PACKAGE_MAP


def _normalize_repo_from_url(url: str) -> Optional[Dict[str, str]]:
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    netloc = parsed.netloc.lower()
    if netloc == "github.com":
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1].removesuffix(".git")
            return {"ecosystem": "GitHub", "name": f"{owner}/{repo}"}
    if url.startswith("https://git.savannah.nongnu.org/git/lwip.git"):
        return {"ecosystem": "Git", "name": "https://git.savannah.nongnu.org/git/lwip.git"}
    return None


def _build_package_payload(name: str, purl: Optional[str], references: Iterable[str]) -> Optional[Dict[str, str]]:
    package: Dict[str, str] = {}

    if purl and not purl.startswith("pkg:generic/"):
        package["purl"] = purl

    mapping = OSV_PACKAGE_MAP.get(name)
    if mapping:
        package.update(mapping)

    if "ecosystem" not in package or "name" not in package:
        for ref in references or []:
            repo = _normalize_repo_from_url(ref)
            if repo:
                package.update(repo)
                break

    if not package:
        return None

    return package


def get_vulns_osv(
    name: str,
    version: str,
    purl: Optional[str] = None,
    references: Optional[Iterable[str]] = None,
) -> List[Dict]:
    package = _build_package_payload(name, purl, references or [])
    if not package:
        return []

    url = "https://api.osv.dev/v1/query"
    payload = {"version": version, "package": package}

    try:
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()
        return r.json().get("vulns", [])
    except Exception:
        return []
