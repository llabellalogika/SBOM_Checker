from __future__ import annotations

from typing import Dict, Iterable, List, Optional

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _build_keyword_terms(name: str, version: str, aliases: Optional[Iterable[str]] = None) -> List[str]:
    terms = [f"{name} {version}"]
    if aliases:
        for alias in aliases:
            alias = alias.strip()
            if alias and alias.lower() != name.lower():
                terms.append(f"{alias} {version}")
    return terms


def get_vulns_nvd(
    name: str,
    version: str,
    *,
    cpe: Optional[str] = None,
    aliases: Optional[Iterable[str]] = None,
    max_results: int = 20,
) -> List[Dict]:
    """Interroga il catalogo CVE NVD cercando corrispondenze per nome/versione."""

    params: Dict[str, str] = {"resultsPerPage": str(max_results)}
    headers = {"User-Agent": "SBOMChecker/1.0"}

    keyword_terms = _build_keyword_terms(name, version, aliases)

    if cpe and cpe.strip():
        params["cpeName"] = cpe.strip()

    vulns: List[Dict] = []

    for term in keyword_terms or [name]:
        params["keywordSearch"] = term
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
            resp.raise_for_status()
        except Exception:
            continue

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            summary = ""
            titles = cve.get("descriptions") or cve.get("titles") or []
            if titles:
                summary = titles[0].get("value") or titles[0].get("title") or ""

            vuln_entry = {
                "id": cve_id,
                "summary": summary,
                "source": "NVD",
                "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")],
            }

            if vuln_entry not in vulns:
                vulns.append(vuln_entry)

        if vulns:
            break

    return vulns
