from functools import lru_cache
from typing import Any, Dict, List, Optional

import requests

from core.constants import OSV_PACKAGE_REFERENCES

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _build_attempts(name: str, version: str) -> List[Dict[str, Any]]:
    """Restituisce una lista di payload/descrizioni da provare contro OSV."""

    meta = OSV_PACKAGE_REFERENCES.get(name, {})
    attempts: List[Dict[str, Any]] = []

    if meta.get("purl"):
        attempts.append(
            {
                "payload": {"package": {"purl": meta["purl"]}, "version": version},
                "description": f"purl {meta['purl']}",
            }
        )

    if meta.get("ecosystem") and meta.get("name"):
        attempts.append(
            {
                "payload": {
                    "package": {
                        "name": meta["name"],
                        "ecosystem": meta["ecosystem"],
                    },
                    "version": version,
                },
                "description": f"{meta['ecosystem']}::{meta['name']}",
            }
        )

    # Fallback minimale: nome libero dalla SBOM.
    attempts.append(
        {
            "payload": {"package": {"name": name}, "version": version},
            "description": f"nome '{name}'",
        }
    )

    # Deduplica mantenendo l'ordine.
    seen = set()
    unique_attempts: List[Dict[str, Any]] = []
    for attempt in attempts:
        package = attempt["payload"].get("package", {})
        key = (tuple(sorted(package.items())), attempt["payload"].get("version"))
        if key not in seen:
            seen.add(key)
            unique_attempts.append(attempt)
    return unique_attempts


def _query_osv(payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(OSV_QUERY_URL, json=payload, timeout=15)
    if response.status_code == 404:
        # Il package non è noto a OSV.
        return {"vulns": []}
    response.raise_for_status()
    data = response.json() if response.content else {}
    return {"vulns": data.get("vulns", [])}


@lru_cache(maxsize=128)
def get_vulns_osv(name: str, version: str) -> Dict[str, Any]:
    """Ricerca le vulnerabilità note su OSV e restituisce dettagli e diagnostica."""

    attempts = _build_attempts(name, version)
    last_error: Optional[str] = None
    last_success: Optional[Dict[str, Any]] = None

    for attempt in attempts:
        payload = attempt["payload"]
        descriptor = attempt["description"]
        try:
            result = _query_osv(payload)
        except Exception as exc:  # pragma: no cover - rete o HTTP variabile
            last_error = str(exc)
            continue

        record = {"vulns": result.get("vulns", []), "query": descriptor, "error": None}

        if record["vulns"]:
            return record

        last_success = record

    if last_success is not None:
        return last_success

    descriptor = attempts[0]["description"] if attempts else "nessuna ricerca"
    return {"vulns": [], "query": descriptor, "error": last_error}
