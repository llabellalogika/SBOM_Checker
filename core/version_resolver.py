from typing import Dict, List, Optional

from core.db_manager import get_releases_for_library


def _normalizza(v: Optional[str]) -> str:
    return v.lstrip("vV") if isinstance(v, str) else ""


def _sort_releases(releases: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return sorted(
        releases,
        key=lambda r: ((r.get("release_date") or ""), _normalizza(r.get("version"))),
    )


def _is_security_update(flag: Optional[str]) -> bool:
    if flag is None:
        return False
    value = str(flag).strip().lower()
    return value not in {"0", "false", ""}


def _find_release(releases: List[Dict[str, str]], version: str) -> Optional[Dict[str, str]]:
    norm = _normalizza(version)
    for rel in releases:
        if _normalizza(rel.get("version")) == norm:
            return rel
    return None


def risolvi_versioni(libs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    For each input library [{name, version}] calculates:
      - latest available version and date
      - release date of the current version
      - whether security updates exist in subsequent releases
    """

    result = []
    for lib in libs:
        name = lib["name"]
        current_version = _normalizza(lib.get("version"))
        releases = _sort_releases(get_releases_for_library(name))

        latest_release = releases[-1] if releases else None
        current_release = _find_release(releases, current_version)

        latest_version = _normalizza(latest_release.get("version")) if latest_release else "not available"
        latest_date = (latest_release.get("release_date") or "n/a") if latest_release else "n/a"
        current_date = (current_release.get("release_date") or "n/a") if current_release else "n/a"

        if releases and current_release:
            idx = releases.index(current_release)
            intermediate = releases[idx + 1 :]
        else:
            intermediate = []

        security_releases = [r for r in intermediate if _is_security_update(r.get("security"))]
        has_security_updates = bool(security_releases)

        if not releases or current_release is None:
            status = "unknown"
            security_label = "n/a"
        elif has_security_updates:
            status = "needs update"
            security_label = "not secure"
        else:
            status = "up-to-date"
            security_label = "secure"

        result.append(
            {
                "name": name,
                "current": current_version,
                "current_date": current_date,
                "latest": latest_version,
                "latest_date": latest_date,
                "security_label": security_label,
                "status": status,
                "security_notes": security_releases,
            }
        )

    return result
