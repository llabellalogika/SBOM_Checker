import sqlite3
from typing import Dict, List, Optional

from utils.paths import DB_PATH

_conn = None
_cursor = None


def _ensure_connection():
    global _conn, _cursor
    if _conn is None:
        try:
            _conn = sqlite3.connect(str(DB_PATH))
            _cursor = _conn.cursor()
        except Exception:
            _conn = None
            _cursor = None


def _library_id(name: str) -> Optional[int]:
    """Returns the library ID for the given name (case-insensitive)."""

    _ensure_connection()
    if _cursor is None:
        return None

    try:
        _cursor.execute(
            'SELECT ID FROM "FirmwareLibraries" WHERE LOWER(name) = LOWER(?)', (name,)
        )
        row = _cursor.fetchone()
        return row[0] if row else None
    except Exception:
        return None


def get_releases_for_library(name: str) -> List[Dict[str, str]]:
    """Returns all releases for a library ordered by date."""

    lib_id = _library_id(name)
    if lib_id is None:
        return []

    try:
        _cursor.execute(
            'SELECT version, release_notes, release_date, security, cve '\
            'FROM "ReleaseNotes" WHERE "IDLibraries" = ? '
            'ORDER BY COALESCE(release_date, "") ASC, version ASC',
            (lib_id,),
        )
        rows = _cursor.fetchall() or []
        releases = []
        for version, notes, rel_date, security, cve in rows:
            releases.append(
                {
                    "version": version,
                    "release_notes": notes or "",
                    "release_date": rel_date,
                    "security": security,
                    "cve": cve or "",
                }
            )
        return releases
    except Exception:
        return []


def get_library_names() -> List[str]:
    """Returns the list of libraries present in the database."""

    _ensure_connection()
    if _cursor is None:
        return []

    try:
        _cursor.execute('SELECT name FROM "FirmwareLibraries"')
        return [row[0] for row in (_cursor.fetchall() or []) if row and row[0]]
    except Exception:
        return []
