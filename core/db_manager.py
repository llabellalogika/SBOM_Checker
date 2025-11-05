import sqlite3
from typing import Optional
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

def get_latest_db_version(name: str) -> str:
    """
    Ritorna l’ultima versione nota per 'name' dalla tabella Version.
    """
    _ensure_connection()
    if _cursor:
        try:
            _cursor.execute('SELECT version FROM "Version" WHERE name = ?', (name,))
            row = _cursor.fetchone()
            if row and row[0]:
                return row[0]
        except Exception:
            pass
    return "non rilevata"
