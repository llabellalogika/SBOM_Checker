import sys
from pathlib import Path

def _base_dir() -> Path:
    # Support PyInstaller builds (sys.frozen)
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent

BASE_DIR = _base_dir()
DATA_DIR = BASE_DIR / "data"
SBOM_DIR = DATA_DIR / "sbom"
DB_PATH = DATA_DIR / "Version.db"
