from pathlib import Path
from typing import Dict, List

from utils.colors import Fore, Style
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni


HEADERS = [
    "Library name",
    "Current version",
    "Latest available version",
    "Security of later versions",
]


def _column_widths(rows: List[Dict[str, str]]) -> List[int]:
    widths = [len(h) for h in HEADERS]
    for lib in rows:
        widths[0] = max(widths[0], len(lib.get("name", "")))
        widths[1] = max(widths[1], len(lib.get("current", "")))
        widths[2] = max(widths[2], len(lib.get("latest", "")))
        widths[3] = max(widths[3], len(lib.get("security_label", "")))
    return widths


def _current_color(status: str) -> str:
    if status == "up-to-date":
        return Fore.GREEN
    if status == "needs update":
        return Fore.RED
    return Fore.YELLOW


def _security_color(label: str) -> str:
    if label.lower() == "secure":
        return Fore.GREEN
    if label.lower() == "not secure":
        return Fore.RED
    return Fore.YELLOW


def report_for_sbom(path: Path) -> None:
    comps = carica_sbom_generico(path)
    libs = estrai_librerie(comps)
    data = risolvi_versioni(libs)
    count_needs_update = sum(1 for lib in data if lib["status"] == "needs update")

    widths = _column_widths(data)
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    header_cells = [h.ljust(w) for h, w in zip(HEADERS, widths)]
    header_line = "| " + " | ".join(Fore.MAGENTA + cell + Style.RESET_ALL for cell in header_cells) + " |"

    print(f"\n{Fore.GREEN}SBOM: {path.name}{Style.RESET_ALL}")
    print(border)
    print(header_line)
    print(border)

    for lib in data:
        status = lib["status"]
        name_raw = lib["name"].ljust(widths[0])
        current_raw = lib["current"].ljust(widths[1])
        latest_raw = lib["latest"].ljust(widths[2])
        security_raw = lib.get("security_label", "").ljust(widths[3])

        name_cell = Fore.CYAN + name_raw + Style.RESET_ALL
        current_cell = _current_color(status) + current_raw + Style.RESET_ALL
        latest_cell = Fore.CYAN + latest_raw + Style.RESET_ALL
        security_cell = _security_color(lib.get("security_label", "")) + security_raw + Style.RESET_ALL

        row = "| " + " | ".join(
            [
                name_cell,
                current_cell,
                latest_cell,
                security_cell,
            ]
        ) + " |"
        print(row)

    print(border)
    print(
        f"\nLibraries requiring updates: {Fore.RED}{count_needs_update}{Style.RESET_ALL}" if count_needs_update else
        f"\nLibraries requiring updates: {Fore.GREEN}{count_needs_update}{Style.RESET_ALL}"
    )

    notes_to_print = [lib for lib in data if lib.get("security_notes")]
    if notes_to_print:
        print(f"\n{Fore.MAGENTA}Release notes with security updates:{Style.RESET_ALL}")
        for lib in notes_to_print:
            print(f"\n{Fore.CYAN}{lib['name']}{Style.RESET_ALL}")
            for rel in lib["security_notes"]:
                version = rel.get("version", "")
                date = rel.get("release_date") or "date n/a"
                notes = rel.get("release_notes") or "No release notes available."
                print(f"  {Fore.YELLOW}{version}{Style.RESET_ALL} ({date})")
                for line in notes.splitlines():
                    print(f"    - {line}")
    else:
        print(f"\n{Style.DIM}No security updates detected in later versions.{Style.RESET_ALL}")

