import re
from pathlib import Path
from typing import Dict, List

from utils.colors import Fore, Style

from core.osv_scanner import get_vulns_osv
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni


HEADERS = [
    "Nome libreria",
    "Versione attuale",
    "Ultima versione",
    "Fonte",
    "Stato",
]


def _column_widths(rows: List[Dict[str, str]]) -> List[int]:
    widths = [len(h) for h in HEADERS]
    for lib in rows:
        widths[0] = max(widths[0], len(lib.get("name", "")))
        widths[1] = max(widths[1], len(lib.get("current", "")))
        widths[2] = max(widths[2], len(lib.get("latest", "")))
        widths[3] = max(widths[3], len(lib.get("source", "")))
        widths[4] = max(widths[4], len(lib.get("status", "")))
    return widths


def _status_color(status: str) -> str:
    if status == "aggiornata":
        return Fore.GREEN
    if status == "da aggiornare":
        return Fore.RED
    return Fore.YELLOW


def _current_color(status: str) -> str:
    if status == "aggiornata":
        return Fore.GREEN
    if status == "da aggiornare":
        return Fore.RED
    return Fore.YELLOW


def _latest_color(status: str, latest: str) -> str:
    if latest == "non rilevata":
        return Fore.YELLOW
    if status == "da aggiornare":
        return Fore.GREEN
    if status == "aggiornata":
        return Fore.GREEN
    return Fore.YELLOW


def _severity_label(vuln: Dict) -> str:
    severity = vuln.get("severity") or []
    if severity:
        entry = severity[0]
        stype = (entry.get("type") or "").replace("_", " ")
        score = entry.get("score")
        if score:
            return f"{stype} {score}".strip()
        return stype or "n.d."

    database = vuln.get("database_specific")
    if isinstance(database, dict):
        db_sev = database.get("severity")
        if db_sev:
            return str(db_sev)

    return "n.d."


def _severity_color(label: str) -> str:
    norm = label.upper()
    if "CRITICAL" in norm:
        return Fore.RED
    if "HIGH" in norm or "ALTA" in norm:
        return Fore.LIGHTRED_EX
    if "MEDIUM" in norm or "MODERATE" in norm or "MEDIA" in norm:
        return Fore.YELLOW
    if "LOW" in norm or "BASSA" in norm:
        return Fore.GREEN

    match = re.search(r"\d+(?:\.\d+)?", label)
    if match:
        try:
            score = float(match.group())
            if score >= 9:
                return Fore.RED
            if score >= 7:
                return Fore.LIGHTRED_EX
            if score >= 4:
                return Fore.YELLOW
            if score > 0:
                return Fore.GREEN
        except ValueError:
            pass

    return Fore.CYAN


def _format_summary(vuln: Dict) -> str:
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        return "Nessuna descrizione fornita da OSV."
    return summary.splitlines()[0]


def report_for_sbom(path: Path) -> None:
    comps = carica_sbom_generico(path)
    libs = estrai_librerie(comps)
    data = risolvi_versioni(libs)
    count_da = sum(1 for lib in data if lib["status"] == "da aggiornare")

    widths = _column_widths(data)
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    header_cells = [h.ljust(w) for h, w in zip(HEADERS, widths)]
    header_line = "| " + " | ".join(Fore.MAGENTA + cell + Style.RESET_ALL for cell in header_cells) + " |"

    print(
        f"\n{Fore.BLUE}Analisi file: {path.name}{Style.RESET_ALL} "
        f"{Style.DIM}(librerie da aggiornare: {count_da}){Style.RESET_ALL}"
    )
    print(border)
    print(header_line)
    print(border)

    for lib in data:
        status = lib["status"]
        name_raw = lib["name"].ljust(widths[0])
        current_raw = lib["current"].ljust(widths[1])
        latest_raw = lib["latest"].ljust(widths[2])
        source_raw = lib["source"].ljust(widths[3])
        status_raw = status.ljust(widths[4])

        name_cell = Fore.CYAN + name_raw + Style.RESET_ALL
        current_cell = _current_color(status) + current_raw + Style.RESET_ALL
        latest_cell = _latest_color(status, lib["latest"]) + latest_raw + Style.RESET_ALL
        if lib["source"]:
            source_cell = Fore.LIGHTMAGENTA_EX + source_raw + Style.RESET_ALL
        else:
            source_cell = Style.DIM + source_raw + Style.RESET_ALL
        status_cell = _status_color(status) + status_raw + Style.RESET_ALL

        row = "| " + " | ".join(
            [name_cell, current_cell, latest_cell, source_cell, status_cell]
        ) + " |"
        print(row)

    print(border)

    print(f"\n{Fore.MAGENTA}Vulnerabilità riscontrate nelle librerie della SBOM:{Style.RESET_ALL}")
    if not data:
        print(f"  {Style.DIM}Nessuna libreria riconosciuta nel file.{Style.RESET_ALL}")
        return

    for lib in data:
        status = lib["status"]
        scan = get_vulns_osv(lib["name"], lib["current"])
        current_cell = _current_color(status) + lib["current"] + Style.RESET_ALL

        print(
            f"\n{Fore.CYAN}{lib['name']}{Style.RESET_ALL} "
            f"({Style.DIM}versione{Style.RESET_ALL} {current_cell})"
        )

        if scan.get("error"):
            print(
                f"  {Fore.YELLOW}Impossibile contattare OSV: {scan['error']}.{Style.RESET_ALL}"
            )
            continue

        vulns = scan.get("vulns", [])
        if not vulns:
            query_desc = scan.get("query") or "query sconosciuta"
            print(
                f"  Nessuna vulnerabilità nota ({Style.DIM}ricerca: {query_desc}{Style.RESET_ALL})."
            )
            continue

        query_desc = scan.get("query")
        if query_desc:
            print(
                f"  {Style.DIM}Ricerca OSV effettuata con: {query_desc}.{Style.RESET_ALL}"
            )

        for vuln in vulns:
            vuln_id = vuln.get("id", "SENZA-ID")
            label = _severity_label(vuln)
            sev_color = _severity_color(label)
            summary = _format_summary(vuln)
            print(
                f"  - {sev_color}{vuln_id}{Style.RESET_ALL} "
                f"[{label}] {summary}"
            )

            refs = [
                ref.get("url")
                for ref in vuln.get("references", [])
                if isinstance(ref, dict) and ref.get("url")
            ]
            if refs:
                print(f"    Riferimenti: {Fore.CYAN}{refs[0]}{Style.RESET_ALL}")
                for extra in refs[1:3]:
                    print(f"                 {Fore.CYAN}{extra}{Style.RESET_ALL}")
