from pathlib import Path
from typing import List, Dict
from utils.colors import Fore, Style
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni
from core.osv_scanner import get_vulns_osv

def report_for_sbom(path: Path) -> None:
    comps = carica_sbom_generico(path)
    libs = estrai_librerie(comps)
    data = risolvi_versioni(libs)
    count_da = sum(1 for lib in data if lib["status"] == "da aggiornare")

    print(f"\n\n=== Report per {path.name} (da aggiornare: {count_da}) ===")
    header = Fore.MAGENTA + "| Libreria   | Versione Attuale | Ultima Versione | Fonte         | Stato         |" + Style.RESET_ALL
    sep    = "|------------|------------------|-----------------|---------------|---------------|"
    print(header)
    print(sep)
    for lib in data:
        name_raw = lib['name'].ljust(10)
        cur_raw  = lib['current'].ljust(16)
        lat_raw  = lib['latest'].ljust(15)
        src_raw  = lib['source'].ljust(13)
        st_text  = lib['status'].ljust(13)

        name_col = Fore.CYAN + name_raw + Style.RESET_ALL
        if lib['status'] == 'aggiornata':
            st_col = Fore.GREEN + st_text + Style.RESET_ALL
        elif lib['status'] == 'da aggiornare':
            st_col = Fore.RED + st_text + Style.RESET_ALL
        else:
            st_col = Fore.YELLOW + st_text + Style.RESET_ALL

        print(f"| {name_col} | {cur_raw} | {lat_raw} | {src_raw} | {st_col} |")

    print(f"\n{Fore.MAGENTA}Vulnerabilità rilevate tramite OSV:{Style.RESET_ALL}")
    any_da = False
    for lib in data:
        if lib['status'] == 'da aggiornare':
            any_da = True
            vulns = get_vulns_osv(lib['name'], lib['current'])
            print(f"\n{Fore.CYAN}{lib['name']} ({lib['current']}):{Style.RESET_ALL}")
            if vulns:
                for v in vulns:
                    vid = v.get("id", "UNKNOWN")
                    summary = v.get("summary", "").split('\n')[0]
                    print(f"  - {vid}: {summary}")
            else:
                print("  Nessuna vulnerabilità trovata.")
    if not any_da:
        print("  (Nessuna libreria da aggiornare.)")
