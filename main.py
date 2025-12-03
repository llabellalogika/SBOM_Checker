import sys
from pathlib import Path

from utils.colors import Fore, Style
from utils.paths import SBOM_DIR
from core.constants import FIRMWARE_LIBRARIES
from core.sbom_reader import carica_sbom_generico, estrai_librerie
from core.version_resolver import risolvi_versioni
from core.report_generator import report_for_sbom

def _build_reports(sbom_files):
    reports = []
    for sbom_file in sbom_files:
        libs = estrai_librerie(carica_sbom_generico(sbom_file))
        data = risolvi_versioni(libs)
        count_da = sum(1 for lib in data if lib['status'] == 'da aggiornare')
        reports.append((sbom_file, data, count_da))
    return reports

def _menu(reports):
    while True:
        print("\n Vuoi eseguire una ricerca?")
        print("1. Cerca una libreria da aggiornare")
        print("2. Cerca una SBOM specifica")
        print("3. Esci")
        scelta = input(" Inserisci la tua scelta (1/2/3): ").strip()

        if scelta == "1":
            query = input(" Nome della libreria: ").strip()
            if query.lower() in {lib.lower() for lib in FIRMWARE_LIBRARIES}:
                trovate = False
                print(f"\n SBOM con '{query}' da aggiornare:")
                for sbom_file, data, _ in reports:
                    for lib in data:
                        if lib['name'].lower() == query.lower() and lib['status'] == "da aggiornare":
                            print(f" {sbom_file.name} → Versione attuale: {lib['current']} | Ultima: {lib['latest']}")
                            trovate = True
                if not trovate:
                    print(f" Nessuna SBOM con '{query}' da aggiornare.")
            else:
                print(f" Libreria '{query}' non riconosciuta.")
        elif scelta == "2":
            nome_sbom = input(" Inserisci il nome del file SBOM (es. SBOM_FIRMWARE.json o TMB2.spdx): ").strip().lower()
            path_match = next((x[0] for x in reports if x[0].name.strip().lower() == nome_sbom), None)
            if path_match:
                report_for_sbom(path_match)
            else:
                print(f" File '{nome_sbom}' non trovato.")
        elif scelta == "3":
            print(" Uscita dal programma.")
            sys.exit(0)
        else:
            print(" Scelta non valida. Riprova.")

def main():
    print(f"\nFirmware Checker - by {Fore.LIGHTYELLOW_EX}Logika{Fore.LIGHTGREEN_EX}Control{Style.RESET_ALL} (v1.0)\n")
    print(f"\nUsando cartella SBOM: {Fore.CYAN}{SBOM_DIR.resolve()}{Style.RESET_ALL}")

    if not SBOM_DIR.is_dir():
        print(f" Cartella non trovata: {SBOM_DIR}")
        sys.exit(1)

    # Cerca sia CycloneDX (*.json) sia SPDX tag-value (*.spdx)
    sbom_files = list(SBOM_DIR.glob("*.json")) + list(SBOM_DIR.glob("*.spdx"))
    if not sbom_files:
        print(" Nessun file .json o .spdx trovato in SBOM_DIR.")
        sys.exit(1)

    reports = _build_reports(sbom_files)

    for sbom_file, _, _ in reports:
        report_for_sbom(sbom_file)

    _menu(reports)

if __name__ == "__main__":
    main()
