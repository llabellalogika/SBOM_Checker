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
        count_needs_update = sum(1 for lib in data if lib['status'] == 'needs update')
        reports.append((sbom_file, data, count_needs_update))
    return reports

def _menu(reports):
    while True:
        print("\n Do you want to run a search?")
        print("1. Find a library that needs an update")
        print("2. Find a specific SBOM")
        print("3. Exit")
        scelta = input(" Enter your choice (1/2/3): ").strip()

        if scelta == "1":
            query = input(" Library name: ").strip()
            if query.lower() in {lib.lower() for lib in FIRMWARE_LIBRARIES}:
                found = False
                print(f"\n SBOMs with '{query}' needing an update:")
                for sbom_file, data, _ in reports:
                    for lib in data:
                        if lib['name'].lower() == query.lower() and lib['status'] == "needs update":
                            print(f" {sbom_file.name} → Current version: {lib['current']} | Latest: {lib['latest']}")
                            found = True
                if not found:
                    print(f" No SBOMs with '{query}' needing an update.")
            else:
                print(f" Library '{query}' not recognized.")
        elif scelta == "2":
            nome_sbom = input(" Enter the SBOM file name (e.g., SBOM_FIRMWARE.json or TMB2.spdx): ").strip().lower()
            path_match = next((x[0] for x in reports if x[0].name.strip().lower() == nome_sbom), None)
            if path_match:
                report_for_sbom(path_match)
            else:
                print(f" File '{nome_sbom}' not found.")
        elif scelta == "3":
            print(" Exiting program.")
            sys.exit(0)
        else:
            print(" Invalid choice. Please try again.")

def main():
    print(f"\nFirmware Checker - by {Fore.LIGHTYELLOW_EX}Logika{Fore.LIGHTGREEN_EX}Control{Style.RESET_ALL} (v1.0)\n")
    print(f"\nUsing SBOM folder: {Fore.CYAN}{SBOM_DIR.resolve()}{Style.RESET_ALL}")

    if not SBOM_DIR.is_dir():
        print(f" Folder not found: {SBOM_DIR}")
        sys.exit(1)

    # Search for both CycloneDX (*.json) and SPDX tag-value (*.spdx)
    sbom_files = list(SBOM_DIR.glob("*.json")) + list(SBOM_DIR.glob("*.spdx"))
    if not sbom_files:
        print(" No .json or .spdx files found in SBOM_DIR.")
        sys.exit(1)

    reports = _build_reports(sbom_files)

    for sbom_file, _, _ in reports:
        report_for_sbom(sbom_file)

    _menu(reports)

if __name__ == "__main__":
    main()
