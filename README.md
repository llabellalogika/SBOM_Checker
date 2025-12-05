# SBOM_Checker

Tool to analyze SBOMs in CycloneDX JSON or SPDX tag-value format and verify whether firmware libraries are up to date or require security updates.

## CLI

Run the command-line version with:

```bash
python main.py
```

SBOM files are read from `data/sbom` and the existing text report is displayed.

## GUI

A small desktop GUI (Tkinter) is available to generate the same report without using the terminal:

```bash
python gui.py
```

The window lets you pick an SBOM file from your computer (`.json` or `.spdx`) and shows:

- the table with current/latest versions and the security status,
- the count of libraries that require updates,
- any available security release notes.
