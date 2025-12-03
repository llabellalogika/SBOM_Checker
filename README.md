# SBOM_Checker

Strumento per analizzare SBOM in formato CycloneDX JSON o SPDX tag-value e verificare se le librerie firmware risultano aggiornate o richiedono update di sicurezza.

## CLI

Esegui la versione a riga di comando con:

```bash
python main.py
```

I file SBOM vengono letti da `data/sbom` e viene mostrato il report testuale già presente nel progetto.

## GUI

È disponibile una piccola interfaccia grafica desktop (Tkinter) per generare lo stesso report senza usare il terminale:

```bash
python gui.py
```

La finestra permette di selezionare un file SBOM dal proprio PC (`.json` o `.spdx`) e mostra:

- la tabella con le versioni corrente/ultima e lo stato di sicurezza,
- il conteggio delle librerie che richiedono aggiornamenti,
- le release note di sicurezza quando presenti.
