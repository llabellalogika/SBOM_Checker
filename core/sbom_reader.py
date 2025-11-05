import json
from pathlib import Path
from typing import List, Dict, Optional
from core.constants import FIRMWARE_LIBRARIES
import re

def _carica_cyclonedx_json(path: Path) -> List[Dict[str, str]]:
    """
    Estrae [{name, version}] da CycloneDX JSON.
    """
    try:
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
    except Exception:
        return []
    comps = data.get("components", [])
    out = []
    for c in comps:
        name = c.get("name")
        version = c.get("version")
        if name and version:
            entry = {"name": name, "version": version}
            purl = c.get("purl")
            if purl:
                entry["purl"] = purl
            refs = []
            for ref in c.get("externalReferences", []) or []:
                url = ref.get("url")
                if url:
                    refs.append(url)
            if refs:
                entry["references"] = refs
            out.append(entry)
    return out

def _carica_spdx_tag_value(path: Path) -> List[Dict[str, str]]:
    """
    Parser minimale SPDX tag-value: coppie PackageName / PackageVersion.
    Ritorna solo i package mappati nelle librerie target.
    """
    NAME_MAP = {
        "freertos": "FreeRTOS",
        "freertos kernel": "FreeRTOS",
        "component-freertos": "FreeRTOS",
        "freertos-freertos-kernel": "FreeRTOS",
        "rt": "FreeRTOS",

        "lwip": "LwIP",
        "component-lwip": "LwIP",
        "lwip-lwip": "LwIP",

        "fatfs": "FAT-FS",
        "component-fatfs": "FAT-FS",

        "cmsis-rtos": "CMSIS-RTOS",
        "cmsis": "CMSIS-RTOS",

        "usb-host": "USB-HOST",
        "usb": "USB-HOST",
        "component-usb": "USB-HOST",
        "stm32_usb_host_library": "USB-HOST",
        "stm32cube_usb_host": "USB-HOST",

        "touchgfx": "TouchGFX",
    }

    def canonizza_nome(pkg_name: str) -> Optional[str]:
        s = pkg_name.strip().lower()
        if s in NAME_MAP:
            return NAME_MAP[s]
        # fallback euristico
        if "freertos" in s: return "FreeRTOS"
        if "lwip" in s: return "LwIP"
        if "fatfs" in s or "fat-fs" in s: return "FAT-FS"
        if "cmsis" in s: return "CMSIS-RTOS"
        if "usb" in s and "host" in s: return "USB-HOST"
        if "touchgfx" in s: return "TouchGFX"
        return None

    components = []
    current_name = None
    current_version = None
    current_purl = None
    current_refs = []

    def flush():
        nonlocal current_name, current_version, current_purl, current_refs
        if current_name and current_version:
            canon = canonizza_nome(current_name)
            if canon in FIRMWARE_LIBRARIES:
                entry = {"name": canon, "version": current_version}
                if current_purl:
                    entry["purl"] = current_purl
                if current_refs:
                    entry["references"] = current_refs.copy()
                components.append(entry)
        current_name, current_version, current_purl, current_refs = None, None, None, []

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("PackageName:"):
                    flush()
                    current_name = line.split("PackageName:", 1)[1].strip()
                    continue
                if line.startswith("PackageVersion:"):
                    current_version = line.split("PackageVersion:", 1)[1].strip()
                    continue
                if line.startswith("PackageDownloadLocation:") or line.startswith("PackageHomePage:"):
                    loc = line.split(":", 1)[1].strip()
                    if loc and loc not in {"NONE", "NOASSERTION"}:
                        current_refs.append(loc)
                    continue
                if line.startswith("ExternalRef:"):
                    try:
                        _, category, ref_type, locator = re.split(r"\s+", line, maxsplit=3)
                    except ValueError:
                        parts = line.split()
                        if len(parts) >= 4:
                            category, ref_type = parts[1], parts[2]
                            locator = " ".join(parts[3:])
                        else:
                            continue
                    locator = locator.strip()
                    if category == "PACKAGE-MANAGER" and ref_type.lower() == "purl":
                        current_purl = locator
                    elif locator and locator not in {"NONE", "NOASSERTION"}:
                        current_refs.append(locator)
                    continue
            flush()
    except Exception:
        return []

    # Deduplica per nome mantenendo la prima occorrenza con metadati
    dedup = {}
    for c in components:
        if c["name"] not in dedup:
            dedup[c["name"]] = c
    return list(dedup.values())

def carica_sbom_generico(path: Path) -> List[Dict[str, str]]:
    """
    Supporta CycloneDX JSON (*.json) e SPDX tag-value (*.spdx).
    """
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _carica_cyclonedx_json(path)
    if suffix == ".spdx":
        return _carica_spdx_tag_value(path)
    # auto-detect
    data = _carica_cyclonedx_json(path)
    return data if data else _carica_spdx_tag_value(path)

def estrai_librerie(componenti: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out = []
    for c in componenti:
        name = c.get("name")
        version = c.get("version")
        if name in FIRMWARE_LIBRARIES and version:
            entry = {"name": name, "version": version}
            if "purl" in c:
                entry["purl"] = c["purl"]
            if "references" in c:
                entry["references"] = c["references"]
            out.append(entry)
    return out
