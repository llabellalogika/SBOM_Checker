import json
from pathlib import Path
from typing import List, Dict, Optional
import re
from core.constants import FIRMWARE_LIBRARIES

def _carica_cyclonedx_json(path: Path) -> List[Dict[str, str]]:
    """
    Extracts [{name, version}] from a CycloneDX JSON file.
    """
    try:
        data = json.load(path.open("r", encoding="utf-8"))
    except Exception:
        return []
    comps = data.get("components", [])
    out = []
    for c in comps:
        name = c.get("name")
        version = c.get("version")
        if name and version:
            out.append({"name": name, "version": version})
    return out

def _carica_spdx_tag_value(path: Path) -> List[Dict[str, str]]:
    """
    Minimal SPDX tag-value parser: pairs of PackageName / PackageVersion.
    Returns only packages mapped to the target libraries.
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

        "fatfs": "FatFs",
        "fat-fs": "FatFs",
        "component-fatfs": "FatFs",

        "cmsis-rtos": "CMSIS-RTOS",
        "cmsis": "CMSIS-RTOS",

        "mbedtls": "mbedTLS",
        "libjpeg": "LibJPEG",
        "openamp": "OpenAMP",
        "stemwin": "STemWin",
        "stm32_audio": "STM32_Audio",

        "usb-host": "STM32_USB_Host_Library",
        "usb": "STM32_USB_Host_Library",
        "component-usb": "STM32_USB_Host_Library",
        "stm32_usb_host_library": "STM32_USB_Host_Library",
        "stm32cube_usb_host": "STM32_USB_Host_Library",

        "usb-device": "STM32_USB_Device_Library",
        "stm32_usb_device_library": "STM32_USB_Device_Library",
        "stm32cube_usb_device": "STM32_USB_Device_Library",

        "touchgfx": "TouchGFX",
        "hal": "STM32H7xx_HAL_Driver",
        "stm32h7xx_hal_driver": "STM32H7xx_HAL_Driver",
    }

    def canonizza_nome(pkg_name: str) -> Optional[str]:
        s = pkg_name.strip().lower()
        if s in NAME_MAP:
            return NAME_MAP[s]
        # heuristic fallback
        if "freertos" in s: return "FreeRTOS"
        if "lwip" in s: return "LwIP"
        if "fatfs" in s or "fat-fs" in s: return "FatFs"
        if "cmsis" in s: return "CMSIS-RTOS"
        if "mbedtls" in s: return "mbedTLS"
        if "openamp" in s: return "OpenAMP"
        if "libjpeg" in s: return "LibJPEG"
        if "stm32h7" in s or "hal" in s: return "STM32H7xx_HAL_Driver"
        if "usb" in s and "host" in s: return "STM32_USB_Host_Library"
        if "usb" in s and "device" in s: return "STM32_USB_Device_Library"
        if "touchgfx" in s: return "TouchGFX"
        if "stemwin" in s: return "STemWin"
        if "audio" in s and "stm32" in s: return "STM32_Audio"
        return None

    components = []
    current_name = None
    current_version = None

    def flush():
        nonlocal current_name, current_version
        if current_name and current_version:
            canon = canonizza_nome(current_name)
            if canon in FIRMWARE_LIBRARIES:
                components.append({"name": canon, "version": current_version})
        current_name, current_version = None, None

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
            flush()
    except Exception:
        return []

    # Deduplicate by name
    dedup = {}
    for c in components:
        if c["name"] not in dedup:
            dedup[c["name"]] = c["version"]
    return [{"name": k, "version": v} for k, v in dedup.items()]

def carica_sbom_generico(path: Path) -> List[Dict[str, str]]:
    """
    Supports CycloneDX JSON (*.json) and SPDX tag-value (*.spdx).
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
            out.append({"name": name, "version": version})
    return out
