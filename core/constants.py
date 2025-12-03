import os

# Librerie firmware target
FIRMWARE_LIBRARIES = {
    "FreeRTOS",
    "HAL",
    "TouchGFX",
    "USB-HOST",
    "FAT-FS",
    "CMSIS-RTOS",
    "LwIP",
}

# Mapping repository GitHub per “latest”
GITHUB_REPOS = {
    "FreeRTOS": ("FreeRTOS", "FreeRTOS-Kernel"),
    "CMSIS-RTOS": ("ARM-software", "CMSIS_5"),
    "HAL": ("STMicroelectronics", "STM32CubeF4"),
    "USB-HOST": ("STMicroelectronics", "STM32_USB_Host_Library"),
}

# Riferimenti noti per l'interrogazione dell'API OSV.
# Preferiamo purl quando disponibile e usiamo l'ecosistema GitHub come fallback.
OSV_PACKAGE_REFERENCES = {
    "FreeRTOS": {
        "purl": "pkg:github/FreeRTOS/FreeRTOS-Kernel",
        "ecosystem": "GitHub",
        "name": "FreeRTOS/FreeRTOS-Kernel",
    },
    "CMSIS-RTOS": {
        "purl": "pkg:github/ARM-software/CMSIS_5",
        "ecosystem": "GitHub",
        "name": "ARM-software/CMSIS_5",
    },
    "HAL": {
        "purl": "pkg:github/STMicroelectronics/STM32CubeF4",
        "ecosystem": "GitHub",
        "name": "STMicroelectronics/STM32CubeF4",
    },
    "USB-HOST": {
        "purl": "pkg:github/STMicroelectronics/STM32_USB_Host_Library",
        "ecosystem": "GitHub",
        "name": "STMicroelectronics/STM32_USB_Host_Library",
    },
    "TouchGFX": {
        "purl": "pkg:github/STMicroelectronics/touchgfx",
        "ecosystem": "GitHub",
        "name": "STMicroelectronics/touchgfx",
    },
    "LwIP": {
        "purl": "pkg:github/lwip-tcpip/lwip",
        "ecosystem": "GitHub",
        "name": "lwip-tcpip/lwip",
    },
    "FAT-FS": {
        "purl": "pkg:github/abbrev/fatfs",
        "ecosystem": "GitHub",
        "name": "abbrev/fatfs",
    },
}

# Token GitHub: variabile d’ambiente consigliata
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip() or None
