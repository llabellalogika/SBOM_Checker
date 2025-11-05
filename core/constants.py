import os

# Librerie firmware target
FIRMWARE_LIBRARIES = {
    "FreeRTOS", "HAL", "TouchGFX", "USB-HOST", "FAT-FS", "CMSIS-RTOS", "LwIP"
}

# Mapping dei package per interrogazioni OSV
OSV_PACKAGE_MAP = {
    "FreeRTOS": {"ecosystem": "GitHub", "name": "FreeRTOS/FreeRTOS-Kernel"},
    "CMSIS-RTOS": {"ecosystem": "GitHub", "name": "ARM-software/CMSIS_5"},
    "HAL": {"ecosystem": "GitHub", "name": "STMicroelectronics/STM32CubeF4"},
    "USB-HOST": {"ecosystem": "GitHub", "name": "STMicroelectronics/STM32_USB_Host_Library"},
    "TouchGFX": {"ecosystem": "GitHub", "name": "STMicroelectronics/TouchGFX"},
    "FAT-FS": {"ecosystem": "GitHub", "name": "elm-chan/ff"},
    "LwIP": {"ecosystem": "Git", "name": "https://git.savannah.nongnu.org/git/lwip.git"},
}

# Mapping repository GitHub per “latest”
GITHUB_REPOS = {
    "FreeRTOS": ("FreeRTOS", "FreeRTOS-Kernel"),
    "CMSIS-RTOS": ("ARM-software", "CMSIS_5"),
    "HAL": ("STMicroelectronics", "STM32CubeF4"),
    "USB-HOST": ("STMicroelectronics", "STM32_USB_Host_Library"),
}

# Token GitHub: variabile d’ambiente consigliata
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip() or None
