import os

# Librerie firmware target
FIRMWARE_LIBRARIES = {
    "FreeRTOS", "HAL", "TouchGFX", "USB-HOST", "FAT-FS", "CMSIS-RTOS", "LwIP"
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
