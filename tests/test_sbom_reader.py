import unittest
from pathlib import Path

from core.sbom_reader import carica_sbom_generico
from utils.paths import SBOM_DIR


class TestSbomReader(unittest.TestCase):
    def test_cyclonedx_json_components_are_parsed(self):
        cyclonedx_path = SBOM_DIR / "SBOM_FIRMWARE.json"
        components = carica_sbom_generico(cyclonedx_path)

        self.assertGreater(len(components), 0, "CycloneDX JSON should yield components")
        for component in components:
            self.assertIn("name", component)
            self.assertIn("version", component)
            self.assertTrue(component["name"], "Component name should not be empty")
            self.assertTrue(component["version"], "Component version should not be empty")

    def test_spdx_tag_value_components_are_normalized(self):
        spdx_path = SBOM_DIR / "TMB2.spdx"
        components = carica_sbom_generico(spdx_path)

        self.assertGreater(len(components), 0, "SPDX tag-value should yield components")
        normalized_names = {component["name"] for component in components}

        expected_names = {"FreeRTOS", "LwIP", "USB-HOST", "FAT-FS"}
        self.assertTrue(
            expected_names.issubset(normalized_names),
            f"Expected SPDX components {expected_names} to be parsed, got {normalized_names}",
        )
        for component in components:
            self.assertTrue(component["version"], "Component version should not be empty")


if __name__ == "__main__":
    unittest.main()
