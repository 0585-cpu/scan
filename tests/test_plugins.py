import json
import tempfile
import unittest
from pathlib import Path

from netprobe.plugins import load_plugin_manifest, load_plugins, parse_plugin_manifest


class PluginTests(unittest.TestCase):
    def test_loads_plugin_manifest_and_builds_runtime_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lab.json"
            path.write_text(json.dumps(plugin_manifest()), encoding="utf-8")

            catalog = load_plugins([path])

        self.assertEqual(catalog.plugins[0].name, "lab-services")
        self.assertEqual(catalog.port_profiles["lab-app"], (18080, 18443))
        runtime = catalog.runtime_catalog_dict()
        self.assertEqual(runtime["schema_version"], 1)
        self.assertEqual(runtime["tcp_services"]["18080"], "custom-http")
        self.assertEqual(runtime["udp_services"]["1812"], "radius")
        self.assertEqual(runtime["tcp_banner_rules"][0]["contains"], list(b"X-Custom-App"))
        self.assertEqual(runtime["udp_response_rules"][0]["starts_with_hex"], [2])

    def test_last_manifest_wins_for_maps_and_rule_order_is_preserved(self):
        first = plugin_manifest()
        second = plugin_manifest()
        second["name"] = "override"
        second["tcp_services"] = {"18080": "override-http"}
        second["tcp_banner_rules"][0]["service"] = "override-rule"
        with tempfile.TemporaryDirectory() as tmp:
            first_path = Path(tmp) / "01-first.json"
            second_path = Path(tmp) / "02-second.json"
            first_path.write_text(json.dumps(first), encoding="utf-8")
            second_path.write_text(json.dumps(second), encoding="utf-8")
            catalog = load_plugins([first_path, second_path])

        self.assertEqual(catalog.tcp_services[18080], "override-http")
        self.assertEqual(
            [rule.service for rule in catalog.tcp_banner_rules],
            ["custom-app", "override-rule"],
        )

    def test_plugin_validation_rejects_unbounded_or_invalid_rules(self):
        data = plugin_manifest()
        data["tcp_banner_rules"][0].pop("contains")
        with self.assertRaisesRegex(ValueError, "requires at least one match field"):
            parse_plugin_manifest(data)

        data = plugin_manifest()
        data["udp_response_rules"][0]["confidence"] = 1.5
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            parse_plugin_manifest(data)

        data = plugin_manifest()
        data["tcp_services"] = {"80-81": "bad"}
        with self.assertRaisesRegex(ValueError, "single port"):
            parse_plugin_manifest(data)

    def test_validate_one_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lab.json"
            path.write_text(json.dumps(plugin_manifest()), encoding="utf-8")

            manifest = load_plugin_manifest(path)

        self.assertEqual(manifest.name, "lab-services")
        self.assertEqual(len(manifest.tcp_banner_rules), 1)


def plugin_manifest() -> dict[str, object]:
    return {
        "name": "lab-services",
        "version": "1.0.0",
        "description": "Lab-owned service names and fingerprint rules.",
        "port_profiles": {
            "lab-app": [18080, 18443],
        },
        "tcp_services": {
            "18080": "custom-http",
        },
        "udp_services": {
            "1812": "radius",
        },
        "tcp_banner_rules": [
            {
                "service": "custom-app",
                "ports": [18080],
                "contains": "X-Custom-App",
                "confidence": 0.93,
            }
        ],
        "udp_response_rules": [
            {
                "service": "radius",
                "ports": [1812],
                "starts_with_hex": "02",
                "confidence": 0.88,
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
