import tempfile
import unittest
from pathlib import Path

from netroach.config import NetroachConfig, load_config, resolve_scan_options


class ConfigTests(unittest.TestCase):
    def test_loads_scan_defaults_custom_profiles_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.toml"
            path.write_text(
                """
[scan]
timeout_ms = 900
exclude = ["10.0.0.5/32"]

[port_profiles]
app = [8080, 8443]

[environments.corp.scan]
scope = ["10.0.0.0/8"]
concurrency = 20
rate_limit_per_sec = 30
port_profile = "app"
""",
                encoding="utf-8",
            )

            config = load_config(path)
            options = resolve_scan_options(config=config, env="corp", values={}, explicit_fields=set())

        self.assertEqual(config.port_profiles["app"], (8080, 8443))
        self.assertEqual(options["timeout_ms"], 900)
        self.assertEqual(options["concurrency"], 20)
        self.assertEqual(options["rate_limit_per_sec"], 30)
        self.assertEqual(options["exclude"], ("10.0.0.5/32",))
        self.assertEqual(options["scope"], ("10.0.0.0/8",))
        self.assertEqual(options["port_profile"], "app")

    def test_explicit_port_source_overrides_config_port_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.toml"
            path.write_text(
                """
[scan]
top_ports = 20
port_profile = "web"
""",
                encoding="utf-8",
            )

            config = load_config(path)
            options = resolve_scan_options(
                config=config,
                env=None,
                values={"ports": "22"},
                explicit_fields={"ports"},
            )

        self.assertEqual(options["ports"], "22")
        self.assertIsNone(options["port_profile"])
        self.assertIsNone(options["top_ports"])

    def test_builtin_local_environment_supplies_safe_loopback_defaults(self):
        options = resolve_scan_options(config=NetroachConfig(), env="local", values={}, explicit_fields=set())

        self.assertIn("127.0.0.0/8", options["scope"])
        self.assertEqual(options["timeout_ms"], 300)
        self.assertEqual(options["top_ports"], 20)

    def test_config_loads_plugin_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.toml"
            path.write_text(
                """
[plugins]
paths = ["plugins/lab.json"]
""",
                encoding="utf-8",
            )

            config = load_config(path)

        self.assertEqual(config.plugin_paths, ("plugins/lab.json",))

    def test_scan_resource_limits_reject_unsafe_values(self):
        with self.assertRaisesRegex(ValueError, "concurrency"):
            resolve_scan_options(
                config=NetroachConfig(),
                env=None,
                values={"concurrency": 5000},
                explicit_fields={"concurrency"},
            )


if __name__ == "__main__":
    unittest.main()
