import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.build_desktop import (
    backend_output_path,
    cargo_build_command,
    cargo_metadata_command,
    clear_private_engine_artifacts,
    engine_build_environment,
    executable_name,
    playwright_install_command,
    playwright_smoke_command,
    pyinstaller_command,
    stage_npcap_installer,
    standard_engine_build_args,
    unstage_npcap_installer,
    validate_personal_npcap_build,
    verify_npcap_installer_signature,
    windows_runtime_architecture,
    write_windows_installer_checksums,
)


class DesktopBuildToolTests(unittest.TestCase):
    def test_executable_name_is_platform_specific(self):
        self.assertEqual(executable_name("netroach-engine", system="Windows"), "netroach-engine.exe")
        self.assertEqual(executable_name("netroach-engine", system="Linux"), "netroach-engine")

    def test_cargo_command_supports_profile_toolchain_and_target(self):
        args = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain="stable",
            cargo_target="x86_64-pc-windows-msvc",
            engine_profile="portable",
        )

        self.assertEqual(
            cargo_build_command(args),
            [
                "cargo",
                "+stable",
                "build",
                "-p",
                "netroach-engine",
                "--profile",
                "portable",
                "--target",
                "x86_64-pc-windows-msvc",
            ],
        )

    def test_syn_build_enables_feature_and_prepends_npcap_sdk_library(self):
        sdk = Path(tempfile.gettempdir()).resolve() / "npcap-sdk" / "Lib" / "x64"
        existing = str(Path(tempfile.gettempdir()).resolve() / "existing")
        args = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain=None,
            cargo_target=None,
            engine_profile="release",
            syn_sweep=True,
            npcap_sdk_lib=sdk,
        )

        self.assertEqual(cargo_build_command(args)[-2:], ["--features", "syn-sweep"])
        environment = engine_build_environment(args, {"LIB": existing})
        self.assertEqual(environment["LIB"], f"{sdk}{os.pathsep}{existing}")

    def test_personal_npcap_build_requires_paired_inputs_and_nsis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = root / "Lib" / "x64"
            sdk.mkdir(parents=True)
            (sdk / "wpcap.lib").write_bytes(b"library")
            (sdk / "Packet.lib").write_bytes(b"library")
            installer = root / "npcap.exe"
            installer.write_bytes(b"abc")

            for missing_sdk, missing_installer in ((None, installer), (sdk, None)):
                with self.subTest(sdk=missing_sdk, installer=missing_installer):
                    args = argparse.Namespace(
                        syn_sweep=True,
                        npcap_sdk_lib=missing_sdk,
                        npcap_installer=missing_installer,
                        bundles="nsis",
                    )
                    with self.assertRaises(SystemExit):
                        validate_personal_npcap_build(args, system="Windows")

            args = argparse.Namespace(
                syn_sweep=True,
                npcap_sdk_lib=sdk,
                npcap_installer=installer,
                bundles="msi",
            )
            with self.assertRaisesRegex(SystemExit, "NSIS"):
                validate_personal_npcap_build(args, system="Windows")

            args = argparse.Namespace(
                syn_sweep=True,
                npcap_sdk_lib=sdk,
                npcap_installer=installer,
                bundles="nsis",
                skip_engine_build=True,
                engine_path=None,
            )
            with self.assertRaisesRegex(SystemExit, "fresh engine build"):
                validate_personal_npcap_build(args, system="Windows")

            args = argparse.Namespace(
                syn_sweep=True,
                npcap_sdk_lib=sdk,
                npcap_installer=installer,
                bundles="nsis",
                skip_engine_build=False,
                engine_path=None,
                prepare_only=True,
            )
            with self.assertRaisesRegex(SystemExit, "prepare-only"):
                validate_personal_npcap_build(args, system="Windows")

    def test_npcap_installer_staging_reports_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "npcap.exe"
            destination = Path(tmp) / "staged" / "npcap-installer.exe"
            source.write_bytes(b"abc")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                digest = stage_npcap_installer(source, destination=destination)

            self.assertEqual(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertEqual(destination.read_bytes(), b"abc")
            self.assertIn(digest, stdout.getvalue())

            self.assertTrue(unstage_npcap_installer(destination=destination))
            self.assertFalse(destination.exists())
            self.assertFalse(unstage_npcap_installer(destination=destination))

    def test_npcap_installer_requires_a_valid_nmap_authenticode_signature(self):
        valid = SimpleNamespace(
            stdout=(
                '{"Status":"Valid","Subject":"CN=Nmap Software LLC, O=Nmap Software LLC",'
                '"Publisher":"Nmap Software LLC"}'
            )
        )
        invalid = SimpleNamespace(stdout='{"Status":"NotSigned","Subject":null,"Publisher":null}')
        deceptive = SimpleNamespace(
            stdout=(
                '{"Status":"Valid","Subject":"CN=Untrusted Publisher, OU=Nmap Software LLC",'
                '"Publisher":"Untrusted Publisher"}'
            )
        )

        with (
            patch("tools.build_desktop.shutil.which", return_value="powershell.exe"),
            patch("tools.build_desktop.subprocess.run", return_value=valid),
        ):
            verify_npcap_installer_signature(Path("npcap.exe"))

        with (
            patch("tools.build_desktop.shutil.which", return_value="powershell.exe"),
            patch("tools.build_desktop.subprocess.run", return_value=invalid),
            self.assertRaisesRegex(SystemExit, "Authenticode"),
        ):
            verify_npcap_installer_signature(Path("npcap.exe"))

        with (
            patch("tools.build_desktop.shutil.which", return_value="powershell.exe"),
            patch("tools.build_desktop.subprocess.run", return_value=deceptive),
            self.assertRaisesRegex(SystemExit, "Authenticode"),
        ):
            verify_npcap_installer_signature(Path("npcap.exe"))

    def test_private_build_restores_a_standard_engine_configuration(self):
        private = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain=None,
            cargo_target=None,
            engine_profile="release",
            syn_sweep=True,
            npcap_sdk_lib=Path(r"C:\npcap-sdk\Lib\x64"),
            npcap_installer=Path("npcap.exe"),
            skip_engine_build=False,
            engine_path=None,
        )

        standard = standard_engine_build_args(private)

        self.assertNotIn("--features", cargo_build_command(standard))
        self.assertNotIn("LIB", engine_build_environment(standard, {}))
        self.assertFalse(standard.syn_sweep)
        self.assertIsNone(standard.npcap_installer)

    def test_private_engine_artifacts_are_removed_before_standard_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = root / "resources" / "netroach-engine.exe"
            output = root / "target" / "netroach-engine.exe"
            staged.parent.mkdir(parents=True)
            output.parent.mkdir(parents=True)
            staged.write_bytes(b"feature engine")
            output.write_bytes(b"feature engine")

            removed = clear_private_engine_artifacts(
                argparse.Namespace(engine_profile="release", cargo_target=None),
                staged_engine=staged,
                engine_output=output,
            )

            self.assertEqual(removed, [staged, output])
            self.assertFalse(staged.exists())
            self.assertFalse(output.exists())

    def test_windows_installer_checksum_sidecars_are_refreshed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)
            installer = bundle / "nsis" / "Netroach-setup.exe"
            installer.parent.mkdir(parents=True)
            installer.write_bytes(b"new installer")
            sidecar = installer.with_suffix(installer.suffix + ".sha256")
            sidecar.write_text("stale", encoding="utf-8")

            written = write_windows_installer_checksums(bundle)

            expected = "8c2c3f289557cbc430c7b0b40c01a0a0b535fa68c1abdff3cecf6d2d8eb5a7d2"
            self.assertEqual(written, [sidecar])
            self.assertEqual(sidecar.read_text(encoding="utf-8"), f"{expected}  {installer.name}\n")

    def test_pyinstaller_command_builds_one_file_backend(self):
        command = pyinstaller_command("python")

        self.assertEqual(command[:3], ["python", "-m", "PyInstaller"])
        self.assertIn("--onefile", command)
        self.assertIn("uvicorn", command)
        self.assertIn("scapy", command)
        self.assertIn("playwright", command)
        self.assertEqual(Path(command[-1]).name, "frozen_backend.py")
        self.assertTrue(backend_output_path().name.startswith("netroach-backend"))

    def test_cargo_metadata_command_uses_desktop_manifest(self):
        args = argparse.Namespace(
            cargo="cargo",
            cargo_toolchain="stable",
        )

        command = cargo_metadata_command(args)

        self.assertEqual(command[0:2], ["cargo", "+stable"])
        self.assertIn("metadata", command)
        self.assertIn("--manifest-path", command)
        self.assertEqual(command[-2:], ["--format-version", "1"])

    def test_windows_runtime_architecture_supports_rust_targets(self):
        self.assertEqual(windows_runtime_architecture("x86_64-pc-windows-gnu"), "x64")
        self.assertEqual(windows_runtime_architecture("aarch64-pc-windows-msvc"), "arm64")
        self.assertEqual(windows_runtime_architecture("i686-pc-windows-msvc"), "x86")

    def test_playwright_install_downloads_only_headless_chromium(self):
        self.assertEqual(
            playwright_install_command("python"),
            ["python", "-m", "playwright", "install", "--only-shell", "chromium"],
        )

    def test_playwright_smoke_launches_headless_chromium(self):
        command = playwright_smoke_command("python")

        self.assertEqual(command[:2], ["python", "-c"])
        self.assertIn("chromium.launch(headless=True)", command[2])


class BrowserPruningTests(unittest.TestCase):
    """Playwright's own GC is disabled for this cache, so the build prunes it.

    Two Chromium revisions once shipped side by side in one installer: 270MB on
    disk and about 80MB in the bundle, for a copy nothing could use.
    """

    def _tree(self, tmp, *names):
        root = Path(tmp) / "browsers"
        for name in names:
            (root / name).mkdir(parents=True)
        return root

    def test_superseded_revisions_are_removed(self):
        import tempfile

        from tools.build_desktop import prune_stale_browser_revisions

        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "chromium_headless_shell-1228", "chromium_headless_shell-1234", "ffmpeg-1011")

            removed = prune_stale_browser_revisions(root, keep={"chromium_headless_shell-1234"})

            self.assertEqual(removed, ["chromium_headless_shell-1228"])
            self.assertTrue((root / "chromium_headless_shell-1234").is_dir())
            # Only browser directories are considered; the helper tools stay.
            self.assertTrue((root / "ffmpeg-1011").is_dir())

    def test_the_newest_revision_of_each_family_is_kept(self):
        """The revision in use must never be the one deleted.

        Asking Playwright which one it uses returned a `chromium-<rev>` path that
        does not exist on disk when only the headless shell is installed, so the
        real `chromium_headless_shell-<rev>` directory looked stale and the build
        deleted the browser it had just installed.
        """
        import tempfile

        from tools.build_desktop import newest_browser_revisions, prune_stale_browser_revisions

        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(
                tmp,
                "chromium_headless_shell-1228",
                "chromium_headless_shell-1234",
                "chromium-1200",
                "ffmpeg-1011",
            )

            keep = newest_browser_revisions(root)
            removed = prune_stale_browser_revisions(root, keep=keep)

            self.assertEqual(keep, {"chromium_headless_shell-1234", "chromium-1200"})
            self.assertEqual(removed, ["chromium_headless_shell-1228"])
            # Each family keeps its own newest, so the two prefixes cannot delete
            # each other, and non-browser tools are never considered.
            self.assertTrue((root / "chromium-1200").is_dir())
            self.assertTrue((root / "ffmpeg-1011").is_dir())

    def test_a_lone_revision_is_never_deleted(self):
        import tempfile

        from tools.build_desktop import newest_browser_revisions, prune_stale_browser_revisions

        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "chromium_headless_shell-1234")

            removed = prune_stale_browser_revisions(root, keep=newest_browser_revisions(root))

            self.assertEqual(removed, [])
            self.assertTrue((root / "chromium_headless_shell-1234").is_dir())

    def test_nothing_is_removed_when_the_kept_revision_is_unknown(self):
        import tempfile

        from tools.build_desktop import prune_stale_browser_revisions

        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "chromium_headless_shell-1228", "chromium_headless_shell-1234")

            removed = prune_stale_browser_revisions(root, keep=set())

            # An empty keep set means "we could not tell" - deleting the revision
            # in use would break evidence capture, which costs more than 80MB.
            self.assertEqual(removed, [])
            self.assertTrue((root / "chromium_headless_shell-1228").is_dir())
            self.assertTrue((root / "chromium_headless_shell-1234").is_dir())


if __name__ == "__main__":
    unittest.main()
