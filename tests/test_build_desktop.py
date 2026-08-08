import argparse
import unittest
from pathlib import Path

from tools.build_desktop import (
    backend_output_path,
    cargo_build_command,
    cargo_metadata_command,
    executable_name,
    playwright_install_command,
    playwright_smoke_command,
    pyinstaller_command,
    windows_runtime_architecture,
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
