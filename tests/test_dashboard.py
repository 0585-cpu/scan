import unittest

from netroach.dashboard import DASHBOARD_FILE, dashboard_html


class DashboardAssetTests(unittest.TestCase):
    def test_dashboard_file_is_served(self):
        self.assertTrue(DASHBOARD_FILE.is_file())
        self.assertEqual(dashboard_html(), DASHBOARD_FILE.read_text(encoding="utf-8"))

    def test_no_action_opens_a_new_window(self):
        """The desktop shell is a webview that drops new-window navigation.

        Reports, evidence images, and exports must therefore stay in the page;
        a `target="_blank"` link is silently dead once packaged.
        """
        html = dashboard_html()

        self.assertNotIn('target="_blank"', html)
        self.assertNotIn("window.open(", html)

    def test_in_page_viewer_and_download_helpers_are_wired(self):
        html = dashboard_html()

        for symbol in (
            "function viewDocument(",
            "function viewImage(",
            "async function previewExport(",
            "async function downloadFile(",
        ):
            self.assertIn(symbol, html)
        self.assertIn('id="viewer"', html)
        self.assertIn("data-evidence-view", html)
        # Every export opens the in-page preview, which offers the file itself.
        for link_id in ("scanExportJson", "scanExportCsv", "scanExportXlsx"):
            self.assertRegex(html, rf"{link_id}: exportPreview\(")
        self.assertRegex(html, r"scanReportLink: \(link\) => viewDocument\(")
        self.assertIn('id="viewerSave"', html)


class DashboardVisualLanguageTests(unittest.TestCase):
    def test_accent_is_the_new_teal_and_the_old_blue_is_gone(self):
        html = dashboard_html()

        self.assertIn("--accent: #0f766e;", html)
        self.assertIn("--bg: #f7f8f7;", html)
        self.assertNotIn("#1b6ec2", html)
        self.assertNotIn("#14589e", html)

    def test_state_colours_are_declared_once_as_tokens(self):
        html = dashboard_html()

        for token in ("--state-open:", "--state-filtered:", "--state-closed:", "--state-error:"):
            self.assertIn(token, html)

    def test_corners_are_uniform(self):
        html = dashboard_html()

        self.assertIn("--radius: 4px;", html)
        self.assertIn("--radius-sm: 4px;", html)

    def test_navigation_is_an_icon_rail(self):
        html = dashboard_html()

        self.assertIn('class="rail"', html)
        self.assertNotIn('class="sidebar"', html)
        # Labels stay in the markup for screen readers and hover.
        self.assertIn('data-rail-icon', html)
        self.assertIn('data-view-target="scans"', html)


if __name__ == "__main__":
    unittest.main()
