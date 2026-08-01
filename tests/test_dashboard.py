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


class DashboardProgressStripTests(unittest.TestCase):
    def test_strip_markup_and_renderer_exist(self):
        html = dashboard_html()

        self.assertIn('id="progressStrip"', html)
        self.assertIn("function renderProgressStrip(", html)
        self.assertIn("async function refreshRunningProgress(", html)

    def test_strip_shows_the_counts_an_operator_watches(self):
        html = dashboard_html()

        self.assertIn('id="stripTarget"', html)
        self.assertIn('id="stripPercent"', html)
        self.assertIn('id="stripCounts"', html)
        self.assertIn('id="stripOpen"', html)
        self.assertIn('id="stripElapsed"', html)
        self.assertIn('id="stripStop"', html)
        self.assertIn('id="stripOpenScan"', html)

    def test_strip_reuses_the_scan_list_instead_of_a_new_endpoint(self):
        html = dashboard_html()

        # The backend contract is unchanged: no new routes were invented.
        for route in ("/v1/scans/running", "/v1/progress", "/v1/scans/active"):
            self.assertNotIn(route, html)


class DashboardPollingTests(unittest.TestCase):
    def test_poll_cadence_matches_the_three_documented_states(self):
        html = dashboard_html()

        self.assertIn("const POLL_ACTIVE_MS = 700;", html)
        self.assertIn("const POLL_HIDDEN_MS = 5000;", html)
        self.assertIn("function schedulePoll(", html)
        self.assertIn("document.hidden", html)

    def test_the_old_fixed_interval_is_gone(self):
        html = dashboard_html()

        # A weak machine must not keep polling with nothing running.
        self.assertNotIn("setInterval(", html)


class DashboardPresetTests(unittest.TestCase):
    def test_preset_storage_is_versioned_and_bounded(self):
        html = dashboard_html()

        self.assertIn("const SCAN_PRESET_STORAGE_KEY = 'netroach.scanPresets.v1';", html)
        self.assertIn("const SCAN_PRESET_MAX_COUNT = 12;", html)

    def test_three_builtin_presets_ship_with_the_dashboard(self):
        html = dashboard_html()

        self.assertIn("const BUILTIN_SCAN_PRESETS = [", html)
        for name in ("빠른 점검", "웹 포트", "전체 정밀"):
            self.assertIn(name, html)

    def test_authorization_is_never_part_of_a_preset(self):
        """A restored checkbox would silently defeat the authorization gate.

        The field list a preset serialises must not contain it, and applying a
        preset must actively clear it.
        """
        html = dashboard_html()

        fields = html.split("const PRESET_FIELDS = [", 1)[1].split("];", 1)[0]
        self.assertNotIn("confirm_authorized", fields)
        self.assertNotIn("authorized", fields)
        self.assertIn("function applyScanPreset(", html)
        self.assertIn("scanAuthorized').checked = false", html)

    def test_a_preset_fills_the_form_rather_than_starting_a_scan(self):
        html = dashboard_html()

        body = html.split("function applyScanPreset(", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("submit(", body)
        self.assertNotIn("startScan(", body)
        self.assertIn("select()", body)

    def test_preset_chips_and_management_controls_exist(self):
        html = dashboard_html()

        self.assertIn('id="scanPresetChips"', html)
        self.assertIn('id="scanPresetSave"', html)
        self.assertIn('id="scanPresetIncludeTargets"', html)
        self.assertIn("function renderScanPresets(", html)


class DashboardEstimateTests(unittest.TestCase):
    def test_estimate_helpers_exist(self):
        html = dashboard_html()

        self.assertIn("function estimateScanScale(", html)
        self.assertIn("function renderScanEstimate(", html)
        self.assertIn("function expandTargetCount(", html)
        self.assertIn('id="scanEstimate"', html)

    def test_estimate_runs_on_blur_not_only_on_submit(self):
        html = dashboard_html()

        self.assertRegex(html, r"scanTargets'\)\.addEventListener\('blur'")

    def test_a_bad_target_disables_the_start_button(self):
        html = dashboard_html()

        body = html.split("function renderScanEstimate(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("disabled", body)

    def test_update_scan_action_state_no_longer_sets_disabled_directly(self):
        """renderScanEstimate() is the sole owner of the button's disabled state.

        If updateScanActionState() also set scanSubmit.disabled, the two
        functions could race and re-enable a button that should stay locked.
        """
        html = dashboard_html()

        body = html.split("function updateScanActionState(", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("scanSubmit').disabled", body)
        self.assertIn("renderScanEstimate()", body)


class DashboardResultPaneTests(unittest.TestCase):
    def test_scan_screen_is_a_command_pane_and_a_result_pane(self):
        html = dashboard_html()

        self.assertIn('class="scan-shell"', html)
        self.assertIn('class="command-pane"', html)
        self.assertIn('class="result-pane"', html)

    def test_host_rows_are_grouped_and_open_hosts_come_first(self):
        html = dashboard_html()

        self.assertIn("function groupResultsByHost(", html)
        self.assertIn("function renderHostRows(", html)
        self.assertIn('id="scanHostRows"', html)
        body = html.split("function groupResultsByHost(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("sort(", body)

    def test_result_tabs_exist(self):
        html = dashboard_html()

        for tab in ("data-result-tab=\"hosts\"", "data-result-tab=\"ports\"", "data-result-tab=\"log\""):
            self.assertIn(tab, html)

    def test_scrolling_up_pins_the_list(self):
        html = dashboard_html()

        self.assertIn('id="scanNewResults"', html)
        self.assertIn("state.autoScroll", html)

    def test_offscreen_rows_are_not_rendered_for_large_scans(self):
        html = dashboard_html()

        self.assertIn("HOST_ROW_RENDER_LIMIT", html)

    def test_new_results_button_lives_inside_the_scroll_container(self):
        """position: sticky is inert unless the button is a descendant of the
        element that actually scrolls (#scanHostRows)."""
        html = dashboard_html()

        host_rows_open = html.index('<div class="host-rows" id="scanHostRows">')
        host_rows_close = html.index("</div>", html.index('id="scanHostRowsList"'))
        button_index = html.index('id="scanNewResults"')
        self.assertTrue(host_rows_open < button_index < host_rows_close)

    def test_new_results_button_shows_a_count(self):
        html = dashboard_html()

        self.assertIn("function updateNewResultsButton(", html)
        self.assertIn("state.newResultCount", html)
        body = html.split("function updateNewResultsButton(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("건", body)


class DashboardShortcutTests(unittest.TestCase):
    def test_shortcut_handler_and_help_overlay_exist(self):
        html = dashboard_html()

        self.assertIn("function handleShortcut(", html)
        self.assertIn("function isTypingTarget(", html)
        self.assertIn('id="shortcutHelp"', html)

    def test_every_documented_shortcut_is_handled(self):
        html = dashboard_html()
        body = html.split("function handleShortcut(", 1)[1].split("\n    }\n", 1)[0]

        for key in ("'t'", "'g'", "'?'", "'Escape'", "ctrlKey"):
            self.assertIn(key, body)

    def test_single_key_shortcuts_do_not_fire_while_typing(self):
        html = dashboard_html()
        body = html.split("function handleShortcut(", 1)[1].split("\n    }\n", 1)[0]

        self.assertIn("isTypingTarget(", body)

    def test_ctrl_enter_is_scoped_to_the_scan_view(self):
        """Ctrl+Enter must not submit the scan form from PCAP/packet/OAST
        views, where the form isn't even visible."""
        html = dashboard_html()
        body = html.split("function handleShortcut(", 1)[1].split("\n    }\n", 1)[0]
        ctrl_enter_block = body.split("event.ctrlKey && event.key === 'Enter'", 1)[1][:120]

        self.assertIn("state.view !== 'scans'", ctrl_enter_block)


class DashboardSelfContainmentTests(unittest.TestCase):
    def test_nothing_is_loaded_from_outside(self):
        """A strict desktop shell and an offline operator both need this."""
        html = dashboard_html()

        self.assertNotRegex(html, r'(?:src|href)\s*=\s*"https?://')
        self.assertNotIn("@import", html)
        self.assertNotIn("fonts.googleapis", html)

    def test_values_are_monospaced_and_motion_is_optional(self):
        html = dashboard_html()

        self.assertIn("ui-monospace", html)
        self.assertIn("@media (prefers-reduced-motion: reduce)", html)


if __name__ == "__main__":
    unittest.main()
