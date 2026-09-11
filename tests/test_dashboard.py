import re
import unittest
from pathlib import Path

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

    def test_quick_check_preset_means_top_100_ports_not_1_1024(self):
        """Design spec section 2: '빠른 점검' is 상위 100포트 (top-ports), not a
        1-1024 port expression - those aren't the same 100 ports."""
        html = dashboard_html()

        presets_block = html.split("const BUILTIN_SCAN_PRESETS = [", 1)[1].split("];", 1)[0]
        quick_preset = presets_block.split("builtin-quick", 1)[1].split("},", 1)[0]
        self.assertIn("top_ports: 100", quick_preset)
        self.assertNotIn("1-1024", quick_preset)

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

    def test_tcp_uses_syn_by_default_and_connect_only_is_explicit(self):
        html = dashboard_html()

        self.assertIn('id="scanConnectOnly" name="tcp_connect_only" type="checkbox"', html)
        self.assertIn('id="scanSynRetries" name="syn_retries"', html)
        self.assertIn("function updateTcpScanAvailability(", html)
        self.assertIn(
            "syn_sweep: tcp && synSweepAvailable() && form.get('tcp_connect_only') !== 'on'",
            html,
        )
        self.assertIn("syn_retries: Number(form.get('syn_retries')", html)

    def test_syn_is_only_offered_where_the_engine_was_built_for_it(self):
        # A build without the feature rejects --syn-sweep outright, so asking for
        # it fails every TCP scan the dashboard starts. The capability decides,
        # and it is read at submit so a preset cannot turn SYN back on.
        html = dashboard_html()

        self.assertIn("function synSweepAvailable(", html)
        self.assertIn("state.health?.diagnostics?.syn_sweep_available", html)
        self.assertIn("if (tcp && !syn) $('scanConnectOnly').checked = true;", html)
        self.assertIn("$('scanConnectOnly').disabled = !tcp || !syn;", html)
        submit = html.split("syn_sweep:", 1)[1].split("\n", 1)[0]
        self.assertIn("synSweepAvailable()", submit)

    def test_tcp_service_detection_enables_analysis_and_both_evidence_paths(self):
        html = dashboard_html()
        scan_form = html.split('id="scanForm"', 1)[1].split("</form>", 1)[0]

        self.assertIn('name="service_probe" type="checkbox" checked', scan_form)
        self.assertNotIn('name="capture_screenshots"', scan_form)
        self.assertNotIn('name="capture_console"', scan_form)
        self.assertIn("const tcpServiceProbe = tcp && form.get('service_probe') === 'on';", html)
        self.assertIn("service_probe: tcp ? tcpServiceProbe", html)
        self.assertIn("capture_screenshots: tcpServiceProbe", html)
        self.assertIn("capture_console: tcpServiceProbe", html)


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


class DashboardAdvancedBadgeTests(unittest.TestCase):
    def test_advanced_badge_markup_and_renderer_exist(self):
        html = dashboard_html()

        self.assertIn('id="scanAdvancedBadge"', html)
        self.assertIn("function renderAdvancedBadge(", html)
        self.assertIn("function advancedDiffCount(", html)

    def test_badge_compares_against_the_field_default_not_a_hardcoded_value(self):
        """Default must be read off the freshly loaded form (defaultValue/
        defaultChecked), not a second hardcoded copy of the initial values
        that could drift from the markup."""
        html = dashboard_html()

        body = html.split("function advancedDiffCount(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("defaultValue", body)
        self.assertIn("defaultChecked", body)

    def test_render_scan_estimate_refreshes_the_badge(self):
        """Applying a preset or resetting the form must update the badge -
        both routes go through renderScanEstimate()."""
        html = dashboard_html()

        body = html.split("function renderScanEstimate(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("renderAdvancedBadge()", body)


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
        """The limit has to be applied, not merely defined.

        This once asserted only that the name appeared somewhere, which a bare
        constant declaration satisfied.
        """
        html = dashboard_html()

        self.assertRegex(html, r"const HOST_ROW_RENDER_LIMIT = \d+;")
        self.assertRegex(html, r"\.slice\(0,\s*HOST_ROW_RENDER_LIMIT\)")

    def test_host_row_ids_do_not_accumulate_across_scans(self):
        """The id map is per scan; a session sweeping several /16s would else grow."""
        html = dashboard_html()

        self.assertIn("hostRowIdScan", html)
        self.assertIn("hostRowIds.clear()", html)

    def test_the_replaced_port_profile_storage_key_is_cleared(self):
        html = dashboard_html()

        self.assertIn("removeItem('netroach.customPortProfiles.v1')", html)

    def test_a_clamped_host_count_is_not_presented_as_exact(self):
        html = dashboard_html()

        self.assertIn("hostsClamped", html)
        self.assertIn("' 이상'", html)

    def test_the_save_row_controls_do_not_mark_a_preset_edited(self):
        html = dashboard_html()

        self.assertIn("event.target.id === 'scanPresetIncludeTargets'", html)

    def test_preset_ids_are_unique_within_a_millisecond(self):
        html = dashboard_html()

        self.assertIn("function newPresetId(", html)
        self.assertNotIn("id: `user-${Date.now()}`", html)

    def test_new_results_button_lives_inside_the_scroll_container(self):
        """position: sticky is inert unless the button is a descendant of the
        element that actually scrolls (#scanHostRows)."""
        html = dashboard_html()

        host_rows_open = html.index('<div class="host-rows" id="scanHostRows">')
        host_rows_close = html.index("</div>", html.index('id="scanHostRowsList"'))
        button_index = html.index('id="scanNewResults"')
        self.assertTrue(host_rows_open < button_index < host_rows_close)

    def test_host_rows_show_a_live_in_progress_state(self):
        """Design spec section 3: a host with fewer rows than the job's
        port_count while the scan is still running reads '스캔 중... n/total',
        not just done/error."""
        html = dashboard_html()

        self.assertIn("function hostRowState(", html)
        body = html.split("function hostRowState(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("스캔 중", body)
        self.assertIn("완료", body)
        self.assertIn("오류", body)

    def test_host_progress_uses_the_unpaginated_host_summary(self):
        """A host's total must come from payload.hosts (an unpaginated
        GROUP BY), not from the possibly-truncated loaded results page -
        otherwise a host sorted late in a big scan reads a wrong fraction."""
        html = dashboard_html()

        body = html.split("function groupResultsByHost(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("hostSummaries", body)

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


class DashboardTargetCompactionTests(unittest.TestCase):
    """A range scan's target list is long enough to swamp the row it sits in.

    Ports were already compacted; targets were printed raw in all four places,
    so six /24 networks filled the table cell, the detail row and the progress
    strip with 71 characters of CIDR.
    """

    def test_the_helpers_exist(self):
        html = dashboard_html()

        for symbol in (
            "function compactTargetsText(",
            "function compactTargetsHtml(",
            "function stripDisclosure(",
            "function stripTargetLabel(",
            "function stripPortLabel(",
        ):
            self.assertIn(symbol, html)

    def test_no_place_prints_the_raw_target_list_any_more(self):
        html = dashboard_html()

        self.assertNotIn("${escapeHtml(job.targets)}</td>", html)
        self.assertNotIn("<span>Targets</span>${escapeHtml(job.targets)}", html)

    def test_lists_compact_and_the_summary_still_expands(self):
        html = dashboard_html()

        # Tables get the tooltip-only form: an expanding row would make the
        # table jump. The summary strip keeps the disclosure the detail panel
        # had, so a scan of 250 targets can still be read in full - but wearing
        # the short label, since a full range expression as the summary pushed
        # the numbers beside it out of their cell.
        self.assertIn("compactTargetsHtml(job.targets)", html)
        self.assertIn("stripDisclosure(stripTargetLabel(job.targets), job.targets)", html)
        self.assertIn("stripDisclosure(stripPortLabel(job.ports), job.ports)", html)

    def test_the_result_toolbar_sits_with_the_results(self):
        """Exports and the lifecycle buttons act on the scan the strip above
        describes; in the command column they wrapped into three rows."""
        html = dashboard_html()

        pane = html.split('<section class="result-pane">', 1)[1]
        for control in ('id="scanExportReport"', 'id="scanCancel"', 'id="scanDelete"',
                        'id="scanSummaryStrip"'):
            self.assertIn(control, pane)

    def test_the_strip_names_one_target_and_counts_the_ports(self):
        html = dashboard_html()

        self.assertIn("label: `${stripTargetLabel(job.targets)} · ${stripPortLabel(job.ports)}`", html)
        self.assertIn("외 ${items.length - 1}개", html)


class DashboardHostViewTests(unittest.TestCase):
    """The hosts tab mixed an accurate summary with a truncated result page.

    Port numbers came from the loaded rows (capped at 500) while totals came
    from the server's GROUP BY over every row, so a host whose open ports fell
    outside the window rendered as an empty line and sorted below hosts with
    nothing open - the opposite of what the tab is for.
    """

    def test_open_detection_uses_the_server_summary_not_the_loaded_page(self):
        html = dashboard_html()

        body = html.split("function groupResultsByHost(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("entry.openCount = Number(summary.states?.open || 0)", body)
        self.assertIn("b.openCount - a.openCount", body)

    def test_hosts_are_ordered_stably(self):
        """Equal hosts kept insertion order, which changed between polls."""
        html = dashboard_html()

        body = html.split("function groupResultsByHost(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("localeCompare(b.host", body)

    def test_the_row_table_says_when_results_are_missing_from_it(self):
        """Filtering to filtered showed the few rows that stayed and hid the
        thousands stored as a count, which reads as a scan that found nothing."""
        html = dashboard_html()

        self.assertIn('id="scanResultFolded"', html)
        self.assertIn("function renderFoldedNotice(", html)
        body = html.split("function renderFoldedNotice(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("state.scanProgress?.states", body)
        self.assertIn("payload.total", body)
        # Scan-wide counts cannot be compared against a host- or search-narrowed page.
        self.assertIn("state.scanResultHost", body)
        self.assertIn("renderFoldedNotice(payload)", html)

    def test_the_hosts_tab_spends_its_page_budget_on_open_rows(self):
        """It draws port numbers for open ports and nothing else; closed and
        filtered rows crowded them out of the page and left counts instead."""
        html = dashboard_html()

        self.assertIn("params.set('state', 'open')", html)

    def test_another_machines_database_can_be_loaded_from_the_ui(self):
        """Copying the folder in by hand needs the app closed and the paths right."""
        html = dashboard_html()

        self.assertIn('id="mergeDbPath"', html)
        self.assertIn('id="mergeDbRun"', html)
        self.assertIn("function mergeDatabase(", html)
        body = html.split("function mergeDatabase(", 1)[1].split(chr(10) + "    }", 1)[0]
        # A path, not an upload: the file is routinely gigabytes.
        self.assertIn("'/v1/db/merge'", body)
        self.assertIn("JSON.stringify({path})", body)
        self.assertIn("netroach-artifacts", html)

    def test_the_two_result_actions_sit_with_the_settings_they_read(self):
        """One takes the evidence settings from this form, the other fills its
        target and port fields - neither belongs in the result pane's toolbar."""
        html = dashboard_html()

        form = html.split('<form id="scanForm">', 1)[1].split("</form>", 1)[0]
        self.assertIn('id="scanRecaptureEvidence"', form)
        self.assertIn('id="scanRescanOpen"', form)
        self.assertIn('id="scanSecondaryStatus"', form)

    def test_a_checkbox_explanation_sits_under_its_label(self):
        """Side by side in a 380px column, the two wrapped into fragments."""
        html = dashboard_html()

        block = html.split(".check-row {", 1)[1].split("}", 1)[0]
        self.assertIn("display: grid", block)
        self.assertIn(".check-row .helper {", html)

    def test_a_running_recapture_reports_how_far_it_has_got(self):
        """It runs on the backend's own thread; a line saying it started is
        indistinguishable from one that died."""
        html = dashboard_html()

        self.assertIn("async function watchRecaptureProgress(", html)
        body = html.split("async function watchRecaptureProgress(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("/evidence/recapture", body)
        self.assertIn("증적 재수집 중", body)
        self.assertIn("progress.error", body)
        self.assertIn("watchRecaptureProgress(scanId)", html)

    def test_evidence_can_be_recaptured_without_scanning_again(self):
        """A scan whose capture limit was too low has the ports already; the
        limit cost the pictures, not the findings."""
        html = dashboard_html()

        self.assertIn('id="scanRecaptureEvidence"', html)
        self.assertIn("/evidence/recapture", html)
        body = html.split("async function recaptureEvidence(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("screenshot_max", body)
        self.assertIn("capture_console", body)
        # It replaces the scan's evidence rather than topping it up, which the
        # operator has to know before pressing it.
        self.assertIn("교체", body)

    def test_rescanning_open_ports_fills_the_form_rather_than_starting(self):
        """The authorization tick and the workload warning belong to every
        scan, and a re-scan has no claim to skip them."""
        html = dashboard_html()

        self.assertIn('id="scanRescanOpen"', html)
        body = html.split("async function fillFormWithOpenTargets(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("open-targets", body)
        self.assertIn("$('scanTargets').value", body)
        self.assertNotIn("/v1/scans'", body)

    def test_service_detection_warns_about_automatic_evidence_cost(self):
        """Service detection owns the evidence side effects, so the warning
        must sit beside that one checkbox."""
        html = dashboard_html()

        service_row = html.split('name="service_probe"', 1)[1].split("</label>", 1)[0]
        self.assertIn("배너", service_row)
        self.assertIn("증적", service_row)
        self.assertIn("화면이 켜진 상태에서만", html)
        self.assertIn("웹 포트는 브라우저 화면 증적", html)

    def test_the_assessment_workbook_is_reachable_and_lists_findings_only(self):
        """It is the shape a report is handed in, and a closed port is not a
        finding - the link asks for open results rather than the whole scan.

        open_only rather than state=open: a UDP port that did not refuse is a
        finding too, and its state is open|filtered."""
        html = dashboard_html()

        self.assertIn('id="scanExportReport"', html)
        self.assertIn("format=report-xlsx&open_only=true", html)

    def test_a_scan_that_photographed_only_some_of_its_ports_says_so(self):
        """Ports past the capture limit are never tried, so nothing fails and
        the scan reads as complete with a twentieth of the evidence."""
        html = dashboard_html()

        self.assertIn("function evidenceCoverageWarning(", html)
        body = html.split("function evidenceCoverageWarning(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("not_attempted", body)
        self.assertIn("evidenceCoverageWarning()", html)

    def test_the_evidence_limit_is_reachable_from_the_form(self):
        html = dashboard_html()

        self.assertIn('name="screenshot_max"', html)
        self.assertIn("'screenshot_max'", html)
        self.assertIn("screenshot_max: Number(form.get('screenshot_max')", html)

    def test_a_scan_that_recorded_more_than_it_planned_says_so(self):
        """Folded counts can double; a fifteen-million total cannot be eyeballed."""
        html = dashboard_html()

        self.assertIn("function overRecordedWarning(", html)
        body = html.split("function overRecordedWarning(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("recorded <= planned", body)
        self.assertIn("metric-warning", body)
        self.assertIn(".metric-warning {", html)
        self.assertIn("grid-column: 1 / -1", html)

    def test_the_row_tab_is_not_named_after_a_filter_it_does_not_apply(self):
        """It defaults to every state, so calling it 열린 포트 misreads closed
        rows as a bug in the scan rather than the name."""
        html = dashboard_html()

        self.assertIn('data-result-tab="ports">포트 결과<', html)
        # The phrase is fine elsewhere - what it must not be is this tab's name.
        self.assertNotIn('data-result-tab="ports">열린 포트<', html)

    def test_a_host_with_nothing_open_still_says_what_was_found(self):
        """Its ports are stored as a count, so the row has no rows to show."""
        html = dashboard_html()

        self.assertIn("function bulkStateText(", html)
        body = html.split("function bulkStateText(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("state !== 'open'", body)
        self.assertIn("toLocaleString()", body)

    def test_open_ports_outside_the_window_are_still_reported(self):
        html = dashboard_html()

        self.assertIn("function hostOpenText(", html)
        body = html.split("function hostOpenText(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("open ${known}개", body)
        self.assertIn("외 ${missing}개", body)
        # A host with dozens of open ports must not push the other hosts off
        # the row it shares with them.
        self.assertIn("HOST_OPEN_PORTS_SHOWN", body)

    def test_a_truncated_host_list_says_so(self):
        html = dashboard_html()

        self.assertIn("표시 중", html)
        self.assertIn("HOST_ROW_RENDER_LIMIT", html)

    def test_both_tabs_ask_for_the_host_summary(self):
        """The ports tab builds its host picker and state chips from it, so
        skipping it there left both of those empty."""
        html = dashboard_html()

        self.assertNotIn("include_hosts", html)

    def test_the_hosts_tab_does_not_apply_the_row_filters(self):
        """Its totals come from an unfiltered summary, so filtering only the
        rows would put two populations in one line. The filter controls live
        inside the ports tab."""
        html = dashboard_html()

        body = html.split("const usingHostView = state.resultTab === 'hosts';", 1)[1].split("try {", 1)[0]
        operator_filters = body.split("} else {", 1)[1]
        for filter_call in (
            "params.set('host', state.scanResultHost)",
            "params.set('state', state.scanResultState)",
            "params.set('search', state.scanResultQuery.trim())",
        ):
            self.assertIn(filter_call, operator_filters)
        # The hosts branch sets state=open, which is not one of those - it is
        # what the list draws, not what the operator narrowed it to.
        hosts_branch = body.split("if (usingHostView) {", 1)[1].split("} else {", 1)[0]
        self.assertNotIn("state.scanResult", hosts_branch)


    def test_recapture_progress_survives_looking_at_another_scan(self):
        """The capture runs on the backend for as long as the ports take. The
        poll used to stop the moment the operator clicked a different job,
        leaving a count frozen mid-run and never resuming - so a second scan's
        recapture looked like it had simply done nothing."""
        html = dashboard_html()

        watch = html.split("async function watchRecaptureProgress(scanId) {", 1)[1]
        tick = watch.split("const tick = async () => {", 1)[1].split("state.recaptureWatch = setTimeout(tick", 1)[0]
        self.assertNotIn("if (state.scanId !== scanId) return;", tick)
        # It says whose run it is once the selection has moved on.
        self.assertIn("scanId === state.scanId ? '' : ` (스캔 ${shortId(scanId)})`", watch)
        # And picking that scan again resumes the count rather than showing a
        # stale line from whatever ran last.
        self.assertIn("resumeRecaptureWatch(scanId)", html.split("async function selectScan(", 1)[1])

    def test_a_rescan_keeps_the_protocol_the_ports_were_found_on(self):
        """UDP ports re-scanned over TCP find nothing and say nothing."""
        html = dashboard_html()

        body = html.split("async function fillFormWithOpenTargets() {", 1)[1]
        self.assertIn("$('scanProtocol').value = payload.protocol", body)

    def test_the_udp_preset_asks_only_for_ports_that_can_answer(self):
        """UDP confirms a port open only by a reply that correlates with what
        was sent, so the preset is the set the engine has a probe for. Every
        other port can say no more than open|filtered."""
        html = dashboard_html()

        preset = html.split("id: 'builtin-udp'", 1)[1].split("}}", 1)[0]
        ports = preset.split("ports: '", 1)[1].split("'", 1)[0]
        engine = (Path(__file__).resolve().parents[1] / "crates" / "netroach-engine" / "src" / "main.rs").read_text(
            encoding="utf-8"
        )
        payloads = engine.split("fn udp_probe_payload(", 1)[1].split(chr(10) + "}", 1)[0]
        # The match arms of that table, so "53" is not satisfied by "5353".
        probed = {
            number
            for arm in re.findall(r"^\s*([0-9|\s]+)=>", payloads, re.MULTILINE)
            for number in arm.replace("|", " ").split()
        }
        self.assertEqual(set(ports.split(",")) - probed, set())
        self.assertIn("protocol: 'udp'", preset)
        # ICMP unreachable arrives at the target's rate limit, not ours: at TCP
        # speed a closed port stops answering and reads as open|filtered.
        self.assertIn("rate_limit_per_sec: 200", preset)
        self.assertIn("rate_limit_per_sec", html.split("const PRESET_FIELDS", 1)[1].split(";", 1)[0])

    def test_udp_service_detection_is_its_own_tick_and_starts_off(self):
        """On UDP the tick decides what packet leaves the machine, not merely
        whether a reply is named: a router asked for its whole routing table is
        not the same scan as one zero byte. So the quiet scan is what a UDP
        scan does unless the operator asks for the probes."""
        html = dashboard_html()

        box = html.split('name="udp_service_probe"', 1)[1].split("</label>", 1)[0]
        # Unticked: `checked` would fall inside this slice if it were there.
        self.assertNotIn("checked", box)
        self.assertIn("RIP", box)
        # A scan is one protocol, so one of the two ticks answers for it.
        self.assertIn("service_probe: tcp ? tcpServiceProbe", html)
        self.assertIn("form.get('udp_service_probe') === 'on'", html)
        # And the preset does not turn the probes on behind the operator.
        preset = html.split("id: 'builtin-udp'", 1)[1].split("}}", 1)[0]
        self.assertIn("udp_service_probe: false", preset)

    def test_the_stop_is_its_own_button_not_the_start_one_relabelled(self):
        """One control that swaps between two opposite actions meant a second
        click where the first had been - the ordinary way to retry something
        that looked stuck - cancelled the run instead of starting it."""
        html = dashboard_html()

        self.assertIn('id="scanStopRecapture"', html)
        self.assertIn("$('scanRecaptureEvidence').addEventListener('click', recaptureEvidence)", html)
        self.assertIn("$('scanStopRecapture').addEventListener('click', cancelRecapture)", html)
        # The start button never becomes a stop.
        self.assertNotIn("'증적 재수집 중지' : '증적 재수집'", html)
        # It is hidden until a capture is running, and the start is out while it is.
        self.assertIn("$('scanStopRecapture').hidden = !recapturing;", html)
        self.assertIn("$('scanRecaptureEvidence').disabled = recapturing || !job || active;", html)

    def test_stopping_a_run_that_already_finished_is_not_an_error(self):
        """A capture can finish between the last poll and the click, and the
        raw API message said nothing an operator could use."""
        html = dashboard_html()

        body = html.split("async function cancelRecapture(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("이미 끝난 재수집입니다.", body)
        self.assertNotIn("error.message", body)

    def test_the_progress_line_says_which_port_it_is_on(self):
        """A port that yields no picture still takes its time, so the stored
        count can stand still for minutes on a range with many of them - which
        was being read as a run that had stopped."""
        html = dashboard_html()

        body = html.split("if (progress.running) {", 1)[1].split("return;", 1)[0]
        self.assertIn("progress.examined", body)
        self.assertIn("progress.current", body)

    def test_a_stalled_scan_can_be_cleared_and_says_why(self):
        """It still reads as running, so without this there is no way to be rid
        of a scan whose backend died and came back too quickly to be
        recovered."""
        html = dashboard_html()

        self.assertIn("const stalled = Boolean(job && job.stalled);", html)
        self.assertIn("$('scanDelete').disabled = !job || (active && !stalled);", html)
        self.assertIn("job.status === 'cancel_requested' && !stalled", html)
        # And the operator can see why those two are open.
        self.assertIn("응답 없음", html)


if __name__ == "__main__":
    unittest.main()
