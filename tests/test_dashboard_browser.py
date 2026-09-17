"""Exercise the shipped dashboard in Chromium against an isolated real API/DB.

Chromium comes from the packaged browser directory in this repository unless
PLAYWRIGHT_BROWSERS_PATH says otherwise. No packets are sent and no user DB is read.
"""

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from netroach.dashboard import dashboard_html
from netroach.evidence import BROWSER_CHANNEL
from netroach.models import PortResult
from netroach.storage import SQLiteRepository

BUNDLED_BROWSERS = Path(__file__).resolve().parents[1] / "desktop" / "src-tauri" / "resources" / "playwright"


def use_bundled_browser() -> None:
    """Point Playwright at the browser this repository already carries.

    Without this the suite skips under the plain `pytest` the project
    documents, because Chromium is not on Playwright's default path - and a
    skipped suite reads as a passing one. What it guards is not spare: the
    fixtures here cover the SYN-versus-Connect regression that reached users in
    0.2.4, so the guard for a bug that already shipped would be inert in the
    only command anyone runs.

    An explicit setting wins, so a machine with its own browsers keeps them.
    """
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or not BUNDLED_BROWSERS.is_dir():
        return
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(BUNDLED_BROWSERS)


class DashboardBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest("playwright is not installed") from None
        use_bundled_browser()
        cls.playwright = sync_playwright().start()
        try:
            # The same channel the evidence path launches: only the full
            # browser is bundled, and a bare launch would look for the
            # headless shell that is deliberately not there.
            cls.browser = cls.playwright.chromium.launch(channel=BROWSER_CHANNEL)
        except PlaywrightError as error:
            cls.playwright.stop()
            if "Executable doesn't exist" in str(error):
                raise unittest.SkipTest(f"Chromium is not installed: {error}") from error
            raise
        cls.addClassCleanup(cls.playwright.stop)
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        from fastapi.testclient import TestClient

        from netroach.api import create_app

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.jobs = []
        for index in range(6):
            host = f"127.0.0.{index + 1}"
            ports = [18080, 18081] if index == 0 else [18080 + index]
            job = self.repo.create_scan_job(
                targets=host, ports=",".join(map(str, ports)), scope=["127.0.0.0/8"],
                params={"protocol": "tcp", "resumable": False},
            )
            self.repo.mark_scan_started(job)
            for port in ports:
                self.repo.add_port_result(PortResult(
                    scan_id=job, host=host, port=port, protocol="tcp", state="open",
                    latency_ms=1, service_name="http" if port == 18080 else "ssh",
                    banner="HTTP/1.1 200 OK" if port == 18080 else "SSH-2.0-Test",
                ))
            self.repo.complete_scan(job, self.repo.summarize_scan_results(job))
            self.jobs.append(job)
        self.repo.add_result_evidence(
            self.jobs[0], host="127.0.0.1", port=18080, protocol="tcp",
            data=base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII="
            ), file_name="web.png", evidence_type="web_screenshot",
        )
        diagnostics = patch("netroach.api.collect_diagnostics")
        self.addCleanup(diagnostics.stop)
        diagnostics.start().return_value.to_dict.return_value = {
            "rust_engine_available": True, "app_version": "test", "platform": "test",
            "rust_engine_version": "test", "scapy_available": True,
            "packet_driver": "Npcap", "raw_socket_privileged": False,
            "syn_sweep_available": True,
        }
        dashboard_html.cache_clear()
        self.client = TestClient(create_app(str(self.repo.path)))
        self.addCleanup(self.client.close)
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 1000})
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.page.set_default_timeout(4000)
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.submitted = []
        self.held = []
        self.hold_prefix = None
        self.fake_recapture = False
        self.recapture_requests = []
        self.context.route("**/*", self.route)
        self.page.goto("http://netroach.test/dashboard")
        self.page.locator('.rail [data-view-target="scans"]').click()
        # Leave the hover/focus-expanded navigation before using the left form.
        self.page.locator("#scanRefresh").click()
        self.page.wait_for_function("state.scans.length === 6 && state.health?.rust_engine_available")

    def route(self, route):
        request = route.request
        url = urlsplit(request.url)
        if url.hostname != "netroach.test":
            route.abort()
            return
        # Intercept only scan execution. Everything read/rendered uses the real API.
        if request.method == "POST" and url.path == "/v1/scans":
            self.submitted.append(request.post_data_json)
            route.fulfill(json={"scan_id": self.jobs[0]})
            return
        if self.fake_recapture and url.path.endswith("/evidence/recapture") and request.method != "GET":
            # Capturing a desktop is external to UI control-flow tests.
            self.recapture_requests.append((request.method, url.path))
            reply = {"json": {"status": "started", "pending": 2, "limit": 20}} if request.method == "POST" else {
                "json": {"scan_id": url.path.split("/")[3], "cancelled": True, "captured": 0}}
        else:
            response = self.client.request(
                request.method, url.path + ("?" + url.query if url.query else ""),
                content=request.post_data,
                headers={"content-type": request.headers.get("content-type", "application/json")},
            )
            reply = {"status": response.status_code, "body": response.content,
                     "content_type": response.headers.get("content-type", "application/json")}
        if self.hold_prefix and request.url.startswith(self.hold_prefix):
            self.held.append((route, reply))
        else:
            route.fulfill(**reply)

    def select(self, index=0):
        self.page.evaluate("id => selectScan(id)", self.jobs[index])

    def release(self, *, fail=False):
        self.hold_prefix = None
        for route, reply in self.held:
            route.fulfill(status=500, json={"detail": "delayed failure"}) if fail else route.fulfill(**reply)
        self.held.clear()

    def open_advanced(self):
        """Detection and Connect-only now live behind 고급 설정, closed by
        default; a test that reaches them has to open the panel first, the
        way an operator would, rather than finding a hidden control."""
        self.page.evaluate("document.getElementById('scanAdvanced').open = true")

    def test_job_picker_is_above_results_and_scrolls_independently(self):
        self.page.wait_for_timeout(180)
        form = self.page.locator(".command-pane").bounding_box()
        jobs = self.page.locator(".scan-jobs-wrap").bounding_box()
        results = self.page.locator(".result-pane").bounding_box()
        self.assertGreater(jobs["x"], form["x"] + form["width"])
        self.assertLess(jobs["y"], 350, "job picker must be reachable without scrolling past the form")
        self.assertGreater(results["y"], jobs["y"] + jobs["height"])
        self.assertTrue(self.page.locator(".scan-jobs-wrap").evaluate("e => e.scrollHeight > e.clientHeight"))
        self.page.locator(".scan-jobs-wrap").evaluate("e => e.scrollTop = e.scrollHeight")
        self.assertEqual(self.page.locator(".workspace").evaluate("e => e.scrollTop"), 0)
        self.page.set_viewport_size({"width": 800, "height": 900})
        self.assertTrue(self.page.locator(".workspace").evaluate("e => e.scrollWidth <= e.clientWidth"))

    def test_hidden_controls_do_not_appear_until_their_action_is_available(self):
        for selector in ("#scanStopRecapture", "#scanNewResults", "#scanAdvancedBadge"):
            with self.subTest(selector=selector):
                self.assertFalse(self.page.locator(selector).is_visible())
        self.page.evaluate("state.recapturingScanId = 'test'; updateScanActionState()")
        self.assertTrue(self.page.locator("#scanStopRecapture").is_visible())

    def test_job_filter_selection_and_evidence_preview(self):
        self.page.locator("#scanJobSearch").fill(self.jobs[0][:8])
        self.assertEqual(self.page.locator("#scanJobs [data-scan-row]").count(), 1)
        self.page.locator("#scanJobStatus").select_option("failed")
        self.assertEqual(self.page.locator("#scanJobs [data-scan-row]").count(), 0)
        self.page.locator("#scanJobStatus").select_option("completed")
        self.page.locator("#scanJobs [data-scan-row]").click()
        self.page.locator('[data-result-tab="ports"]').click()
        self.page.wait_for_function("document.querySelectorAll('#scanResults tr').length === 2")
        self.assertIn("127.0.0.1", self.page.locator("#scanSummaryStrip").inner_text())
        self.page.locator("[data-evidence-view]").first.click()
        self.page.wait_for_function("document.querySelector('#viewerBody img')?.naturalWidth > 0")
        self.page.locator("#viewerClose").click()
        self.assertFalse(self.page.locator("#viewer").is_visible())
        self.assertEqual(self.errors, [])

    def test_submit_maps_scan_modes_and_requires_authorization(self):
        self.open_advanced()
        self.page.locator("#scanTargets").fill("127.0.0.1")
        self.page.locator("#scanPorts").fill("18080")
        self.assertTrue(self.page.locator("#scanSubmit").is_disabled())
        cases = [("tcp", False, False, True, False, False),
                 ("tcp", False, True, True, True, True),
                 ("tcp", True, True, False, True, True),
                 ("udp", False, True, False, True, False),
                 ("udp", False, False, False, False, False)]
        for protocol, connect, probe, want_syn, want_probe, want_evidence in cases:
            with self.subTest(protocol=protocol, connect=connect, probe=probe):
                self.page.locator("#scanProtocol").select_option(protocol)
                if protocol == "tcp":
                    self.page.locator("#scanConnectOnly").set_checked(connect)
                    self.page.locator('[name="service_probe"]').set_checked(probe)
                else:
                    self.page.locator('[name="udp_service_probe"]').set_checked(probe)
                self.page.locator("#scanAuthorized").check()
                with self.page.expect_response(lambda r: r.request.method == "POST"):
                    self.page.locator("#scanSubmit").click()
                self.page.wait_for_function("!document.querySelector('#scanAuthorized').checked")
                body = self.submitted[-1]
                self.assertEqual((body["syn_sweep"], body["service_probe"], body["capture_screenshots"],
                                  body["capture_console"]),
                                 (want_syn, want_probe, want_evidence, want_evidence))
                self.assertEqual(body["scope"], ["127.0.0.1/32"])
        self.page.locator("#scanReset").click()
        self.assertFalse(self.page.locator("#scanConnectOnly").is_disabled())
        self.assertFalse(self.page.locator("#scanConnectOnly").is_checked())

    def test_an_unavailable_syn_scan_names_the_remedy_it_actually_has(self):
        """A missing driver and a build without the feature need opposite things.

        The SYN build stopped shipping an Npcap installer, so "built for SYN,
        driver not installed yet" is the ordinary state of a fresh install.
        Telling that operator they need a build that includes Npcap sends them
        after the one part that is already correct.
        """
        self.open_advanced()
        cases = [
            (False, "Npcap이 필요한데 이 PC에서 찾지 못했습니다", "포함한 빌드"),
            (True, "이 빌드는 SYN 스캔을 지원하지 않아", "설치 파일로 설치"),
        ]
        for driver_present, expected, forbidden in cases:
            with self.subTest(driver_present=driver_present):
                self.page.evaluate(
                    "present => { state.health.diagnostics.syn_sweep_available = false;"
                    " state.health.diagnostics.packet_driver_available = present;"
                    " updateTcpScanAvailability(); }",
                    driver_present,
                )
                help_text = self.page.locator("#scanConnectOnlyHelp").inner_text()

                self.assertIn(expected, help_text)
                self.assertNotIn(forbidden, help_text)
                # Either way the scan that does work is the one left selected.
                self.assertTrue(self.page.locator("#scanConnectOnly").is_checked())
                self.assertTrue(self.page.locator("#scanConnectOnly").is_disabled())

    def test_scan_help_descriptions_open_from_their_question_mark(self):
        self.open_advanced()
        cases = [
            ("#scanServiceProbeHelpTrigger", "#scanServiceProbeHelp", "SYN-open 포트만"),
            ("#scanConnectOnlyHelpTrigger", "#scanConnectOnlyHelp", "Npcap 기반 SYN 스캔"),
            ("#scanUdpServiceProbeHelpTrigger", "#scanUdpServiceProbeHelp", "UDP 스캔에만 적용"),
        ]
        original_states = self.page.locator(
            '[name="service_probe"], #scanConnectOnly, [name="udp_service_probe"]'
        ).evaluate_all("nodes => nodes.map(node => node.checked)")

        for trigger_selector, tooltip_selector, expected_text in cases:
            with self.subTest(trigger=trigger_selector):
                trigger = self.page.locator(trigger_selector)
                tooltip = self.page.locator(tooltip_selector)
                self.assertEqual(trigger.inner_text(), "(?)")
                self.assertEqual(trigger.get_attribute("aria-describedby"), tooltip_selector[1:])
                self.assertFalse(tooltip.is_visible())
                trigger.hover()
                self.assertTrue(tooltip.is_visible())
                self.assertIn(expected_text, tooltip.inner_text())

        self.assertEqual(
            self.page.locator(
                '[name="service_probe"], #scanConnectOnly, [name="udp_service_probe"]'
            ).evaluate_all("nodes => nodes.map(node => node.checked)"),
            original_states,
        )

    def test_scan_help_descriptions_open_for_keyboard_focus(self):
        self.open_advanced()
        cases = [
            ("#scanServiceProbeHelpTrigger", "#scanServiceProbeHelp"),
            ("#scanConnectOnlyHelpTrigger", "#scanConnectOnlyHelp"),
            ("#scanUdpServiceProbeHelpTrigger", "#scanUdpServiceProbeHelp"),
        ]

        for trigger_selector, tooltip_selector in cases:
            with self.subTest(trigger=trigger_selector):
                trigger = self.page.locator(trigger_selector)
                tooltip = self.page.locator(tooltip_selector)
                trigger.focus()
                self.assertTrue(tooltip.is_visible())
                self.assertEqual(trigger.get_attribute("type"), "button")

    def test_scan_help_tooltips_stay_inside_a_phone_viewport(self):
        self.open_advanced()
        self.page.set_viewport_size({"width": 390, "height": 844})

        for trigger_selector, tooltip_selector in [
            ("#scanServiceProbeHelpTrigger", "#scanServiceProbeHelp"),
            ("#scanConnectOnlyHelpTrigger", "#scanConnectOnlyHelp"),
            ("#scanUdpServiceProbeHelpTrigger", "#scanUdpServiceProbeHelp"),
        ]:
            with self.subTest(trigger=trigger_selector):
                self.page.locator(trigger_selector).focus()
                box = self.page.locator(tooltip_selector).bounding_box()
                self.assertIsNotNone(box)
                self.assertGreaterEqual(box["x"], 0, box)
                self.assertLessEqual(box["x"] + box["width"], 390, box)
                self.assertEqual(
                    self.page.evaluate("document.documentElement.scrollWidth"),
                    self.page.evaluate("document.documentElement.clientWidth"),
                )

    def test_control_deck_theme_is_scoped_and_preserves_native_disabled_state(self):
        self.assertIsNotNone(self.page.locator("body").get_attribute("data-cd2001"))
        self.assertEqual(
            self.page.locator(".topbar").evaluate("node => getComputedStyle(node).backgroundColor"),
            "rgb(0, 61, 143)",
        )
        self.assertEqual(
            self.page.locator("#scanSubmit").evaluate("node => getComputedStyle(node).borderRadius"),
            "0px",
        )
        self.assertNotEqual(
            self.page.locator("#scanTargets").evaluate("node => getComputedStyle(node).boxShadow"),
            "none",
        )
        self.assertEqual(
            self.page.locator("#scanJobs").locator("xpath=ancestor::table/thead/tr/th[1]").evaluate(
                "node => getComputedStyle(node).borderRightWidth"
            ),
            "1px",
        )
        self.assertTrue(self.page.locator("#scanSubmit").is_disabled())

    def test_control_deck_job_and_host_summary_text_is_clear_without_heavy_bold(self):
        self.select()
        self.page.wait_for_function(
            "document.querySelector('#scanHostRowsList .host-row .host-state')?.textContent.includes('완료')"
        )

        selectors = {
            "job_id": "#scanJobs tr.selected td:nth-child(1)",
            "job_state": "#scanJobs tr.selected td:nth-child(2) .pill",
            "job_target": "#scanJobs tr.selected td:nth-child(3)",
            "host_name": "#scanHostRowsList .host-row .host-name",
            "host_open": "#scanHostRowsList .host-row .host-open",
            "host_state": "#scanHostRowsList .host-row .host-state",
        }
        metrics = self.page.evaluate(
            """selectors => Object.fromEntries(
              Object.entries(selectors).map(([name, selector]) => {
                const node = document.querySelector(selector);
                const style = getComputedStyle(node);
                return [name, {
                  text: node.textContent.trim(),
                  color: style.color,
                  fontSize: parseFloat(style.fontSize),
                  fontWeight: Number(style.fontWeight),
                }];
              })
            )""",
            selectors,
        )

        for name, item in metrics.items():
            with self.subTest(name=name, text=item["text"]):
                self.assertEqual(item["fontWeight"], 600, item)
                self.assertEqual(item["color"], "rgb(17, 17, 17)", item)
                self.assertGreaterEqual(
                    item["fontSize"], 15 if name == "job_state" else 16, item
                )

    def test_control_deck_host_and_port_values_are_visually_emphasized(self):
        self.select()
        self.page.locator('[data-result-tab="ports"]').click()
        self.page.wait_for_function("document.querySelectorAll('#scanResults tr').length === 2")

        metrics = self.page.locator(
            "#scanResults tr:first-child td:nth-child(-n+2)"
        ).evaluate_all(
            """nodes => {
              const channel = value => {
                value /= 255;
                return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
              };
              const rgb = value => (value.match(/\\d+(?:\\.\\d+)?/g) || []).slice(0, 3).map(Number);
              const visibleBackground = node => {
                let current = node;
                while (current) {
                  const value = getComputedStyle(current).backgroundColor;
                  const parts = value.match(/\\d+(?:\\.\\d+)?/g) || [];
                  if (parts.length < 4 || Number(parts[3]) > 0) return value;
                  current = current.parentElement;
                }
                return 'rgb(255, 255, 255)';
              };
              const luminance = value => {
                const [r, g, b] = rgb(value).map(channel);
                return 0.2126 * r + 0.7152 * g + 0.0722 * b;
              };
              return nodes.map(node => {
                const style = getComputedStyle(node);
                const foreground = luminance(style.color);
                const background = luminance(visibleBackground(node));
                return {
                  text: node.textContent.trim(),
                  fontWeight: Number(style.fontWeight),
                  contrast: (Math.max(foreground, background) + 0.05) /
                    (Math.min(foreground, background) + 0.05),
                };
              });
            }"""
        )

        self.assertEqual(len(metrics), 2)
        for item in metrics:
            with self.subTest(text=item["text"]):
                self.assertGreaterEqual(item["fontWeight"], 600, item)
                self.assertGreaterEqual(item["contrast"], 7, item)

    def test_sidebar_exposes_only_port_scan_and_opens_it_by_default(self):
        self.page.reload()
        self.page.wait_for_function("state.health?.rust_engine_available === true")

        items = self.page.locator(".rail .nav [data-view-target]")
        self.assertEqual(items.count(), 1)
        self.assertEqual(items.first.get_attribute("data-view-target"), "scans")
        self.assertEqual(self.page.evaluate("state.view"), "scans")
        self.assertTrue(self.page.locator("#view-scans").is_visible())
        self.assertEqual(self.page.locator("#viewTitle").inner_text(), "포트 스캔")

    def test_expanded_sidebar_reflows_the_workspace_instead_of_covering_it(self):
        self.page.wait_for_timeout(180)
        collapsed = self.page.evaluate(
            """() => {
              const rail = document.querySelector('.rail').getBoundingClientRect();
              const shell = document.querySelector('.shell').getBoundingClientRect();
              return {railRight: rail.right, railWidth: rail.width, shellLeft: shell.left};
            }"""
        )
        self.page.locator(".rail .nav button").first.hover()
        self.page.wait_for_timeout(180)
        expanded = self.page.evaluate(
            """() => {
              const rail = document.querySelector('.rail').getBoundingClientRect();
              const shell = document.querySelector('.shell').getBoundingClientRect();
              return {railRight: rail.right, railWidth: rail.width, shellLeft: shell.left};
            }"""
        )

        self.assertAlmostEqual(collapsed["railRight"], collapsed["shellLeft"], delta=1)
        self.assertGreaterEqual(expanded["railWidth"], 180)
        self.assertAlmostEqual(expanded["railRight"], expanded["shellLeft"], delta=1)

    def test_control_deck_scan_buttons_keep_labels_readable_and_unclipped(self):
        metrics = self.page.evaluate(
            """() => {
              const selectors = [
                '#scanRefresh', '#scanPresetSave', '#scanFillScope',
                '#scanSubmit', '#scanReset', '.preset-chip-apply'
              ];
              const channel = value => {
                value /= 255;
                return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
              };
              const rgb = value => (value.match(/\\d+(?:\\.\\d+)?/g) || []).slice(0, 3).map(Number);
              const visibleBackground = node => {
                let current = node;
                while (current) {
                  const value = getComputedStyle(current).backgroundColor;
                  const parts = value.match(/\\d+(?:\\.\\d+)?/g) || [];
                  if (parts.length < 4 || Number(parts[3]) > 0) return value;
                  current = current.parentElement;
                }
                return 'rgb(255, 255, 255)';
              };
              const luminance = value => {
                const [r, g, b] = rgb(value).map(channel);
                return 0.2126 * r + 0.7152 * g + 0.0722 * b;
              };
              return selectors.map(selector => {
                const node = document.querySelector(selector);
                const style = getComputedStyle(node);
                const foreground = luminance(style.color);
                const background = luminance(visibleBackground(node));
                const contrast = (Math.max(foreground, background) + 0.05) /
                  (Math.min(foreground, background) + 0.05);
                return {
                  selector,
                  text: node.textContent.trim(),
                  fontSize: parseFloat(style.fontSize),
                  contrast,
                  clippedX: node.scrollWidth > node.clientWidth + 1,
                  clippedY: node.scrollHeight > node.clientHeight + 1,
                };
              });
            }"""
        )

        for item in metrics:
            with self.subTest(selector=item["selector"], text=item["text"]):
                self.assertGreaterEqual(item["fontSize"], 14, item)
                self.assertGreaterEqual(item["contrast"], 4.5, item)
                self.assertFalse(item["clippedX"], item)
                self.assertFalse(item["clippedY"], item)

    def test_control_deck_navigation_stays_compact_on_a_phone_width(self):
        self.page.set_viewport_size({"width": 390, "height": 844})

        layout = self.page.evaluate(
            """() => {
              const rect = selector => {
                const box = document.querySelector(selector).getBoundingClientRect();
                return {width: box.width, height: box.height, top: box.top, bottom: box.bottom};
              };
              return {
                body: rect('body'), app: rect('.app'), rail: rect('.rail'), shell: rect('.shell'),
                topbar: rect('.topbar'), statusStrip: rect('.status-strip'),
                client: document.documentElement.clientWidth,
                scroll: document.documentElement.scrollWidth,
                railStyle: {
                  width: getComputedStyle(document.querySelector('.rail')).width,
                  maxWidth: getComputedStyle(document.querySelector('.rail')).maxWidth,
                  transform: getComputedStyle(document.querySelector('.rail')).transform,
                },
              };
            }"""
        )

        self.assertLessEqual(layout["rail"]["height"], 56, layout)
        self.assertEqual(layout["rail"]["width"], layout["client"], layout)
        self.assertLessEqual(layout["shell"]["top"], 56, layout)
        self.assertEqual(layout["scroll"], layout["client"], layout)
        self.assertGreaterEqual(layout["topbar"]["bottom"], layout["statusStrip"]["bottom"], layout)

    def test_rescan_replaces_port_sources_scope_and_authorization(self):
        self.page.locator('[data-preset-apply="builtin-quick"]').click()
        self.page.locator("#scanTargets").fill("127.0.0.9")
        self.page.locator("#scanAuthorized").check()
        self.select(1)
        self.page.locator("#scanRescanOpen").click()
        self.page.wait_for_function("document.querySelector('#scanTargets').value === '127.0.0.2'")
        self.assertEqual(self.page.locator("#scanPorts").input_value(), "18081")
        self.assertEqual(self.page.locator("#scanTopPorts").input_value(), "")
        self.assertEqual(self.page.locator("#scanProfile").input_value(), "")
        self.assertEqual(self.page.locator("#scanScope").input_value(), "127.0.0.2/32")
        self.assertFalse(self.page.locator("#scanAuthorized").is_checked())
        self.assertTrue(self.page.locator("#scanSubmit").is_disabled())
        self.assertEqual(self.submitted, [])

    def test_saved_profile_replaces_previous_port_range(self):
        self.page.locator("#scanProfile").select_option("web")
        preset = self.page.evaluate("presetFromForm(false)")
        self.page.locator("#scanPorts").fill("1-65535")
        self.page.evaluate("preset => applyScanPreset(preset)", preset)
        self.assertEqual(self.page.locator("#scanProfile").input_value(), "web")
        self.assertEqual(self.page.locator("#scanPorts").input_value(), "")
        self.assertEqual(self.page.locator("#scanTopPorts").input_value(), "")

    def test_recapture_start_and_cancel_keep_original_job_after_selection_changes(self):
        self.select(0)
        self.fake_recapture = True
        self.hold_prefix = f"http://netroach.test/v1/scans/{self.jobs[0]}/evidence/recapture"
        self.page.evaluate("() => { window.recaptureStart = recaptureEvidence(); }")
        self.select(1)
        self.assertTrue(self.held)
        self.release()
        self.page.evaluate("() => window.recaptureStart")
        self.assertEqual(self.page.evaluate("state.recapturingScanId"), self.jobs[0])
        self.page.evaluate("() => cancelRecapture()")
        self.assertEqual(self.recapture_requests, [
            ("POST", f"/v1/scans/{self.jobs[0]}/evidence/recapture"),
            ("DELETE", f"/v1/scans/{self.jobs[0]}/evidence/recapture"),
        ])

    def test_delayed_previous_job_response_cannot_replace_selected_results(self):
        self.hold_prefix = f"http://netroach.test/v1/scans/{self.jobs[0]}/"
        self.page.evaluate("id => { window.oldSelection = selectScan(id); }", self.jobs[0])
        self.page.wait_for_function("state.scanId !== null")
        self.select(1)
        self.assertTrue(self.held, "the old job's responses must arrive after the new job")
        self.release()
        self.page.evaluate("() => window.oldSelection")
        self.assertEqual(self.page.evaluate("state.scanResultPayload.scan_id"), self.jobs[1])
        self.assertEqual(self.page.evaluate("state.scanProgress.scan_id"), self.jobs[1])
        self.assertIn("127.0.0.2", self.page.locator("#scanHostRows").inner_text())

    def test_delayed_result_error_cannot_replace_another_jobs_success(self):
        self.hold_prefix = f"http://netroach.test/v1/scans/{self.jobs[0]}/results"
        self.page.evaluate("id => { window.oldSelection = selectScan(id); }", self.jobs[0])
        self.select(1)
        self.assertTrue(self.held)
        self.release(fail=True)
        self.page.evaluate("() => window.oldSelection")
        self.assertNotIn("delayed failure", self.page.locator("#scanResults").inner_text())
        self.assertNotIn("불러오지 못했습니다", self.page.locator("#resultCount").inner_text())

    def test_delayed_results_cannot_replace_new_search_for_the_same_job(self):
        self.select(0)
        self.page.locator('[data-result-tab="ports"]').click()
        self.hold_prefix = f"http://netroach.test/v1/scans/{self.jobs[0]}/results"
        with self.page.expect_request(lambda request: request.url.startswith(self.hold_prefix)):
            self.page.evaluate("() => { window.oldResults = refreshScanResults(); }")
        self.page.evaluate("() => 0")  # Dispatch the route before releasing later requests.
        self.assertTrue(self.held)
        self.hold_prefix = None
        self.page.locator("#scanResultSearch").fill("SSH")
        self.page.locator("#scanResultSearch").press("Enter")
        self.page.wait_for_function("document.querySelectorAll('#scanResults tr').length === 1")
        self.release()
        self.page.evaluate("() => window.oldResults")
        self.assertEqual(self.page.locator("#scanResults tr").count(), 1)
        self.assertIn("SSH-2.0-Test", self.page.locator("#scanResults").inner_text())
        self.assertEqual(self.page.locator("#scanResultSearch").input_value(), "SSH")


if __name__ == "__main__":
    unittest.main()
