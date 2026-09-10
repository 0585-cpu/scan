"""Exercise the shipped dashboard in Chromium against an isolated real API/DB.

Install the desktop-build extra and Chromium, or set PLAYWRIGHT_BROWSERS_PATH
to the packaged browser directory. No packets are sent and no user DB is read.
"""

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from netroach.dashboard import dashboard_html
from netroach.models import PortResult
from netroach.storage import SQLiteRepository


class DashboardBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest("playwright is not installed") from None
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch()
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

    def test_job_picker_is_above_results_and_scrolls_independently(self):
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
        self.page.locator("#scanTargets").fill("127.0.0.1")
        self.page.locator("#scanPorts").fill("18080")
        self.assertTrue(self.page.locator("#scanSubmit").is_disabled())
        cases = [("tcp", False, False, True, False, False),
                 ("tcp", False, True, True, True, True),
                 ("tcp", True, True, False, True, True),
                 ("udp", False, False, False, False, False)]
        for protocol, connect, probe, want_syn, want_probe, want_evidence in cases:
            with self.subTest(protocol=protocol, connect=connect, probe=probe):
                self.page.locator("#scanProtocol").select_option(protocol)
                if protocol == "tcp":
                    self.page.locator("#scanConnectOnly").set_checked(connect)
                    self.page.locator('[name="service_probe"]').set_checked(probe)
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
