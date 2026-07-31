import json
import tempfile
import unittest
from pathlib import Path

from netprobe.reports import build_scan_report, embed_report_evidence, format_scan_report


class ReportTests(unittest.TestCase):
    def test_scan_report_summarizes_open_services_and_escapes_html(self):
        job = {"id": "scan-1", "status": "completed", "targets": "127.0.0.1", "ports": "80", "summary": None}
        results = [
            {
                "scan_id": "scan-1",
                "host": "127.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "latency_ms": 1.2,
                "service_name": "http",
                "service_confidence": 0.98,
                "evidence_files": [
                    {
                        "id": "evidence-1",
                        "type": "manual",
                        "file_name": "proof.png",
                        "download_url": "/v1/evidence/evidence-1/content",
                    }
                ],
                "tags": ["prod"],
                "note": "<script>alert(1)</script>",
            },
            {
                "scan_id": "scan-1",
                "host": "127.0.0.1",
                "port": 22,
                "protocol": "tcp",
                "state": "closed",
                "latency_ms": 2.0,
                "service_name": None,
                "tags": [],
                "note": None,
            },
        ]

        report = build_scan_report(job, results)
        html = format_scan_report(report, "html")
        markdown = format_scan_report(report, "markdown")
        payload = json.loads(format_scan_report(report, "json"))

        self.assertEqual(report["summary"]["open"], 1)
        self.assertEqual(report["counts"]["services"], {"http": 1})
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("| 127.0.0.1 | 80 | tcp | http |", markdown)
        self.assertEqual(payload["result_count"], 2)
        self.assertNotIn("latency_ms", report["open_results"][0])
        self.assertNotIn("service_confidence", report["open_results"][0])
        self.assertNotIn("Latency", html)
        self.assertNotIn("Latency", markdown)
        self.assertNotIn("latency_ms", payload["open_results"][0])
        self.assertNotIn("service_confidence", payload["open_results"][0])
        self.assertIn('class="evidence-image"', html)
        self.assertIn("width: 320px; height: 240px", html)
        self.assertIn("object-fit: contain", html)
        self.assertIn('width="320" height="240"', html)
        self.assertIn("![proof.png](/v1/evidence/evidence-1/content)", markdown)
        self.assertEqual(payload["open_results"][0]["evidence_files"][0]["type"], "manual")
        self.assertIn("<h2>Host Summary</h2>", html)
        self.assertIn('data-report-section="needs-review" open', html)
        self.assertIn('data-report-section="evidence-gallery" open', html)
        self.assertIn('data-report-toggle="expand"', html)
        self.assertIn('data-report-toggle="collapse"', html)
        self.assertIn(
            "<th>Host</th><th>Port</th><th>Protocol</th><th>Service</th>"
            "<th>Evidence</th><th>Tags</th><th>Note</th>",
            html,
        )

    def test_report_discloses_truncation_and_uses_complete_aggregates(self):
        job = {
            "id": "scan-large",
            "status": "completed",
            "targets": "127.0.0.1",
            "ports": "1-5",
            "summary": None,
            "params": {"protocol": "tcp", "timeout_ms": 800},
        }
        results = [
            {
                "scan_id": "scan-large",
                "host": "127.0.0.1",
                "port": 5,
                "protocol": "tcp",
                "state": "open",
                "service_name": "http",
                "banner": "inferred from port mapping",
                "tags": [],
                "note": None,
            }
        ]
        counts = {
            "states": {"open": 1, "filtered": 4},
            "protocols": {"tcp": 5},
            "services": {"http": 1},
            "hosts_with_open_ports": 1,
            "total": 5,
        }

        report = build_scan_report(
            job,
            results,
            total_result_count=5,
            counts=counts,
            host_summaries=[
                {"host": "127.0.0.1", "total": 5, "states": {"open": 1, "filtered": 4}}
            ],
        )
        html = format_scan_report(report, "html")
        markdown = format_scan_report(report, "markdown")

        self.assertEqual(report["summary"]["total"], 5)
        self.assertTrue(report["completeness"]["truncated"])
        self.assertEqual(report["completeness"]["omitted_results"], 4)
        self.assertEqual(report["review_results"][0]["review_reasons"], ["service inferred from port"])
        self.assertIn("Incomplete detail set", html)
        self.assertIn("Included results: <code>1 / 5</code>", html)
        self.assertIn("**Incomplete detail set:** 4 stored result(s)", markdown)

    def test_html_report_can_embed_evidence_for_offline_viewing(self):
        job = {"id": "scan-embed", "status": "completed", "targets": "127.0.0.1", "ports": "80"}
        results = [
            {
                "scan_id": "scan-embed",
                "host": "127.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service_name": "http",
                "evidence_files": [
                    {
                        "id": "evidence-embed",
                        "type": "manual",
                        "file_name": "proof.png",
                        "download_url": "/v1/evidence/evidence-embed/content",
                    }
                ],
            }
        ]
        report = build_scan_report(job, results)
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "proof.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\nfixture")

            summary = embed_report_evidence(
                report,
                lambda evidence_id: (
                    ({"mime_type": "image/png"}, image)
                    if evidence_id == "evidence-embed"
                    else None
                ),
            )

        html = format_scan_report(report, "html")
        self.assertEqual(summary, {"embedded": 1, "skipped": 0, "bytes": 15})
        self.assertIn("data:image/png;base64,", html)
        self.assertIn('href="data:image/png;base64,', html)

    def test_long_review_sections_and_text_default_to_collapsed(self):
        job = {"id": "scan-review", "status": "completed", "targets": "127.0.0.1", "ports": "1-6"}
        long_error = "denied " + ("detail " * 40)
        results = [
            {
                "scan_id": "scan-review",
                "host": "127.0.0.1",
                "port": port,
                "protocol": "tcp",
                "state": "error",
                "error": long_error,
                "tags": [],
            }
            for port in range(1, 7)
        ]

        html = format_scan_report(build_scan_report(job, results), "html")

        self.assertIn(
            '<details class="report-section" data-report-section="needs-review">',
            html,
        )
        self.assertNotIn('data-report-section="needs-review" open', html)
        self.assertIn('class="section-summary">Errors 6', html)
        self.assertIn('<details class="inline-detail">', html)
        self.assertIn("Show full", html)
        self.assertIn("details.report-section &gt; .section-content", html.replace(">", "&gt;"))

    def test_filtered_timeout_is_not_treated_as_review_item(self):
        job = {"id": "scan-filtered", "status": "completed", "targets": "127.0.0.1", "ports": "80"}
        report = build_scan_report(
            job,
            [
                {
                    "scan_id": "scan-filtered",
                    "host": "127.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "state": "filtered",
                    "error": "timeout",
                }
            ],
        )

        self.assertEqual(report["review_results"], [])


if __name__ == "__main__":
    unittest.main()
