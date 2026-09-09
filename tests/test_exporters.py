import io
import json
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from netroach.exporters import (
    format_results_csv,
    format_results_csv_bundle,
    format_results_json,
    format_results_ndjson,
    format_results_xlsx,
)


class ExporterTests(unittest.TestCase):
    def test_public_exports_omit_internal_measurements_without_mutating_input(self):
        job = {"id": "scan-1"}
        result = {
            "scan_id": "scan-1",
            "host": "127.0.0.1",
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "latency_ms": 1.2,
            "service_name": "http",
            "service_confidence": 0.98,
            "tags": [],
            "evidence_files": [
                {
                    "id": "evidence-1",
                    "type": "manual",
                    "file_name": "proof.png",
                    "download_url": "/v1/evidence/evidence-1/content",
                }
            ],
        }

        json_result = json.loads(format_results_json(job, [result]))["results"][0]
        csv_header = format_results_csv([result]).splitlines()[0]
        ndjson_result = json.loads(format_results_ndjson(job, [result]).splitlines()[1])["result"]

        for public_result in (json_result, ndjson_result):
            self.assertNotIn("latency_ms", public_result)
            self.assertNotIn("service_confidence", public_result)
        self.assertNotIn("latency_ms", csv_header)
        self.assertNotIn("service_confidence", csv_header)
        self.assertEqual(json_result["evidence_files"][0]["file_name"], "proof.png")
        self.assertEqual(ndjson_result["evidence_files"][0]["id"], "evidence-1")
        self.assertIn("evidence_files", csv_header)
        self.assertEqual(result["latency_ms"], 1.2)
        self.assertEqual(result["service_confidence"], 0.98)

    def test_csv_evidence_bundle_contains_csv_manifest_and_image_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "evidence.png"
            image_path.write_bytes(b"\x89PNG\r\n\x1a\nbundled")
            evidence = {
                "id": "evidence-1",
                "type": "manual",
                "file_name": "proof.png",
                "mime_type": "image/png",
                "download_url": "/v1/evidence/evidence-1/content",
            }
            result = {
                "scan_id": "scan-1",
                "host": "127.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "evidence_files": [evidence],
            }

            bundle = format_results_csv_bundle(
                {"id": "scan-1"},
                [result],
                load_evidence=lambda _evidence_id: (evidence, image_path),
            )

            with zipfile.ZipFile(BytesIO(bundle)) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"results.csv", "manifest.json", "evidence/evidence-1.png"},
                )
                csv_text = archive.read("results.csv").decode("utf-8-sig")
                self.assertIn("evidence/evidence-1.png", csv_text)
                self.assertEqual(archive.read("evidence/evidence-1.png"), image_path.read_bytes())

    def test_xlsx_export_embeds_images_in_evidence_sheet(self):
        from openpyxl import load_workbook
        from PIL import Image

        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "evidence.png"
            Image.new("RGB", (1042, 706), "navy").save(image_path, format="PNG")
            evidence = {
                "id": "evidence-1",
                "type": "manual",
                "file_name": "proof.png",
                "mime_type": "image/png",
                "sha256": "abc123",
            }
            result = {
                "scan_id": "scan-1",
                "host": "127.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service_name": "http",
                "note": "=SUM(1,1)",
                "evidence_files": [evidence],
            }

            payload = format_results_xlsx(
                {"id": "scan-1"},
                [result],
                load_evidence=lambda _evidence_id: (evidence, image_path),
            )
            workbook = load_workbook(BytesIO(payload))

            # One sheet. Matching a result to its picture across two of them
            # was the reader's job, for the one thing they opened the file for.
            self.assertEqual(workbook.sheetnames, ["Results"])
            sheet = workbook["Results"]
            self.assertEqual(sheet["B2"].value, "127.0.0.1")
            self.assertEqual(sheet["J2"].value, "'=SUM(1,1)")
            self.assertEqual(sheet.cell(1, 13).value, "Evidence")
            self.assertEqual(len(sheet._images), 1)
            # In the row it belongs to, in the Evidence column.
            self.assertEqual(sheet._images[0].anchor._from.col, 12)
            self.assertEqual(sheet._images[0].anchor._from.row, 1)

    def test_the_results_sheet_drops_the_bookkeeping_columns(self):
        """A sha256, a stored file name and an evidence type told the reader
        nothing they were reading the sheet to learn."""
        from openpyxl import load_workbook

        payload = format_results_xlsx(
            {"id": "scan-1"},
            [{"scan_id": "scan-1", "host": "10.0.0.1", "port": 80, "protocol": "tcp",
              "state": "open", "service_name": "http", "evidence_files": []}],
            load_evidence=lambda _evidence_id: None,
        )
        sheet = load_workbook(BytesIO(payload))["Results"]

        headers = [sheet.cell(1, column).value for column in range(1, 14)]
        for gone in ("SHA-256", "File Name", "Type"):
            self.assertNotIn(gone, headers)


class ExcelIllegalCharacterTests(unittest.TestCase):
    """A raw service banner is bytes, and Excel refuses most control codes."""

    def _job_and_result(self, banner):
        job = {"id": "scan-1", "targets": "10.0.0.1", "ports": "80"}
        result = {
            "scan_id": "scan-1",
            "host": "10.0.0.1",
            "port": 3127,
            "protocol": "tcp",
            "state": "open",
            "service_name": "unknown",
            "banner": banner,
            "evidence": None,
            "tags": [],
            "note": None,
            "created_at": "2026-09-09 02:13:26",
            "evidence_files": [],
        }
        return job, [result]

    def test_a_banner_full_of_control_bytes_still_exports(self):
        from netroach.exporters import format_results_xlsx

        job, results = self._job_and_result(chr(0x8D) + chr(0) + chr(1) + " raw {")

        book = format_results_xlsx(job, results, load_evidence=lambda _id: None)

        self.assertGreater(len(book), 0)

    def test_the_readable_part_of_the_banner_survives(self):
        import io

        import openpyxl

        from netroach.exporters import format_results_xlsx

        job, results = self._job_and_result("SSH-2.0-OpenSSH" + chr(0) + chr(0x8D) + " ready")

        book = format_results_xlsx(job, results, load_evidence=lambda _id: None)

        sheet = openpyxl.load_workbook(io.BytesIO(book))["Results"]
        banner = sheet.cell(2, 7).value
        self.assertIn("SSH-2.0-OpenSSH", banner)
        self.assertIn("ready", banner)

    def test_tabs_and_newlines_are_left_alone(self):
        import io

        import openpyxl

        from netroach.exporters import format_results_xlsx

        job, results = self._job_and_result("line one" + chr(10) + "line two" + chr(9) + "end")

        book = format_results_xlsx(job, results, load_evidence=lambda _id: None)

        sheet = openpyxl.load_workbook(io.BytesIO(book))["Results"]
        self.assertEqual(sheet.cell(2, 7).value, "line one" + chr(10) + "line two" + chr(9) + "end")


class DiagnosticReportWorkbookTests(unittest.TestCase):
    """The deliverable shape: one row per open port, its evidence beside it."""

    def _png(self, size=(800, 600)):
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", size, (12, 12, 12)).save(buffer, format="PNG")
        return buffer.getvalue()

    def _result(self, port, service, *, evidence=True):
        return {
            "scan_id": "scan-1",
            "host": "192.0.2.4",
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service_name": service,
            "banner": None,
            "evidence": None,
            "tags": [],
            "note": None,
            "created_at": "2026-09-09 02:13:26",
            "evidence_files": [{"id": f"e{port}", "file_name": f"{port}.png"}] if evidence else [],
        }

    def _build(self, results, loader=None):
        from netroach.exporters import format_diagnostic_report_xlsx

        job = {"id": "scan-1", "targets": "192.0.2.4", "ports": "1-65535"}
        return format_diagnostic_report_xlsx(job, results, load_evidence=loader or (lambda _id: None))

    def test_the_columns_match_the_report_they_are_pasted_into(self):
        import openpyxl

        book = self._build([self._result(111, "msrpc", evidence=False)])

        sheet = openpyxl.load_workbook(io.BytesIO(book)).active
        headers = [sheet.cell(1, column).value for column in range(1, 9)]
        self.assertEqual(
            headers,
            ["번호", "구분", "IP", "포트번호", "서비스 명", "상세내용", "증적", "비고"],
        )

    def test_a_row_carries_the_finding_and_leaves_the_operator_theirs(self):
        import openpyxl

        book = self._build([self._result(111, "msrpc", evidence=False)])

        sheet = openpyxl.load_workbook(io.BytesIO(book)).active
        self.assertEqual(sheet.cell(2, 1).value, 1)
        # 구분 and 비고 are the operator's to fill in.
        self.assertIsNone(sheet.cell(2, 2).value)
        self.assertEqual(sheet.cell(2, 3).value, "192.0.2.4")
        self.assertEqual(sheet.cell(2, 4).value, 111)
        self.assertEqual(sheet.cell(2, 5).value, "RPC")
        self.assertEqual(sheet.cell(2, 6).value, "포트 오픈됨")
        self.assertIsNone(sheet.cell(2, 8).value)

    def test_a_web_service_is_named_and_described_as_one(self):
        import openpyxl

        book = self._build([self._result(8080, "http", evidence=False)])

        sheet = openpyxl.load_workbook(io.BytesIO(book)).active
        self.assertEqual(sheet.cell(2, 5).value, "WEB")
        self.assertEqual(sheet.cell(2, 6).value, "웹 서비스 오픈됨")

    def test_an_unidentified_service_leaves_the_name_blank(self):
        import openpyxl

        book = self._build([self._result(9130, "unknown", evidence=False)])

        sheet = openpyxl.load_workbook(io.BytesIO(book)).active
        self.assertIsNone(sheet.cell(2, 5).value)
        self.assertEqual(sheet.cell(2, 6).value, "포트 오픈됨")

    def test_the_evidence_image_sits_in_the_row_it_belongs_to(self):
        import openpyxl

        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "shot.png"
            image_path.write_bytes(self._png())

            book = self._build(
                [self._result(111, "msrpc"), self._result(8080, "http")],
                loader=lambda _id: ({}, image_path),
            )

            sheet = openpyxl.load_workbook(io.BytesIO(book)).active
            self.assertEqual(len(sheet._images), 2)
            # Column G, on the rows the two findings occupy.
            anchors = sorted((image.anchor._from.col, image.anchor._from.row) for image in sheet._images)
            self.assertEqual(anchors, [(6, 1), (6, 2)])

    def test_a_tall_screenshot_is_scaled_to_fit_rather_than_squashed(self):
        import openpyxl

        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "shot.png"
            image_path.write_bytes(self._png((800, 600)))

            book = self._build([self._result(111, "msrpc")], loader=lambda _id: ({}, image_path))

            sheet = openpyxl.load_workbook(io.BytesIO(book)).active
            image = sheet._images[0]
            self.assertAlmostEqual(image.width / image.height, 800 / 600, places=2)

    def test_a_port_without_evidence_still_gets_its_row(self):
        import openpyxl

        book = self._build([self._result(111, "msrpc", evidence=False), self._result(7000, "unknown", evidence=False)])

        sheet = openpyxl.load_workbook(io.BytesIO(book)).active
        self.assertEqual(sheet.max_row, 3)
        self.assertEqual([sheet.cell(row, 1).value for row in (2, 3)], [1, 2])


class PrimaryEvidenceTests(unittest.TestCase):
    """A row shows one picture, and with two taken it is the netstat one."""

    def test_the_console_capture_wins_when_both_were_taken(self):
        from netroach.exporters import primary_evidence

        chosen = primary_evidence(
            [
                {"id": "page", "capture_agent": "chromium 151 800x600"},
                {"id": "console", "capture_agent": "windows console capture"},
            ]
        )

        self.assertEqual(chosen["id"], "console")

    def test_the_first_is_used_when_no_console_capture_is_there(self):
        from netroach.exporters import primary_evidence

        chosen = primary_evidence(
            [{"id": "page", "capture_agent": "chromium 151 800x600"}, {"id": "other"}]
        )

        self.assertEqual(chosen["id"], "page")

    def test_no_evidence_chooses_nothing(self):
        from netroach.exporters import primary_evidence

        self.assertIsNone(primary_evidence([]))


if __name__ == "__main__":
    unittest.main()
