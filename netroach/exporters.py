from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .models import public_result_dicts

RESULT_EXPORT_FIELDS = [
    "scan_id",
    "host",
    "port",
    "protocol",
    "state",
    "service_name",
    "banner",
    "evidence",
    "evidence_files",
    "error",
    "tags",
    "note",
    "created_at",
]


def format_results_json(job: dict[str, Any], results: list[dict[str, Any]]) -> str:
    return json.dumps({"job": job, "results": public_result_dicts(results)}, indent=2)


def format_results_csv(results: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=RESULT_EXPORT_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for result in public_result_dicts(results):
        row = dict(result)
        row["tags"] = json.dumps(row.get("tags") or [], ensure_ascii=False)
        row["evidence_files"] = json.dumps(row.get("evidence_files") or [], ensure_ascii=False)
        writer.writerow(row)
    return output.getvalue()


def format_results_csv_bundle(
    job: dict[str, Any],
    results: list[dict[str, Any]],
    *,
    load_evidence: Callable[[str], tuple[dict[str, Any], Path] | None],
) -> bytes:
    bundle_results = public_result_dicts(results)
    assets: list[tuple[str, Path]] = []
    manifest_evidence: list[dict[str, Any]] = []
    seen: set[str] = set()

    for result in bundle_results:
        bundled_evidence: list[dict[str, Any]] = []
        for evidence in result.get("evidence_files") or []:
            item = dict(evidence)
            evidence_id = str(item.get("id") or "")
            if evidence_id and evidence_id not in seen:
                loaded = load_evidence(evidence_id)
                if loaded:
                    metadata, path = loaded
                    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", evidence_id)
                    extension = _extension_for_mime_type(str(metadata.get("mime_type") or ""))
                    archive_path = f"evidence/{safe_id}{extension}"
                    item["bundle_path"] = archive_path
                    assets.append((archive_path, path))
                    manifest_evidence.append(item)
                    seen.add(evidence_id)
            elif evidence_id in seen:
                existing = next(
                    (entry for entry in manifest_evidence if entry.get("id") == evidence_id),
                    None,
                )
                if existing and existing.get("bundle_path"):
                    item["bundle_path"] = existing["bundle_path"]
            bundled_evidence.append(item)
        result["evidence_files"] = bundled_evidence

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("results.csv", format_results_csv(bundle_results).encode("utf-8-sig"))
        archive.writestr(
            "manifest.json",
            json.dumps(
                {"job": job, "evidence_files": manifest_evidence},
                ensure_ascii=False,
                indent=2,
            ).encode("utf-8"),
        )
        for archive_path, source_path in assets:
            archive.write(source_path, archive_path)
    return output.getvalue()


# The picture a row shows when it has more than one. A console capture carries
# the netstat line the report is written around; a page screenshot shows what
# the service looks like. When both were taken, the first is the finding.
CONSOLE_CAPTURE_AGENT = "windows console capture"


def primary_evidence(evidence_files: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not evidence_files:
        return None
    for evidence in evidence_files:
        if str(evidence.get("capture_agent") or "") == CONSOLE_CAPTURE_AGENT:
            return evidence
    return evidence_files[0]


# The evidence image inside a result row, and the room a row needs for it.
_RESULT_EVIDENCE_BOX = (1150, 260)
_RESULT_EVIDENCE_COLUMN_WIDTH = 164.6
_RESULT_EVIDENCE_ROW_HEIGHT = 200.1


def format_results_xlsx(
    job: dict[str, Any],
    results: list[dict[str, Any]],
    *,
    load_evidence: Callable[[str], tuple[dict[str, Any], Path] | None],
) -> bytes:
    """One sheet: every result, with its evidence in the row it belongs to.

    This used to be two - the results on one, the images on another keyed by
    host and port - which left the reader matching rows across sheets by hand
    for the one thing they opened the file to see.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.drawing.image import Image as ExcelImage
        from openpyxl.styles import Alignment, Font, PatternFill
        from PIL import Image as PillowImage
        from PIL import ImageOps
    except ImportError as exc:
        raise RuntimeError("Excel export requires openpyxl and Pillow; install with: pip install -e .") from exc

    workbook = Workbook()
    workbook.properties.title = f"Netroach Scan {job.get('id', '')}".strip()
    workbook.properties.creator = "Netroach"
    sheet = workbook.active
    sheet.title = "Results"
    headers = [
        "Scan ID",
        "Host",
        "Port",
        "Protocol",
        "State",
        "Service",
        "Banner",
        "Evidence Detail",
        "Tags",
        "Note",
        "Created At",
        "Image Count",
        "Evidence",
    ]
    sheet.append(headers)
    _style_excel_header(sheet, Font, PatternFill, Alignment)
    sheet.freeze_panes = "A2"
    sheet.column_dimensions["A"].width = 38
    sheet.column_dimensions["B"].width = 24
    for column in ("C", "D", "E", "F", "L"):
        sheet.column_dimensions[column].width = 14
    for column in ("G", "H", "I", "J"):
        sheet.column_dimensions[column].width = 36
    sheet.column_dimensions["K"].width = 22
    sheet.column_dimensions["M"].width = _RESULT_EVIDENCE_COLUMN_WIDTH

    image_streams: list[io.BytesIO] = []
    row_number = 2
    for result in public_result_dicts(results):
        evidence_files = result.get("evidence_files") or []
        sheet.append(
            [
                _excel_text(result.get("scan_id")),
                _excel_text(result.get("host")),
                result.get("port"),
                _excel_text(result.get("protocol")),
                _excel_text(result.get("state")),
                _excel_text(result.get("service_name")),
                _excel_text(result.get("banner")),
                _excel_text(result.get("evidence")),
                _excel_text(", ".join(result.get("tags") or [])),
                _excel_text(result.get("note")),
                _excel_text(result.get("created_at")),
                len(evidence_files),
                None,
            ]
        )
        for cell in sheet[row_number]:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        if evidence_files:
            # The first image is the one shown; Image Count says whether the
            # row carries more than the one on screen.
            loaded = load_evidence(str((primary_evidence(evidence_files) or {}).get("id") or ""))
            if loaded:
                try:
                    _, source_path = loaded
                    with PillowImage.open(source_path) as source_image:
                        source_image.load()
                        contained = ImageOps.contain(
                            source_image.convert("RGB"), _RESULT_EVIDENCE_BOX
                        )
                        stream = io.BytesIO()
                        contained.save(stream, format="PNG")
                        stream.seek(0)
                    image_streams.append(stream)
                    excel_image = ExcelImage(stream)
                    excel_image.width = contained.width
                    excel_image.height = contained.height
                    sheet.add_image(excel_image, f"M{row_number}")
                    sheet.row_dimensions[row_number].height = _RESULT_EVIDENCE_ROW_HEIGHT
                except Exception as exc:  # noqa: BLE001 - one broken image must not cost the sheet.
                    sheet.cell(row_number, 13, f"Image unavailable: {str(exc)[:160]}")
        row_number += 1

    sheet.auto_filter.ref = f"A1:M{max(1, row_number - 1)}"
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


# The deliverable these become: one row per open port with its evidence in the
# row, matching the workbook an assessment is handed in. 구분 and 비고 are the
# assessor's columns and are left empty on purpose.
_REPORT_HEADERS = ("번호", "구분", "IP", "포트번호", "서비스 명", "상세내용", "증적", "비고")
_REPORT_COLUMN_WIDTHS = {"A": 10.6, "B": 15.6, "C": 35.6, "D": 20.6, "E": 20.6, "F": 55.6, "G": 164.6, "H": 40.6}
# The evidence box in column G, in pixels. A screenshot keeps its proportions
# inside it rather than being stretched to fill it. Wide enough to hold a
# console capture at its own size: scaling one down to a narrower column is
# paid for by the netstat line, which is the thing being evidenced.
_REPORT_EVIDENCE_BOX = (1150, 260)
_REPORT_ROW_HEIGHT = 200.1

# Service names as an assessment report writes them, not as a scanner prints
# them. Anything unrecognised is left blank: a guess in this column is worse
# than a gap, because the reader takes it as identified.
_REPORT_SERVICE_NAMES = {
    "http": "WEB",
    "https": "WEB",
    "tls": "WEB",
    "ssh": "SSH",
    "msrpc": "RPC",
    "rpcbind": "RPC",
    "smb": "SMB",
    "netbios-ssn": "Netbios",
    "snmp": "SNMP",
    "ldaps": "LDAPS",
    "ldap": "LDAP",
    "nfs": "NFS",
    "telnet": "Telnet",
    "ftp": "FTP",
    "vnc": "VNC",
    "winrm": "WinRM",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "oracle": "OracleDB",
    "postgresql": "PostgreSQL",
    "mssql": "MSSQL",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "slp": "SLP",
}
_REPORT_WEB_SERVICES = {"WEB"}


def report_service_name(service: str | None) -> str | None:
    return _REPORT_SERVICE_NAMES.get(str(service or "").strip().lower())


def report_detail(service_label: str | None) -> str:
    return "웹 서비스 오픈됨" if service_label in _REPORT_WEB_SERVICES else "포트 오픈됨"


def format_diagnostic_report_xlsx(
    job: dict[str, Any],
    results: list[dict[str, Any]],
    *,
    load_evidence: Callable[[str], tuple[dict[str, Any], Path] | None],
) -> bytes:
    try:
        from openpyxl import Workbook
        from openpyxl.drawing.image import Image as ExcelImage
        from openpyxl.styles import Alignment, Font, PatternFill
        from PIL import Image as PillowImage
        from PIL import ImageOps
    except ImportError as exc:
        raise RuntimeError("Excel export requires openpyxl and Pillow; install with: pip install -e .") from exc

    workbook = Workbook()
    workbook.properties.title = f"Netroach 진단 결과 {job.get('id', '')}".strip()
    workbook.properties.creator = "Netroach"
    sheet = workbook.active
    sheet.title = "진단 결과"
    sheet.append(list(_REPORT_HEADERS))
    _style_excel_header(sheet, Font, PatternFill, Alignment)
    sheet.freeze_panes = "A2"
    for column, width in _REPORT_COLUMN_WIDTHS.items():
        sheet.column_dimensions[column].width = width

    image_streams: list[io.BytesIO] = []
    row_number = 2
    for index, result in enumerate(public_result_dicts(results), start=1):
        service_label = report_service_name(result.get("service_name"))
        sheet.append(
            [
                index,
                None,
                _excel_text(result.get("host")),
                result.get("port"),
                service_label,
                report_detail(service_label),
                None,
                None,
            ]
        )
        sheet.row_dimensions[row_number].height = _REPORT_ROW_HEIGHT
        evidence_files = result.get("evidence_files") or []
        if evidence_files:
            loaded = load_evidence(str((primary_evidence(evidence_files) or {}).get("id") or ""))
            if loaded:
                try:
                    _, source_path = loaded
                    with PillowImage.open(source_path) as source_image:
                        source_image.load()
                        contained = ImageOps.contain(source_image.convert("RGB"), _REPORT_EVIDENCE_BOX)
                        stream = io.BytesIO()
                        contained.save(stream, format="PNG")
                        stream.seek(0)
                    image_streams.append(stream)
                    excel_image = ExcelImage(stream)
                    excel_image.width = contained.width
                    excel_image.height = contained.height
                    sheet.add_image(excel_image, f"G{row_number}")
                except Exception as exc:  # noqa: BLE001 - one broken image must not cost the report.
                    sheet.cell(row_number, 7, f"증적 사용 불가: {str(exc)[:120]}")
        for cell in sheet[row_number]:
            cell.alignment = Alignment(vertical="center", horizontal="center", wrap_text=True)
        row_number += 1

    if row_number == 2:
        sheet.cell(2, 6, "열린 포트가 없습니다")

    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


def format_results_ndjson(job: dict[str, Any], results: list[dict[str, Any]]) -> str:
    lines = [json.dumps({"type": "job", "job": job})]
    lines.extend(
        json.dumps({"type": "result", "result": result})
        for result in public_result_dicts(results)
    )
    return "\n".join(lines) + "\n"


def _extension_for_mime_type(mime_type: str) -> str:
    return {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }.get(mime_type, ".bin")


def _style_excel_header(sheet: Any, font_type: Any, fill_type: Any, alignment_type: Any) -> None:
    for cell in sheet[1]:
        cell.font = font_type(bold=True, color="FFFFFF")
        cell.fill = fill_type("solid", fgColor="0F766E")
        cell.alignment = alignment_type(horizontal="center", vertical="center")
    sheet.row_dimensions[1].height = 24


# Excel rejects most control codes outright, and a service banner is raw
# bytes off a socket: a scan of one range carried fifty-six of them. openpyxl
# raises on the first, so a single binary banner cost the whole workbook.
_EXCEL_CONTROL_CHARACTERS = re.compile(
    "[" + "".join(chr(code) for code in [*range(0, 9), 11, 12, *range(14, 32)]) + "]"
)


def _excel_text(value: Any) -> str:
    text = "" if value is None else str(value)
    # Tab, newline and carriage return are the three Excel accepts, and a
    # banner's line breaks are worth keeping - the rest are dropped rather
    # than escaped, because what they carried was never text to begin with.
    text = _EXCEL_CONTROL_CHARACTERS.sub("", text)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text
