from __future__ import annotations

import base64
import html
import json
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import public_result_dicts

REPORT_FORMATS = {"html", "markdown", "json"}
MAX_EMBEDDED_EVIDENCE_BYTES = 50 * 1024 * 1024
COLLAPSIBLE_SECTION_OPEN_LIMIT = 5
COLLAPSIBLE_TEXT_LIMIT = 160

# The JSON report keeps machine-readable keys; these are display labels only.
IDENTIFICATION_LABELS = {
    "confirmed": "확인됨",
    "inferred": "포트 추정",
    "unverified": "미확인",
}
REVIEW_REASON_LABELS = {
    "scan error": "스캔 오류",
    "ambiguous state": "상태 불명확",
    "service inferred from port": "서비스가 포트로만 추정됨",
    "annotated": "주석 있음",
    "error detail present": "오류 상세 있음",
}


def identification_label(value: Any) -> str:
    return IDENTIFICATION_LABELS.get(str(value or ""), str(value or ""))


def review_reason_labels(reasons: Any) -> str:
    return ", ".join(REVIEW_REASON_LABELS.get(str(reason), str(reason)) for reason in reasons or [])


def build_scan_report(
    job: dict[str, Any],
    results: list[dict[str, Any]],
    *,
    title: str | None = None,
    total_result_count: int | None = None,
    counts: dict[str, Any] | None = None,
    host_summaries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    results = public_result_dicts(results)
    generated_at = datetime.now(timezone.utc).isoformat()
    complete_states = dict((counts or {}).get("states") or {})
    summary = job.get("summary") or (
        summarize_state_counts(job.get("id"), complete_states)
        if complete_states
        else summarize_results(results)
    )
    open_results = [result for result in results if result.get("state") == "open"]
    annotated = [
        result
        for result in results
        if result.get("tags") or result.get("note") or result.get("evidence_files")
    ]
    observed_counts: dict[str, Any] = {
        "states": dict(Counter(str(result.get("state") or "unknown") for result in results)),
        "protocols": dict(Counter(str(result.get("protocol") or "unknown") for result in results)),
        "services": top_counter(result.get("service_name") or "unknown" for result in open_results),
        "hosts_with_open_ports": len({result.get("host") for result in open_results}),
    }
    supplied: dict[str, Any] = counts or {}
    report_counts = {
        "states": dict(supplied.get("states") or observed_counts["states"]),
        "protocols": dict(supplied.get("protocols") or observed_counts["protocols"]),
        "services": dict(supplied.get("services") or observed_counts["services"]),
        "hosts_with_open_ports": int(
            supplied.get("hosts_with_open_ports", observed_counts["hosts_with_open_ports"])
        ),
    }
    included_count = len(results)
    stored_count = included_count if total_result_count is None else max(0, int(total_result_count))
    omitted_count = max(0, stored_count - included_count)
    review_results = []
    for result in results:
        reasons = review_reasons(result)
        if reasons:
            review_results.append({**result, "review_reasons": reasons})
    evidence_items = [
        {
            "host": result.get("host"),
            "port": result.get("port"),
            "protocol": result.get("protocol"),
            "service_name": result.get("service_name"),
            "evidence": evidence,
        }
        for result in results
        for evidence in result.get("evidence_files") or []
    ]
    service_details = [
        {
            "host": result.get("host"),
            "port": result.get("port"),
            "protocol": result.get("protocol"),
            "service_name": result.get("service_name") or "",
            "identification": service_identification(result),
            "banner": result.get("banner") or "",
        }
        for result in open_results
        if result.get("service_name") or result.get("banner")
    ]
    return {
        "title": title or f"Netroach 스캔 보고서 {job.get('id', '')}".strip(),
        "generated_at": generated_at,
        "job": job,
        "summary": summary,
        "counts": report_counts,
        "completeness": {
            "total_stored_results": stored_count,
            "included_results": included_count,
            "omitted_results": omitted_count,
            "truncated": omitted_count > 0,
            "detail_selection": "open, review, and annotated results are prioritized before routine states",
        },
        "host_summaries": host_summaries or summarize_results_by_host(results),
        "open_results": open_results,
        "annotated_results": annotated,
        "review_results": review_results,
        "service_details": service_details,
        "evidence_items": evidence_items,
        "result_count": included_count,
    }


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    states = Counter(str(result.get("state") or "unknown") for result in results)
    return {
        "scan_id": results[0].get("scan_id") if results else None,
        "total": len(results),
        "open": states.get("open", 0),
        "closed": states.get("closed", 0),
        "open_filtered": states.get("open|filtered", 0),
        "filtered": states.get("filtered", 0),
        "error": states.get("error", 0) + states.get("unknown", 0),
    }


def summarize_state_counts(scan_id: Any, states: dict[str, int]) -> dict[str, Any]:
    known_total = sum(int(count) for count in states.values())
    known_states = {"open", "closed", "open|filtered", "filtered"}
    return {
        "scan_id": scan_id,
        "total": known_total,
        "open": int(states.get("open", 0)),
        "closed": int(states.get("closed", 0)),
        "open_filtered": int(states.get("open|filtered", 0)),
        "filtered": int(states.get("filtered", 0)),
        "error": sum(int(count) for state, count in states.items() if state not in known_states),
    }


def format_scan_report(report: dict[str, Any], report_format: str) -> str:
    if report_format == "json":
        return json.dumps(report, indent=2)
    if report_format == "markdown":
        return format_scan_report_markdown(report)
    if report_format == "html":
        return format_scan_report_html(report)
    raise ValueError("format must be one of: html, markdown, json")


def embed_report_evidence(
    report: dict[str, Any],
    load_evidence: Callable[[str], tuple[dict[str, Any], Path] | None],
    *,
    max_total_bytes: int = MAX_EMBEDDED_EVIDENCE_BYTES,
) -> dict[str, int]:
    if max_total_bytes < 0:
        raise ValueError("max_total_bytes cannot be negative")
    embedded = 0
    skipped = 0
    embedded_bytes = 0
    seen: set[str] = set()
    for item in report.get("evidence_items") or []:
        evidence = item.get("evidence") or {}
        evidence_id = str(evidence.get("id") or "")
        if not evidence_id or evidence_id in seen:
            continue
        seen.add(evidence_id)
        loaded = load_evidence(evidence_id)
        if loaded is None:
            evidence["embed_status"] = "missing"
            skipped += 1
            continue
        metadata, path = loaded
        size = path.stat().st_size
        if embedded_bytes + size > max_total_bytes:
            evidence["embed_status"] = "size_limit"
            skipped += 1
            continue
        content = path.read_bytes()
        media_type = str(metadata.get("mime_type") or "application/octet-stream")
        evidence["report_url"] = f"data:{media_type};base64,{base64.b64encode(content).decode('ascii')}"
        evidence["embed_status"] = "embedded"
        embedded += 1
        embedded_bytes += len(content)
    summary = {"embedded": embedded, "skipped": skipped, "bytes": embedded_bytes}
    report["embedded_evidence"] = summary
    return summary


def format_scan_report_markdown(report: dict[str, Any]) -> str:
    job = report["job"]
    summary = report["summary"]
    completeness = report["completeness"]
    lines = [
        f"# {report['title']}",
        "",
        f"- 생성 시각: `{report['generated_at']}`",
        f"- 스캔 ID: `{job.get('id')}`",
        f"- 상태: `{job.get('status')}`",
        f"- 대상: `{job.get('targets')}`",
        f"- 포트: `{job.get('ports')}`",
        f"- 포함된 결과: {completeness['included_results']} / {completeness['total_stored_results']}",
        "",
    ]
    if completeness["truncated"]:
        lines.extend(
            [
                f"> **상세 결과 일부 생략:** 보고서 한도 때문에 저장된 결과 {completeness['omitted_results']}건이 빠졌습니다.",
                "> open · 검토 대상 · 주석이 있는 행을 일반 상태보다 먼저 싣습니다.",
                "",
            ]
        )
    lines.extend(
        [
            "## 요약",
            "",
            f"- 전체: {summary.get('total', 0)}",
            f"- open: {summary.get('open', 0)}",
            f"- closed: {summary.get('closed', 0)}",
            f"- open|filtered: {summary.get('open_filtered', 0)}",
            f"- filtered: {summary.get('filtered', 0)}",
            f"- error: {summary.get('error', 0)}",
            f"- open 포트가 있는 호스트: {report['counts']['hosts_with_open_ports']}",
            "",
            "상태 표기: `open` 응답함, `closed` 거부됨, `filtered` 시간 초과, "
            "`open|filtered` 는 판단이 불가능한 UDP 결과, `error` 는 로컬 또는 네트워크 오류입니다.",
            "",
            "## 스캔 설정",
            "",
        ]
    )
    for label, value in scan_configuration(job):
        lines.append(f"- {label}: `{markdown_cell(value)}`")
    lines.extend(
        [
            "",
            "## 호스트별 요약",
            "",
            "| 호스트 | 전체 | open | closed | open\\|filtered | filtered | error |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for host_summary in report["host_summaries"]:
        states = host_summary.get("states") or {}
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in [
                    host_summary.get("host"),
                    host_summary.get("total", 0),
                    states.get("open", 0),
                    states.get("closed", 0),
                    states.get("open|filtered", 0),
                    states.get("filtered", 0),
                    states.get("error", 0),
                ]
            )
            + " |"
        )
    if not report["host_summaries"]:
        lines.append("| _없음_ | 0 | 0 | 0 | 0 | 0 | 0 |")
    lines.extend(
        [
            "",
            "## open 결과",
            "",
            "| 호스트 | 포트 | 프로토콜 | 서비스 | 증적 | 태그 | 메모 |",
            "| --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    for result in report["open_results"]:
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in [
                    result.get("host"),
                    result.get("port"),
                    result.get("protocol"),
                    result.get("service_name") or "",
                    format_markdown_evidence(result.get("evidence_files") or []),
                    ", ".join(result.get("tags") or []),
                    result.get("note") or "",
                ]
            )
            + " |"
        )
    if not report["open_results"]:
        lines.append("| _없음_ |  |  |  |  |  |  |")
    lines.extend(["", "## 서비스 식별 상세", ""])
    lines.extend(
        [
            "| 호스트 | 포트/프로토콜 | 서비스 | 식별 근거 | 배너 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for detail in report["service_details"]:
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in [
                    detail.get("host"),
                    f"{detail.get('port')}/{detail.get('protocol')}",
                    detail.get("service_name"),
                    identification_label(detail.get("identification")),
                    detail.get("banner"),
                ]
            )
            + " |"
        )
    if not report["service_details"]:
        lines.append("| _없음_ |  |  |  |  |")
    lines.extend(["", "## 검토 필요", ""])
    lines.extend(
        [
            "| 호스트 | 포트/프로토콜 | 상태 | 사유 | 서비스 | 상세 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for result in report["review_results"]:
        detail = result.get("error") or result.get("note") or result.get("banner") or ""
        lines.append(
            "| "
            + " | ".join(
                markdown_cell(value)
                for value in [
                    result.get("host"),
                    f"{result.get('port')}/{result.get('protocol')}",
                    result.get("state"),
                    review_reason_labels(result.get("review_reasons")),
                    result.get("service_name") or "",
                    detail,
                ]
            )
            + " |"
        )
    if not report["review_results"]:
        lines.append("| _없음_ |  |  |  |  |  |")
    lines.extend(["", "## 증적 이미지", ""])
    for item in report["evidence_items"]:
        evidence = item["evidence"]
        caption = (
            f"{item.get('host')}:{item.get('port')}/{item.get('protocol')} "
            f"{item.get('service_name') or ''} - {evidence.get('file_name') or 'evidence'}"
        ).strip()
        lines.extend([f"### {caption}", "", format_markdown_evidence([evidence]), ""])
    if not report["evidence_items"]:
        lines.append("- 없음")
    lines.extend(["", "## 서비스별 건수", ""])
    for service, count in report["counts"]["services"].items():
        lines.append(f"- `{service}`: {count}")
    if not report["counts"]["services"]:
        lines.append("- 없음")
    return "\n".join(lines) + "\n"


def format_scan_report_html(report: dict[str, Any]) -> str:
    job = report["job"]
    summary = report["summary"]
    completeness = report["completeness"]
    open_rows = "\n".join(format_html_result_row(result) for result in report["open_results"])
    if not open_rows:
        open_rows = "<tr><td colspan=\"7\"><em>open 결과 없음</em></td></tr>"
    host_rows = "\n".join(format_html_host_summary(summary) for summary in report["host_summaries"])
    if not host_rows:
        host_rows = '<tr><td colspan="7"><em>호스트 결과 없음</em></td></tr>'
    service_detail_rows = "\n".join(
        format_html_service_detail(detail) for detail in report["service_details"]
    )
    if not service_detail_rows:
        service_detail_rows = '<tr><td colspan="5"><em>식별된 서비스 없음</em></td></tr>'
    review_rows = "\n".join(format_html_review_row(result) for result in report["review_results"])
    if not review_rows:
        review_rows = '<tr><td colspan="6"><em>검토가 필요한 결과 없음</em></td></tr>'
    configuration_rows = "\n".join(
        f"<div><span>{html.escape(label)}</span><code>{html.escape(str(value))}</code></div>"
        for label, value in scan_configuration(job)
    )
    evidence_gallery = "\n".join(
        format_html_evidence_gallery_item(item) for item in report["evidence_items"]
    )
    if not evidence_gallery:
        evidence_gallery = "<p><em>포함된 결과에 증적 이미지가 없습니다.</em></p>"
    service_items = "\n".join(
        f"<li><code>{html.escape(str(service))}</code>: {count}</li>"
        for service, count in report["counts"]["services"].items()
    )
    if not service_items:
        service_items = "<li>없음</li>"
    service_details_section = format_html_collapsible_section(
        section_id="service-identification",
        title="서비스 식별 상세",
        count=len(report["service_details"]),
        summary=summarize_service_details(report["service_details"]),
        content=(
            '<div class="table-scroll"><table>'
            "<thead><tr><th>호스트</th><th>포트/프로토콜</th><th>서비스</th>"
            "<th>식별 근거</th><th>배너</th></tr></thead>"
            f"<tbody>{service_detail_rows}</tbody></table></div>"
        ),
    )
    review_section = format_html_collapsible_section(
        section_id="needs-review",
        title="검토 필요",
        count=len(report["review_results"]),
        summary=summarize_review_results(report["review_results"]),
        content=(
            '<div class="table-scroll"><table>'
            "<thead><tr><th>호스트</th><th>포트/프로토콜</th><th>상태</th>"
            "<th>사유</th><th>서비스</th><th>상세</th></tr></thead>"
            f"<tbody>{review_rows}</tbody></table></div>"
        ),
    )
    evidence_section = format_html_collapsible_section(
        section_id="evidence-gallery",
        title="증적 이미지",
        count=len(report["evidence_items"]),
        summary=summarize_evidence_items(report["evidence_items"]),
        content=f'<section class="evidence-gallery">{evidence_gallery}</section>',
    )
    completeness_warning = ""
    if completeness["truncated"]:
        completeness_warning = (
            '<aside class="warning"><strong>상세 결과 일부 생략</strong>'
            f'<span>보고서 한도 때문에 저장된 결과 {completeness["omitted_results"]}건이 빠졌습니다. '
            "open · 검토 대상 · 주석이 있는 행을 일반 상태보다 먼저 싣습니다.</span></aside>"
        )
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>{html.escape(str(report["title"]))}</title>
  <style>
    :root {{ color-scheme: light; --border: #d1d5db; --muted: #f3f4f6; --ink: #1f2937; --accent: #0f766e; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: "Malgun Gothic", "Segoe UI", system-ui, -apple-system, sans-serif; margin: 32px; color: var(--ink); line-height: 1.45; }}
    h1, h2, h3 {{ color: #111827; }}
    h2 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; margin-top: 34px; }}
    .meta, .cards {{ display: grid; gap: 8px; }}
    .cards {{ grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin: 16px 0 28px; }}
    .card {{ border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: #f9fafb; }}
    .card strong {{ display: block; font-size: 1.6rem; }}
    .configuration {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px 18px; }}
    .configuration div {{ display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px solid #e5e7eb; padding: 6px 0; }}
    .configuration span {{ color: #4b5563; }}
    .table-scroll {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: var(--muted); white-space: nowrap; }}
    code {{ background: var(--muted); padding: 1px 4px; border-radius: 4px; }}
    code.wrap {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
    .warning {{ display: grid; gap: 4px; border: 1px solid #f59e0b; border-left-width: 5px; background: #fffbeb; padding: 12px 14px; margin: 18px 0; }}
    .legend {{ border-left: 4px solid var(--accent); background: #f0fdfa; padding: 10px 12px; }}
    .section-controls {{ display: flex; justify-content: flex-end; gap: 8px; margin: 18px 0 4px; }}
    .section-controls button {{ border: 1px solid var(--border); border-radius: 6px; background: #fff; color: var(--ink); padding: 6px 10px; cursor: pointer; }}
    .section-controls button:hover {{ border-color: var(--accent); color: var(--accent); }}
    details.report-section {{ border-bottom: 2px solid #e5e7eb; margin-top: 28px; padding-bottom: 8px; }}
    details.report-section > summary {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; cursor: pointer; list-style: none; padding: 8px 2px; }}
    details.report-section > summary::-webkit-details-marker {{ display: none; }}
    details.report-section > summary::before {{ content: "▶"; color: var(--accent); font-size: .8rem; transition: transform .15s ease; }}
    details.report-section[open] > summary::before {{ transform: rotate(90deg); }}
    .section-heading {{ display: flex; align-items: center; gap: 8px; margin-right: auto; font-size: 1.5rem; font-weight: 700; color: #111827; }}
    .count-badge {{ min-width: 1.8rem; border-radius: 999px; background: #e5e7eb; padding: 2px 8px; text-align: center; font-size: .85rem; }}
    .section-summary {{ color: #6b7280; font-size: .9rem; text-align: right; }}
    .section-content {{ padding-top: 4px; }}
    .wrap-text {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
    details.inline-detail {{ max-width: 48rem; }}
    details.inline-detail > summary {{ cursor: pointer; color: #374151; list-style: none; }}
    details.inline-detail > summary::-webkit-details-marker {{ display: none; }}
    details.inline-detail > summary::after {{ content: " 전체 보기"; color: var(--accent); font-size: .82rem; white-space: nowrap; }}
    details.inline-detail[open] > summary::after {{ content: " 접기"; }}
    details.inline-detail[open] .detail-preview {{ display: none; }}
    .full-detail {{ margin-top: 6px; white-space: pre-wrap; overflow-wrap: anywhere; }}
    .evidence-image {{ width: 320px; height: 240px; object-fit: contain; background: #fff; border: 1px solid var(--border); border-radius: 4px; }}
    .evidence-item {{ display: inline-block; margin: 0 6px 6px 0; vertical-align: top; }}
    .evidence-agent {{ display: block; max-width: 320px; margin-top: 4px; font-size: 11px; color: #6b7280; word-break: break-word; }}
    .evidence-gallery {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }}
    .evidence-card {{ border: 1px solid var(--border); border-radius: 8px; padding: 10px; background: #f9fafb; break-inside: avoid; }}
    .evidence-card .evidence-image {{ width: 100%; max-width: 320px; display: block; margin-top: 8px; }}
    .muted {{ color: #6b7280; }}
    @media print {{
      body {{ margin: 12mm; font-size: 10pt; }}
      h2 {{ break-after: avoid; }}
      table, .card, .evidence-card {{ break-inside: avoid; }}
      .table-scroll {{ overflow: visible; }}
      .section-controls {{ display: none; }}
      details.report-section {{ border-bottom: 0; }}
      details.report-section > summary {{ break-after: avoid; }}
      details.report-section > summary::before {{ display: none; }}
      details.report-section > .section-content {{ display: block !important; }}
      details.inline-detail > summary {{ display: none; }}
      details.inline-detail > .full-detail {{ display: block !important; }}
      .evidence-image {{ width: 160px; height: 120px; }}
      a {{ color: inherit; text-decoration: none; }}
    }}
  </style>
</head>
<body>
  <h1>{html.escape(str(report["title"]))}</h1>
  <section class="meta">
    <div>생성 시각: <code>{html.escape(str(report["generated_at"]))}</code></div>
    <div>스캔 ID: <code>{html.escape(str(job.get("id")))}</code></div>
    <div>상태: <code>{html.escape(str(job.get("status")))}</code></div>
    <div>대상: <code>{html.escape(str(job.get("targets")))}</code></div>
    <div>포트: <code>{html.escape(str(job.get("ports")))}</code></div>
    <div>포함된 결과: <code>{completeness["included_results"]} / {completeness["total_stored_results"]}</code></div>
  </section>
  {completeness_warning}
  <section class="cards">
    {summary_card("전체", summary.get("total", 0))}
    {summary_card("open", summary.get("open", 0))}
    {summary_card("closed", summary.get("closed", 0))}
    {summary_card("open|filtered", summary.get("open_filtered", 0))}
    {summary_card("filtered", summary.get("filtered", 0))}
    {summary_card("error", summary.get("error", 0))}
    {summary_card("open 포트 보유 호스트", report["counts"]["hosts_with_open_ports"])}
  </section>
  <p class="legend"><strong>상태 표기:</strong> <code>open</code> 응답함, <code>closed</code> 거부됨,
    <code>filtered</code> 시간 초과, <code>open|filtered</code> 는 판단이 불가능한 UDP 결과,
    <code>error</code> 는 로컬 또는 네트워크 오류입니다.</p>
  <nav class="section-controls" aria-label="보고서 섹션 제어">
    <button type="button" data-report-toggle="expand">모두 펼치기</button>
    <button type="button" data-report-toggle="collapse">모두 접기</button>
  </nav>
  <h2>스캔 설정</h2>
  <section class="configuration">{configuration_rows}</section>
  <h2>호스트별 요약</h2>
  <div class="table-scroll"><table>
    <thead><tr><th>호스트</th><th>전체</th><th>open</th><th>closed</th><th>open|filtered</th><th>filtered</th><th>error</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table></div>
  <h2>open 결과</h2>
  <div class="table-scroll"><table>
    <thead><tr><th>호스트</th><th>포트</th><th>프로토콜</th><th>서비스</th><th>증적</th><th>태그</th><th>메모</th></tr></thead>
    <tbody>
      {open_rows}
    </tbody>
  </table></div>
  {service_details_section}
  {review_section}
  {evidence_section}
  <h2>서비스별 건수</h2>
  <ul>
    {service_items}
  </ul>
  <script>
    document.querySelectorAll('[data-report-toggle]').forEach((button) => {{
      button.addEventListener('click', () => {{
        const expanded = button.dataset.reportToggle === 'expand';
        document.querySelectorAll('details.report-section').forEach((section) => {{
          section.open = expanded;
        }});
      }});
    }});
  </script>
</body>
</html>
"""


def format_html_collapsible_section(
    *,
    section_id: str,
    title: str,
    count: int,
    summary: str,
    content: str,
) -> str:
    open_attribute = " open" if count <= COLLAPSIBLE_SECTION_OPEN_LIMIT else ""
    return (
        f'<details class="report-section" data-report-section="{html.escape(section_id, quote=True)}"'
        f"{open_attribute}>"
        '<summary><span class="section-heading" role="heading" aria-level="2">'
        f'{html.escape(title)} <span class="count-badge">{count}</span></span>'
        f'<span class="section-summary">{html.escape(summary)}</span></summary>'
        f'<div class="section-content">{content}</div></details>'
    )


def format_html_result_row(result: dict[str, Any]) -> str:
    leading_values = [
        result.get("host"),
        result.get("port"),
        result.get("protocol"),
        result.get("service_name") or "",
    ]
    cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in leading_values)
    cells += f"<td>{format_html_evidence(result.get('evidence_files') or [])}</td>"
    cells += f'<td>{html.escape(", ".join(result.get("tags") or []))}</td>'
    cells += f'<td>{format_html_collapsible_text(result.get("note") or "")}</td>'
    return f"<tr>{cells}</tr>"


def format_html_host_summary(host_summary: dict[str, Any]) -> str:
    states = host_summary.get("states") or {}
    values = [
        host_summary.get("host"),
        host_summary.get("total", 0),
        states.get("open", 0),
        states.get("closed", 0),
        states.get("open|filtered", 0),
        states.get("filtered", 0),
        states.get("error", 0),
    ]
    return "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in values) + "</tr>"


def format_html_service_detail(detail: dict[str, Any]) -> str:
    values = [
        detail.get("host"),
        f"{detail.get('port')}/{detail.get('protocol')}",
        detail.get("service_name") or "",
        identification_label(detail.get("identification")),
    ]
    cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in values)
    cells += f'<td>{format_html_collapsible_text(detail.get("banner") or "", code=True)}</td>'
    return f"<tr>{cells}</tr>"


def format_html_review_row(result: dict[str, Any]) -> str:
    detail = result.get("error") or result.get("note") or result.get("banner") or ""
    values = [
        result.get("host"),
        f"{result.get('port')}/{result.get('protocol')}",
        result.get("state"),
        review_reason_labels(result.get("review_reasons")),
        result.get("service_name") or "",
    ]
    cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in values)
    cells += f"<td>{format_html_collapsible_text(detail)}</td>"
    return f"<tr>{cells}</tr>"


def format_html_collapsible_text(
    value: Any,
    *,
    limit: int = COLLAPSIBLE_TEXT_LIMIT,
    code: bool = False,
) -> str:
    text = str(value or "")
    escaped = html.escape(text)
    wrapper = "code" if code else "span"
    wrapper_class = ' class="wrap"' if code else ' class="wrap-text"'
    if len(text) <= limit:
        return f"<{wrapper}{wrapper_class}>{escaped}</{wrapper}>"
    preview = html.escape(text[: max(1, limit - 3)].rstrip() + "...")
    return (
        '<details class="inline-detail">'
        f'<summary><span class="detail-preview">{preview}</span></summary>'
        f'<div class="full-detail"><{wrapper}{wrapper_class}>{escaped}</{wrapper}></div>'
        "</details>"
    )


def summarize_service_details(details: list[dict[str, Any]]) -> str:
    counts = Counter(str(detail.get("identification") or "unverified") for detail in details)
    parts = [
        f"{label} {counts[key]}"
        for key, label in [("confirmed", "확인됨"), ("inferred", "포트 추정"), ("unverified", "미확인")]
        if counts[key]
    ]
    return " | ".join(parts) if parts else "식별된 서비스 없음"


def summarize_review_results(results: list[dict[str, Any]]) -> str:
    reasons = Counter(reason for result in results for reason in result.get("review_reasons") or [])
    parts = [
        f"{label} {reasons[key]}"
        for key, label in [
            ("scan error", "오류"),
            ("ambiguous state", "불명확"),
            ("service inferred from port", "포트 추정"),
            ("annotated", "주석"),
            ("error detail present", "오류 상세"),
        ]
        if reasons[key]
    ]
    return " | ".join(parts) if parts else "검토가 필요한 결과 없음"


def summarize_evidence_items(items: list[dict[str, Any]]) -> str:
    types = Counter(str((item.get("evidence") or {}).get("type") or "image") for item in items)
    parts = [f"{evidence_type} {count}" for evidence_type, count in sorted(types.items())]
    return " | ".join(parts) if parts else "증적 이미지 없음"


def format_html_evidence_gallery_item(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") or {}
    caption = (
        f"{item.get('host')}:{item.get('port')}/{item.get('protocol')} "
        f"{item.get('service_name') or ''}"
    ).strip()
    file_name = evidence.get("file_name") or "evidence"
    evidence_type = evidence.get("type") or "image"
    return (
        '<article class="evidence-card">'
        f"<strong>{html.escape(caption)}</strong>"
        f'<div class="muted">{html.escape(str(file_name))} · {html.escape(str(evidence_type))}</div>'
        f"{format_html_evidence([evidence])}</article>"
    )


def format_html_evidence(evidence_files: list[dict[str, Any]]) -> str:
    items: list[str] = []
    for evidence in evidence_files:
        url = html.escape(str(evidence.get("report_url") or evidence.get("download_url") or ""), quote=True)
        name = html.escape(str(evidence.get("file_name") or "evidence"), quote=True)
        if not url:
            continue
        agent = str(evidence.get("capture_agent") or "")
        # Named so the exported report can answer "what rendered this" on its
        # own. Manual uploads have no capturing tool, so they get no caption.
        caption = (
            f'<span class="evidence-agent">수집 도구: {html.escape(agent)}</span>' if agent else ""
        )
        items.append(
            f'<span class="evidence-item">'
            f'<img class="evidence-image" src="{url}" alt="{name}" width="320" height="240" '
            f'loading="lazy">{caption}</span>'
        )
    return "".join(items) or ""


def format_markdown_evidence(evidence_files: list[dict[str, Any]]) -> str:
    items: list[str] = []
    for evidence in evidence_files:
        url = str(evidence.get("download_url") or "").replace(" ", "%20")
        name = str(evidence.get("file_name") or "evidence").replace("]", "\\]")
        agent = str(evidence.get("capture_agent") or "")
        if url:
            items.append(f"![{name}]({url})" + (f" (수집 도구: {agent})" if agent else ""))
    return "<br>".join(items)


def summary_card(label: str, value: Any) -> str:
    return f'<div class="card"><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></div>'


def summarize_results_by_host(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = {}
    for result in results:
        host = str(result.get("host") or "unknown")
        state = str(result.get("state") or "unknown")
        summary = summaries.setdefault(host, {"host": host, "total": 0, "states": {}})
        summary["total"] += 1
        summary["states"][state] = summary["states"].get(state, 0) + 1
    return [summaries[host] for host in sorted(summaries)]


def review_reasons(result: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    state = str(result.get("state") or "unknown")
    if state == "error":
        reasons.append("scan error")
    elif state == "open|filtered":
        reasons.append("ambiguous state")
    if service_identification(result) == "inferred":
        reasons.append("service inferred from port")
    if result.get("tags") or result.get("note"):
        reasons.append("annotated")
    if result.get("error") and state not in {"error", "filtered", "closed"}:
        reasons.append("error detail present")
    return reasons


def service_identification(result: dict[str, Any]) -> str:
    banner = str(result.get("banner") or "")
    if "inferred from port mapping" in banner:
        return "inferred"
    if banner:
        return "confirmed"
    return "unverified"


def scan_configuration(job: dict[str, Any]) -> list[tuple[str, Any]]:
    params = job.get("params") or {}
    values = [
        ("승인 범위", ", ".join(str(value) for value in job.get("scope") or [])),
        ("생성", job.get("created_at")),
        ("시작", job.get("started_at")),
        ("완료", job.get("completed_at")),
        ("프로토콜", params.get("protocol")),
        ("포트 프로필", params.get("port_profile")),
        ("상위 포트 수", params.get("top_ports")),
        ("제외 대상", ", ".join(str(value) for value in params.get("exclude") or [])),
        ("타임아웃 ms", params.get("timeout_ms")),
        ("동시 실행 수", params.get("concurrency")),
        ("초당 속도", params.get("rate_limit_per_sec")),
        ("UDP 재시도", params.get("udp_retries")),
        ("서비스 탐지", params.get("service_probe")),
        ("증적 수집", params.get("capture_evidence", params.get("capture_screenshots"))),
    ]
    return [(label, value) for label, value in values if value not in (None, "")]


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def top_counter(values: Any, *, limit: int = 10) -> dict[str, int]:
    grouped: defaultdict[str, int] = defaultdict(int)
    for value in values:
        grouped[str(value)] += 1
    ordered = sorted(grouped.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return dict(ordered)
