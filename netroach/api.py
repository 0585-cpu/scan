from __future__ import annotations

import hmac
import threading
from collections.abc import Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from .auth import API_TOKEN_COOKIE, require_active_authorization
from .config import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_UDP_RETRIES,
    MAX_CONCURRENCY,
    MAX_HOSTS,
    MAX_RATE_LIMIT_PER_SEC,
    MAX_TIMEOUT_MS,
    load_config,
    resolve_scan_options,
)
from .constants import RESULT_PROTOCOLS, RESULT_STATES
from .dashboard import dashboard_html
from .diagnostics import collect_diagnostics
from .engine import ScanCancelled, resolve_engine_path, run_scan
from .evidence import (
    DEFAULT_SCREENSHOT_MAX,
    DEFAULT_SCREENSHOT_TIMEOUT_MS,
    MAX_EVIDENCE_BYTES,
    capture_automatic_evidence,
)
from .exporters import (
    format_results_csv,
    format_results_csv_bundle,
    format_results_json,
    format_results_ndjson,
    format_results_xlsx,
)
from .live_capture import LiveCaptureRequest as LiveCaptureTask
from .live_capture import execute_live_capture
from .models import EngineSettings, PacketRequest, PortResult, public_result_dict, public_result_dicts
from .oast import OastSessionRequest, build_callback_url, build_interaction_payload, validate_oast_session_request
from .packet_sender import execute_packet_request
from .pcap import analyze_pcap
from .plugins import load_effective_plugin_catalog
from .reports import REPORT_FORMATS, build_scan_report, embed_report_evidence, format_scan_report
from .scan_inputs import (
    PORT_PROFILES,
    normalize_ports_expr,
    normalize_targets_expr,
    resolve_host_names,
    resolve_ports,
    resolve_targets,
    validate_scan_workload,
)
from .scope import IPAddress, scope_values_from_targets
from .storage import SQLiteRepository
from .version import __version__


class ScanCreateRequest(BaseModel):
    targets: str
    ports: str | None = None
    exclude: list[str] = Field(default_factory=list)
    port_profile: str | None = None
    top_ports: int | None = None
    config_env: str | None = None
    scope: list[str] = Field(default_factory=list)
    scope_from_targets: bool = False
    confirm_authorized: bool = False
    protocol: str = "tcp"
    timeout_ms: int = Field(default=800, ge=1, le=MAX_TIMEOUT_MS)
    concurrency: int = Field(default=2000, ge=1, le=MAX_CONCURRENCY)
    rate_limit_per_sec: int = Field(default=5000, ge=1, le=MAX_RATE_LIMIT_PER_SEC)
    udp_retries: int = Field(default=DEFAULT_UDP_RETRIES, ge=0, le=3)
    service_probe: bool = True
    capture_screenshots: bool = False
    screenshot_timeout_ms: int = Field(default=DEFAULT_SCREENSHOT_TIMEOUT_MS, ge=1_000, le=30_000)
    screenshot_max: int = Field(default=DEFAULT_SCREENSHOT_MAX, ge=1, le=100)
    max_hosts: int = Field(default=65536, ge=1, le=MAX_HOSTS)
    max_attempts: int = Field(default=DEFAULT_MAX_ATTEMPTS, ge=1)
    confirm_large_scan: bool = False


class PcapAnalyzeRequest(BaseModel):
    file: str
    top: int = 10


class LiveCaptureRequest(BaseModel):
    output: str
    duration_s: float | None = None
    count: int | None = None
    iface: str | None = None
    bpf_filter: str | None = None
    confirm_authorized: bool = False
    analyze: bool = True
    top: int = 10


class PacketSendRequest(BaseModel):
    template: str
    target: str
    scope: list[str] = Field(default_factory=list)
    confirm_authorized: bool = False
    count: int = 1
    interval_ms: int = 1000
    dport: int | None = None
    sport: int | None = None
    flags: str = "S"
    payload_text: str | None = None
    payload_base64: str | None = None
    dns_name: str | None = None
    http_method: str = "GET"
    http_path: str = "/"
    http_host: str | None = None
    dry_run: bool = False


class ResultMetadataRequest(BaseModel):
    tags: list[str] | None = None
    note: str | None = None


class CleanupRequest(BaseModel):
    older_than_days: int
    statuses: list[str] | None = None
    dry_run: bool = False


class DatabaseImportRequest(BaseModel):
    data: dict[str, Any]
    replace: bool = False


class OastSessionCreateRequest(BaseModel):
    label: str | None = None
    base_url: str | None = None
    ttl_seconds: int = 3600
    confirm_authorized: bool = False


def create_app(
    db_path: str | None = None,
    *,
    config_path: str | None = None,
    config_env: str | None = None,
    plugin_paths: list[str] | tuple[str, ...] | None = None,
    api_token: str | None = None,
) -> FastAPI:
    repo = SQLiteRepository(db_path)
    app_config = load_config(config_path)
    plugin_catalog = load_effective_plugin_catalog(app_config, plugin_paths)
    resolved_plugin_paths = tuple(plugin.path for plugin in plugin_catalog.plugins if plugin.path)
    plugin_payload = plugin_catalog.to_dict()
    plugin_payload["port_profiles"] = {
        name: list(ports)
        for name, ports in {
            **PORT_PROFILES,
            **app_config.port_profiles,
            **plugin_catalog.port_profiles,
        }.items()
    }
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.recovery_threads = _start_scan_recovery(repo.path)
        yield

    app = FastAPI(title="Netroach Local API", version=__version__, lifespan=lifespan)

    if api_token:
        _install_token_guard(app, api_token)

    @app.get("/")
    def dashboard_root() -> Response:
        return Response(content=dashboard_html(), media_type="text/html")

    @app.get("/dashboard")
    def dashboard() -> Response:
        return Response(content=dashboard_html(), media_type="text/html")

    @app.get("/v1/health")
    def health() -> dict[str, object]:
        diagnostics = collect_diagnostics().to_dict()
        diagnostics["database_path"] = str(repo.path)
        engine_available = bool(diagnostics["rust_engine_available"])
        return {
            "status": "ok" if engine_available else "degraded",
            "rust_engine_available": engine_available,
            "db": str(repo.path),
            "diagnostics": diagnostics,
            "plugins": plugin_payload,
        }

    @app.get("/v1/plugins")
    def list_plugins() -> dict[str, object]:
        return plugin_payload

    @app.post("/v1/oast/sessions")
    def create_oast_session(request: OastSessionCreateRequest, http_request: Request) -> dict[str, object]:
        try:
            base_url = request.base_url or str(http_request.base_url)
            oast_request = OastSessionRequest(
                confirm_authorized=request.confirm_authorized,
                label=request.label,
                base_url=base_url,
                ttl_seconds=request.ttl_seconds,
            )
            validate_oast_session_request(oast_request)
            session = repo.create_oast_session(
                label=request.label,
                base_url=base_url,
                ttl_seconds=request.ttl_seconds,
            )
            return {"session": session, "callback_url": build_callback_url(base_url, session["token"])}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/oast/sessions")
    def list_oast_sessions(limit: int = 50, offset: int = 0) -> dict[str, object]:
        try:
            _validate_limit_offset(limit=limit, offset=offset)
            sessions = repo.list_oast_sessions(limit=limit, offset=offset)
            return {"limit": limit, "offset": offset, "count": len(sessions), "sessions": sessions}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/oast/sessions/{session_id}")
    def get_oast_session(session_id: str) -> dict[str, object]:
        session = repo.get_oast_session(session_id)
        if not session:
            raise _not_found("OAST session not found")
        return session

    @app.delete("/v1/oast/sessions/{session_id}")
    def delete_oast_session(session_id: str) -> dict[str, object]:
        if not repo.delete_oast_session(session_id):
            raise _not_found("OAST session not found")
        return {"session_id": session_id, "deleted": True}

    @app.get("/v1/oast/sessions/{session_id}/interactions")
    def list_oast_interactions(session_id: str, limit: int = 50, offset: int = 0) -> dict[str, object]:
        if not repo.get_oast_session(session_id):
            raise _not_found("OAST session not found")
        try:
            _validate_limit_offset(limit=limit, offset=offset)
            interactions = repo.list_oast_interactions(session_id=session_id, limit=limit, offset=offset)
            return {
                "session_id": session_id,
                "limit": limit,
                "offset": offset,
                "count": len(interactions),
                "interactions": interactions,
            }
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.api_route(
        "/oast/{token}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        response_model=None,
    )
    async def record_oast_callback(token: str, request: Request) -> Response | dict[str, object]:
        session = repo.get_active_oast_session_by_token(token)
        if not session:
            raise _not_found("OAST token not found or expired")
        body = await request.body()
        interaction = build_interaction_payload(
            method=request.method,
            path=request.url.path,
            query_string=request.url.query,
            client_host=request.client.host if request.client else None,
            headers=list(request.headers.items()),
            body=body,
        )
        saved = repo.save_oast_interaction(session_id=session["id"], interaction=interaction)
        if request.method == "HEAD":
            return Response(status_code=204)
        return {
            "status": "recorded",
            "session_id": session["id"],
            "interaction_id": saved["id"],
        }

    @app.post("/v1/scans")
    def create_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks) -> dict[str, object]:
        if resolve_engine_path() is None:
            raise HTTPException(
                status_code=503,
                detail={"error": "Rust scan engine is unavailable"},
            )
        try:
            if request.protocol not in {"tcp", "udp"}:
                raise ValueError("protocol must be 'tcp' or 'udp'")
            effective_env = request.config_env or config_env
            request_values = _model_dump(request)
            explicit_fields = _model_fields_set(request)
            # Convenience, not a control: a scope derived from the targets can
            # never reject them. `confirm_authorized` remains the real gate.
            if request.scope_from_targets:
                request_values["scope"] = _merge_scope_values(
                    request.scope,
                    scope_values_from_targets(resolve_host_names(request.targets)),
                )
                explicit_fields.add("scope")
            options = resolve_scan_options(
                config=app_config,
                env=effective_env,
                values=request_values,
                explicit_fields=explicit_fields,
            )
            options = {**options, "plugins": resolved_plugin_paths}
            scope = require_active_authorization(request.confirm_authorized, options["scope"])
            targets, target_expr = resolve_targets(
                targets=request.targets,
                exclude=options["exclude"],
                max_hosts=options["max_hosts"],
            )
            scope.require_targets(targets)
            ports, port_expr = resolve_ports(
                ports=options["ports"],
                ports_file=options["ports_file"],
                port_profile=options["port_profile"],
                top_ports=options["top_ports"],
                port_profiles={**app_config.port_profiles, **plugin_catalog.port_profiles},
            )
            workload = validate_scan_workload(
                targets,
                ports,
                max_attempts=int(options["max_attempts"]),
                confirm_large_scan=request.confirm_large_scan,
            )
            options = {**options, "workload": workload}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc
        settings = EngineSettings(
            timeout_ms=options["timeout_ms"],
            concurrency=options["concurrency"],
            rate_limit_per_sec=options["rate_limit_per_sec"],
            service_probe=options["service_probe"],
            protocol=options["protocol"],
            udp_retries=options["udp_retries"],
            plugin_paths=resolved_plugin_paths,
        )
        scan_id = repo.create_scan_job(
            targets=target_expr,
            ports=port_expr,
            scope=list(options["scope"]),
            params=_scan_params(request, options),
        )
        background_tasks.add_task(
            _run_scan_job,
            repo.path,
            scan_id,
            targets,
            ports,
            settings,
            request.capture_screenshots,
            request.screenshot_timeout_ms,
            request.screenshot_max,
        )
        return {"scan_id": scan_id, "status": "queued", "workload": workload}

    @app.get("/v1/scans")
    def list_scans(limit: int = 50) -> dict[str, object]:
        try:
            if limit < 1:
                raise ValueError("limit must be at least 1")
            scans = repo.list_jobs(limit=limit)
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc
        return {"limit": limit, "count": len(scans), "scans": scans}

    @app.get("/v1/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, object]:
        job = repo.get_job(scan_id)
        if not job:
            raise _not_found("scan not found")
        return job

    @app.get("/v1/scans/{scan_id}/results")
    def get_scan_results(
        scan_id: str,
        limit: int = 10000,
        offset: int = 0,
        open_only: bool = False,
        state: str | None = None,
        protocol: str | None = None,
        service: str | None = None,
        host: str | None = None,
        search: str | None = None,
    ) -> dict[str, object]:
        if not repo.get_job(scan_id):
            raise _not_found("scan not found")
        try:
            _validate_result_query(
                limit=limit,
                offset=offset,
                open_only=open_only,
                state=state,
                protocol=protocol,
                host=host,
                search=search,
            )
            results = repo.get_results(
                scan_id,
                limit=limit,
                offset=offset,
                open_only=open_only,
                state=state,
                protocol=protocol,
                service=service,
                host=host,
                search=search,
            )
            total = repo.count_results(
                scan_id,
                open_only=open_only,
                state=state,
                protocol=protocol,
                service=service,
                host=host,
                search=search,
            )
            return {
                "scan_id": scan_id,
                "limit": limit,
                "offset": offset,
                "count": len(results),
                "total": total,
                "hosts": repo.summarize_results_by_host(scan_id),
                "results": public_result_dicts(results),
            }
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.patch("/v1/scans/{scan_id}/results/{host}/{protocol}/{port}")
    def annotate_scan_result(
        scan_id: str,
        host: str,
        protocol: str,
        port: int,
        request: ResultMetadataRequest,
    ) -> dict[str, object]:
        if protocol not in RESULT_PROTOCOLS:
            raise _bad_request(ValueError("protocol must be 'tcp' or 'udp'"))
        result = repo.update_result_metadata(
            scan_id,
            host=host,
            port=port,
            protocol=protocol,
            tags=request.tags,
            note=request.note,
        )
        if not result:
            raise _not_found("scan result not found")
        return public_result_dict(result)

    @app.post("/v1/scans/{scan_id}/results/{host}/{protocol}/{port}/evidence")
    async def attach_scan_result_evidence(
        scan_id: str,
        host: str,
        protocol: str,
        port: int,
        request: Request,
        filename: str = "evidence.png",
    ) -> dict[str, object]:
        if protocol not in RESULT_PROTOCOLS:
            raise _bad_request(ValueError("protocol must be 'tcp' or 'udp'"))
        try:
            content_length = int(request.headers.get("content-length") or 0)
        except ValueError as exc:
            raise _bad_request(ValueError("invalid Content-Length")) from exc
        if content_length > MAX_EVIDENCE_BYTES:
            raise _bad_request(ValueError(f"evidence image exceeds {MAX_EVIDENCE_BYTES} bytes"))
        content_buffer = bytearray()
        async for chunk in request.stream():
            content_buffer.extend(chunk)
            if len(content_buffer) > MAX_EVIDENCE_BYTES:
                raise _bad_request(ValueError(f"evidence image exceeds {MAX_EVIDENCE_BYTES} bytes"))
        content = bytes(content_buffer)
        try:
            return repo.add_result_evidence(
                scan_id,
                host=host,
                port=port,
                protocol=protocol,
                data=content,
                file_name=filename,
                evidence_type="manual",
            )
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/evidence/{evidence_id}/content")
    def get_evidence_content(evidence_id: str) -> FileResponse:
        evidence = repo.get_evidence_content(evidence_id)
        if not evidence:
            raise _not_found("evidence file not found")
        metadata, path = evidence
        return FileResponse(
            path,
            media_type=str(metadata["mime_type"]),
            filename=str(metadata["file_name"]),
            content_disposition_type="inline",
        )

    @app.delete("/v1/evidence/{evidence_id}")
    def delete_evidence(evidence_id: str) -> dict[str, object]:
        if not repo.delete_evidence_file(evidence_id):
            raise _not_found("evidence file not found")
        return {"evidence_id": evidence_id, "deleted": True}

    @app.get("/v1/scans/{scan_id}/progress")
    def get_scan_progress(scan_id: str) -> dict[str, object]:
        progress = repo.get_scan_progress(scan_id)
        if not progress:
            raise _not_found("scan not found")
        return progress

    @app.post("/v1/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> dict[str, object]:
        try:
            job = repo.request_scan_cancel(scan_id)
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc
        if not job:
            raise _not_found("scan not found")
        return {"scan_id": scan_id, "status": job["status"]}

    @app.delete("/v1/scans/{scan_id}")
    def delete_scan(scan_id: str) -> dict[str, object]:
        if not repo.delete_scan(scan_id):
            raise _not_found("scan not found")
        return {"scan_id": scan_id, "deleted": True}

    @app.post("/v1/scans/cleanup")
    def cleanup_scans(request: CleanupRequest) -> dict[str, object]:
        try:
            return repo.cleanup_scan_jobs(
                older_than_days=request.older_than_days,
                statuses=request.statuses,
                dry_run=request.dry_run,
            )
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/scans/{scan_id}/export")
    def export_scan(
        scan_id: str,
        format: str = "json",  # noqa: A002 - public query parameter name.
        limit: int = 1_000_000,
        offset: int = 0,
        open_only: bool = False,
        state: str | None = None,
        protocol: str | None = None,
        service: str | None = None,
        host: str | None = None,
        search: str | None = None,
        bundle_evidence: bool = False,
    ) -> Response:
        job = repo.get_job(scan_id)
        if not job:
            raise _not_found("scan not found")
        try:
            if format not in {"json", "csv", "ndjson", "xlsx"}:
                raise ValueError("format must be one of: json, csv, ndjson, xlsx")
            _validate_result_query(
                limit=limit,
                offset=offset,
                open_only=open_only,
                state=state,
                protocol=protocol,
                host=host,
                search=search,
            )
            results = repo.get_results(
                scan_id,
                limit=limit,
                offset=offset,
                open_only=open_only,
                state=state,
                protocol=protocol,
                service=service,
                host=host,
                search=search,
            )
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc
        if format == "csv":
            if bundle_evidence:
                bundle = format_results_csv_bundle(
                    job,
                    results,
                    load_evidence=repo.get_evidence_content,
                )
                return Response(
                    content=bundle,
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": 'attachment; filename="netroach-csv-evidence.zip"'
                    },
                )
            return Response(content=format_results_csv(results), media_type="text/csv")
        if format == "xlsx":
            try:
                workbook = format_results_xlsx(
                    job,
                    results,
                    load_evidence=repo.get_evidence_content,
                )
            except Exception as exc:  # noqa: BLE001
                raise _bad_request(exc) from exc
            return Response(
                content=workbook,
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={
                    "Content-Disposition": 'attachment; filename="netroach-results.xlsx"'
                },
            )
        if format == "ndjson":
            return Response(content=format_results_ndjson(job, results), media_type="application/x-ndjson")
        return Response(content=format_results_json(job, results), media_type="application/json")

    @app.get("/v1/scans/{scan_id}/report")
    def report_scan(
        scan_id: str,
        format: str = "html",  # noqa: A002 - public query parameter name.
        limit: int = 1_000_000,
        embed_evidence: bool = False,
    ) -> Response:
        job = repo.get_job(scan_id)
        if not job:
            raise _not_found("scan not found")
        try:
            if format not in REPORT_FORMATS:
                raise ValueError("format must be one of: html, markdown, json")
            if limit < 1:
                raise ValueError("limit must be at least 1")
            results = repo.get_report_results(scan_id, limit=limit)
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc
        counts = repo.summarize_report_counts(scan_id)
        report = build_scan_report(
            job,
            results,
            total_result_count=counts["total"],
            counts=counts,
            host_summaries=repo.summarize_results_by_host(scan_id),
        )
        if embed_evidence:
            if format != "html":
                raise _bad_request(ValueError("embed_evidence requires format=html"))
            embed_report_evidence(report, repo.get_evidence_content)
        media_type = {
            "html": "text/html",
            "markdown": "text/markdown",
            "json": "application/json",
        }[format]
        return Response(
            content=format_scan_report(report, format),
            media_type=media_type,
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/v1/pcaps/analyze")
    def analyze(request: PcapAnalyzeRequest) -> dict[str, object]:
        try:
            summary = analyze_pcap(request.file, top=request.top).to_dict()
            analysis_id = repo.save_pcap_analysis(request.file, summary)
            return {"analysis_id": analysis_id, "summary": summary}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.post("/v1/captures/live")
    def capture_live(request: LiveCaptureRequest) -> dict[str, object]:
        try:
            capture_request = LiveCaptureTask(**_model_dump(request))
            result = execute_live_capture(capture_request)
            analysis_id = None
            if result.analysis:
                analysis_id = repo.save_pcap_analysis(result.file, result.analysis)
            return {"analysis_id": analysis_id, "capture": result.to_dict()}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/pcaps/analyses")
    def list_pcap_analyses(limit: int = 50, offset: int = 0) -> dict[str, object]:
        try:
            _validate_limit_offset(limit=limit, offset=offset)
            analyses = repo.list_pcap_analyses(limit=limit, offset=offset)
            return {"limit": limit, "offset": offset, "count": len(analyses), "analyses": analyses}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/pcaps/analyses/{analysis_id}")
    def get_pcap_analysis(analysis_id: str) -> dict[str, object]:
        analysis = repo.get_pcap_analysis(analysis_id)
        if not analysis:
            raise _not_found("pcap analysis not found")
        return analysis

    @app.post("/v1/packets/send")
    def send_packet(request: PacketSendRequest) -> dict[str, object]:
        try:
            packet_request = PacketRequest(**_model_dump(request))
            result = execute_packet_request(packet_request)
            audit_id = repo.save_packet_audit(request=_model_dump(request), result=result)
            return {"audit_id": audit_id, "result": result.to_dict()}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/packets/audits")
    def list_packet_audits(
        limit: int = 50,
        offset: int = 0,
        template: str | None = None,
        target: str | None = None,
    ) -> dict[str, object]:
        try:
            _validate_limit_offset(limit=limit, offset=offset)
            audits = repo.list_packet_audits(limit=limit, offset=offset, template=template, target=target)
            return {"limit": limit, "offset": offset, "count": len(audits), "audits": audits}
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    @app.get("/v1/packets/audits/{audit_id}")
    def get_packet_audit(audit_id: str) -> dict[str, object]:
        audit = repo.get_packet_audit(audit_id)
        if not audit:
            raise _not_found("packet audit not found")
        return audit

    @app.get("/v1/db/export")
    def export_database() -> dict[str, object]:
        return repo.export_database()

    @app.post("/v1/db/import")
    def import_database(request: DatabaseImportRequest) -> dict[str, int]:
        try:
            return repo.import_database(request.data, replace=request.replace)
        except Exception as exc:  # noqa: BLE001
            raise _bad_request(exc) from exc

    return app


# Paths that must stay reachable without a token: OAST callbacks are delivered by
# the scanned systems themselves, which cannot present operator credentials.
_TOKEN_EXEMPT_PREFIXES = ("/oast/",)
_DASHBOARD_PATHS = ("/", "/dashboard")


def _install_token_guard(app: FastAPI, api_token: str) -> None:
    @app.middleware("http")
    async def require_api_token(request: Request, call_next):
        path = request.url.path
        if path.startswith(_TOKEN_EXEMPT_PREFIXES):
            return await call_next(request)
        if path in _DASHBOARD_PATHS and _token_matches(request.query_params.get("token"), api_token):
            # Hand the browser a cookie so the token stops travelling in URLs
            # (history, referrer headers, server logs).
            response = RedirectResponse(path, status_code=303)
            response.set_cookie(
                API_TOKEN_COOKIE,
                api_token,
                httponly=True,
                samesite="strict",
                path="/",
            )
            return response
        if _token_matches(_supplied_token(request), api_token):
            return await call_next(request)
        return JSONResponse(
            status_code=401,
            content={"detail": {"error": "missing or invalid API token"}},
            headers={"WWW-Authenticate": "Bearer"},
        )


def _supplied_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return request.cookies.get(API_TOKEN_COOKIE)


def _token_matches(supplied: str | None, api_token: str) -> bool:
    if not supplied:
        return False
    return hmac.compare_digest(supplied, api_token)


def _run_scan_job(
    db_path: str | Path,
    scan_id: str,
    targets: list[IPAddress],
    ports: list[int],
    settings: EngineSettings,
    capture_screenshots: bool = False,
    screenshot_timeout_ms: int = DEFAULT_SCREENSHOT_TIMEOUT_MS,
    screenshot_max: int = DEFAULT_SCREENSHOT_MAX,
    recovery_token: str | None = None,
) -> None:
    repo = SQLiteRepository(db_path)
    pending_results: list[PortResult] = []

    def flush_results() -> None:
        if not pending_results:
            return
        repo.add_port_results(pending_results)
        pending_results.clear()

    started = (
        repo.mark_recovered_scan_started(scan_id, recovery_token)
        if recovery_token is not None
        else repo.mark_scan_started(scan_id)
    )
    if not started:
        if repo.is_scan_cancel_requested(scan_id):
            repo.mark_scan_cancelled(scan_id, "cancelled before scan started")
        return
    if repo.is_scan_cancel_requested(scan_id):
        repo.mark_scan_cancelled(scan_id, "cancelled before scan started")
        return

    def on_event(event: dict[str, object]) -> None:
        if repo.is_scan_cancel_requested(scan_id):
            raise ScanCancelled(f"scan cancelled: {scan_id}")
        if event.get("event") != "port":
            return
        from .engine import _port_result_from_event

        pending_results.append(_port_result_from_event(event))
        if len(pending_results) >= 250:
            flush_results()
        if repo.is_scan_cancel_requested(scan_id):
            flush_results()
            raise ScanCancelled(f"scan cancelled: {scan_id}")

    try:
        completed_keys = repo.get_result_keys(scan_id, protocol=settings.protocol)
        pending_groups = _group_pending_scan_work(targets, ports, completed_keys)
        for pending_ports, pending_targets in pending_groups:
            if repo.is_scan_cancel_requested(scan_id):
                raise ScanCancelled(f"scan cancelled: {scan_id}")
            run_scan(
                scan_id=scan_id,
                targets=pending_targets,
                ports=pending_ports,
                target_expr=normalize_targets_expr(pending_targets),
                port_expr=normalize_ports_expr(pending_ports),
                settings=settings,
                on_event=on_event,
                collect_results=False,
                should_stop=lambda: repo.is_scan_cancel_requested(scan_id),
            )
        flush_results()
        if repo.is_scan_cancel_requested(scan_id):
            repo.mark_scan_cancelled(scan_id)
        else:
            if capture_screenshots:
                stored_results = repo.get_automatic_evidence_candidates(
                    scan_id,
                    limit=screenshot_max,
                )

                def store_screenshot(
                    result: Mapping[str, Any],
                    data: bytes,
                    file_name: str,
                    source_url: str | None,
                    evidence_type: str,
                ) -> None:
                    repo.add_result_evidence(
                        scan_id,
                        host=str(result["host"]),
                        port=int(result["port"]),
                        protocol=str(result["protocol"]),
                        data=data,
                        file_name=file_name,
                        evidence_type=evidence_type,
                        source_url=source_url,
                    )

                capture_automatic_evidence(
                    stored_results,
                    store=store_screenshot,
                    timeout_ms=screenshot_timeout_ms,
                    maximum=screenshot_max,
                    should_stop=lambda: repo.is_scan_cancel_requested(scan_id),
                )
            if repo.is_scan_cancel_requested(scan_id):
                repo.mark_scan_cancelled(scan_id)
            else:
                repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))
    except ScanCancelled as exc:
        flush_results()
        repo.mark_scan_cancelled(scan_id, str(exc))
    except Exception as exc:  # noqa: BLE001
        flush_results()
        repo.fail_scan(scan_id, str(exc))


def _model_dump(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _model_fields_set(model: BaseModel) -> set[str]:
    fields = getattr(model, "model_fields_set", None)
    if fields is not None:
        return set(fields)
    return set(getattr(model, "__fields_set__", set()))


def _scan_params(request: ScanCreateRequest, options: dict[str, Any]) -> dict[str, Any]:
    params = _model_dump(request)
    params.update(
        {
            "ports": options["ports"],
            "ports_file": options["ports_file"],
            "exclude": list(options["exclude"]),
            "port_profile": options["port_profile"],
            "top_ports": options["top_ports"],
            "scope": list(options["scope"]),
            "timeout_ms": options["timeout_ms"],
            "concurrency": options["concurrency"],
            "rate_limit_per_sec": options["rate_limit_per_sec"],
            "udp_retries": options["udp_retries"],
            "service_probe": options["service_probe"],
            "protocol": options["protocol"],
            "max_hosts": options["max_hosts"],
            "max_attempts": options["max_attempts"],
            "workload": options.get("workload"),
            "config_path": options["config_path"],
            "config_env": options["config_env"],
            "plugins": list(options.get("plugins", ())),
            "resumable": True,
        }
    )
    return params


def _group_pending_scan_work(
    targets: list[IPAddress],
    ports: list[int],
    completed_keys: set[tuple[str, int]],
) -> list[tuple[list[int], list[IPAddress]]]:
    ordered_ports = list(dict.fromkeys(int(port) for port in ports))
    groups: dict[tuple[int, ...], list[IPAddress]] = {}
    for target in targets:
        host = str(target)
        missing = tuple(port for port in ordered_ports if (host, port) not in completed_keys)
        if missing:
            groups.setdefault(missing, []).append(target)
    return [(list(group_ports), group_targets) for group_ports, group_targets in groups.items()]


def _start_scan_recovery(db_path) -> list[threading.Thread]:
    if resolve_engine_path() is None:
        return []
    repo = SQLiteRepository(db_path)
    threads: list[threading.Thread] = []
    for job in repo.list_recoverable_scan_jobs():
        scan_id = str(job["id"])
        if job["status"] == "cancel_requested":
            repo.mark_scan_cancelled(scan_id, "cancelled during application restart")
            continue
        recovery_token = repo.claim_scan_for_recovery(
            scan_id,
            status=str(job["status"]),
            worker_token=job.get("_worker_token"),
        )
        if recovery_token is None:
            continue
        try:
            params = job["params"]
            targets, _ = resolve_targets(
                targets=str(job["targets"]),
                max_hosts=int(params.get("max_hosts", 65536)),
            )
            ports, _ = resolve_ports(ports=str(job["ports"]))
            settings = EngineSettings(
                timeout_ms=int(params.get("timeout_ms", 800)),
                concurrency=int(params.get("concurrency", 2000)),
                rate_limit_per_sec=int(params.get("rate_limit_per_sec", 5000)),
                service_probe=bool(params.get("service_probe", True)),
                protocol=str(params.get("protocol", "tcp")),
                udp_retries=int(params.get("udp_retries", DEFAULT_UDP_RETRIES)),
                plugin_paths=tuple(str(path) for path in params.get("plugins", ())),
            )
            thread = threading.Thread(
                target=_run_scan_job,
                args=(
                    str(repo.path),
                    scan_id,
                    targets,
                    ports,
                    settings,
                    bool(params.get("capture_screenshots", False)),
                    int(params.get("screenshot_timeout_ms", DEFAULT_SCREENSHOT_TIMEOUT_MS)),
                    int(params.get("screenshot_max", DEFAULT_SCREENSHOT_MAX)),
                    recovery_token,
                ),
                name=f"netroach-recovery-{scan_id[:8]}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        except Exception as exc:  # noqa: BLE001 - corrupt legacy jobs must not block API startup.
            repo.fail_scan(scan_id, f"scan recovery failed: {exc}")
    return threads


def _merge_scope_values(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for value in group:
            normalized = value.strip()
            if normalized and normalized not in seen:
                merged.append(normalized)
                seen.add(normalized)
    return merged


def _validate_result_query(
    *,
    limit: int,
    offset: int,
    open_only: bool,
    state: str | None,
    protocol: str | None,
    host: str | None,
    search: str | None,
) -> None:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must be at least 0")
    if state and state not in RESULT_STATES:
        raise ValueError("state must be one of: open, closed, open|filtered, filtered, error")
    if protocol and protocol not in RESULT_PROTOCOLS:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    if open_only and state and state != "open":
        raise ValueError("open_only can only be combined with state=open")
    if host and len(host) > 255:
        raise ValueError("host must be 255 characters or fewer")
    if search and len(search) > 200:
        raise ValueError("search must be 200 characters or fewer")


def _validate_limit_offset(*, limit: int, offset: int) -> None:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must be at least 0")


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail={"error": str(exc)})


def _not_found(message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"error": message})
