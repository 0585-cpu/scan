from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .auth import require_active_authorization, resolve_api_token
from .config import load_config, resolve_scan_options
from .constants import RESULT_PROTOCOLS, RESULT_STATES
from .diagnostics import collect_diagnostics
from .engine import run_scan
from .evidence import (
    DEFAULT_SCREENSHOT_MAX,
    DEFAULT_SCREENSHOT_TIMEOUT_MS,
    ScreenshotCaptureSummary,
    capture_automatic_evidence,
)
from .exporters import (
    RESULT_EXPORT_FIELDS,
    format_results_csv,
    format_results_csv_bundle,
    format_results_json,
    format_results_ndjson,
    format_results_xlsx,
)
from .live_capture import LiveCaptureRequest, execute_live_capture
from .models import EngineSettings, PacketRequest, public_result_dicts
from .packet_sender import execute_packet_request
from .pcap import analyze_pcap
from .plugins import load_effective_plugin_catalog, load_plugin_manifest
from .reports import REPORT_FORMATS, build_scan_report, embed_report_evidence, format_scan_report
from .scan_inputs import PORT_PROFILES, resolve_ports, resolve_targets, validate_scan_workload
from .storage import SQLiteRepository
from .version import APP_NAME, __version__

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI should convert failures to concise stderr.
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME)
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run an authorized TCP or UDP port scan")
    add_db_arg(scan)
    add_config_args(scan)
    add_scope_args(scan)
    scan.add_argument("--targets", help="comma-separated IP/CIDR targets")
    scan.add_argument("--targets-file", help="file with IP/CIDR targets, one per line or comma-separated")
    scan.add_argument("--exclude", action="append", default=[], help="IP/CIDR to exclude from expanded targets; repeatable")
    scan.add_argument("--ports", help="ports such as 22,80,443 or 1-1024")
    scan.add_argument("--ports-file", help="file with ports/ranges, one per line or comma-separated")
    scan.add_argument("--profile", dest="port_profile", help=f"named port profile; built-ins: {', '.join(sorted(PORT_PROFILES))}")
    scan.add_argument("--top-ports", type=int, help="include the first N built-in common ports")
    scan.add_argument("--protocol", choices=["tcp", "udp"], help="scan protocol")
    scan.add_argument("--timeout-ms", type=int, help="per-port timeout in milliseconds")
    scan.add_argument("--concurrency", type=int, help="maximum simultaneous scan attempts")
    scan.add_argument("--rate-limit-per-sec", type=int, help="maximum scan starts per second")
    scan.add_argument("--udp-retries", type=int, choices=range(0, 4), help="UDP retries after the initial probe (0-3)")
    scan.add_argument("--no-service-probe", action="store_true", help="disable service fingerprint probes")
    scan.add_argument(
        "--capture-evidence",
        dest="capture_evidence",
        action="store_true",
        help="capture web screenshots and PowerShell terminal evidence for other discovered services",
    )
    scan.add_argument(
        "--screenshot-timeout-ms",
        type=int,
        default=DEFAULT_SCREENSHOT_TIMEOUT_MS,
        help="browser navigation or PowerShell diagnostic timeout per evidence item",
    )
    scan.add_argument(
        "--screenshot-max",
        type=int,
        default=DEFAULT_SCREENSHOT_MAX,
        help="maximum automatic evidence images captured for this scan (1-100)",
    )
    scan.add_argument("--max-hosts", type=int, help="maximum expanded host count")
    scan.add_argument("--max-attempts", type=int, help="maximum host x port attempts before extra confirmation")
    scan.add_argument(
        "--confirm-large-scan",
        action="store_true",
        help="explicitly confirm a scan that exceeds max-attempts",
    )
    scan.add_argument("--engine-path", help="path to scaprobe-engine; defaults to auto-discovery")
    scan.add_argument("--json", action="store_true", help="emit JSON")
    scan.set_defaults(func=cmd_scan)

    pcap = subparsers.add_parser("pcap", help="summarize a pcap or pcapng file")
    add_db_arg(pcap)
    pcap.add_argument("file", help="pcap or pcapng file path")
    pcap.add_argument("--top", type=int, default=10, help="number of top talkers/conversations")
    pcap.add_argument("--json", action="store_true", help="emit JSON")
    pcap.set_defaults(func=cmd_pcap)

    capture = subparsers.add_parser("capture", help="run a bounded authorized live packet capture")
    add_db_arg(capture)
    capture.add_argument("--output", required=True, help="output pcap file path")
    capture.add_argument("--duration-s", type=float, help="capture duration in seconds")
    capture.add_argument("--count", type=int, help="maximum packet count")
    capture.add_argument("--iface", "--interface", dest="iface", help="capture interface name")
    capture.add_argument("--filter", dest="bpf_filter", help="optional BPF capture filter")
    capture.add_argument("--top", type=int, default=10, help="number of top pcap analysis entries")
    capture.add_argument("--no-analyze", action="store_true", help="skip automatic pcap analysis")
    capture.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="confirm you are authorized to capture traffic on this interface",
    )
    capture.add_argument("--json", action="store_true", help="emit JSON")
    capture.set_defaults(func=cmd_capture)

    send = subparsers.add_parser("send", help="send authorized template-based packets")
    send_sub = send.add_subparsers(dest="template", required=True)
    for template in ("icmp", "udp", "tcp", "dns", "http"):
        sub = send_sub.add_parser(template, help=f"send {template} template traffic")
        add_db_arg(sub)
        add_send_common_args(sub)
        if template in {"udp", "tcp", "dns", "http"}:
            sub.add_argument("--dport", type=int, help="destination port")
        if template in {"udp", "tcp"}:
            sub.add_argument("--sport", type=int, help="source port")
        if template == "tcp":
            sub.add_argument("--flags", default="S", help="TCP flags, default SYN")
        if template == "dns":
            sub.add_argument("--dns-name", required=True, help="DNS query name")
        if template == "http":
            sub.add_argument("--http-method", default="GET", help="HTTP method")
            sub.add_argument("--http-path", default="/", help="HTTP path")
            sub.add_argument("--http-host", help="HTTP Host header")
        sub.set_defaults(func=cmd_send)

    serve = subparsers.add_parser("serve", help="start the local REST API")
    add_db_arg(serve)
    add_config_args(serve)
    serve.add_argument("--host", default="127.0.0.1", help="bind host")
    serve.add_argument("--port", type=int, default=8765, help="bind port")
    serve.add_argument(
        "--api-token",
        help="require this bearer token; generated automatically for non-loopback binds",
    )
    serve.add_argument("--check", action="store_true", help="print startup diagnostics and exit")
    serve.set_defaults(func=cmd_serve)

    desktop = subparsers.add_parser("desktop", help="start the local dashboard in desktop mode")
    add_db_arg(desktop)
    add_config_args(desktop)
    desktop.add_argument("--host", default="127.0.0.1", help="bind host")
    desktop.add_argument("--port", type=int, default=8765, help="bind port; defaults to 8765, use 0 for a free port")
    desktop.add_argument(
        "--api-token",
        help="require this bearer token; generated automatically for non-loopback binds",
    )
    desktop.add_argument("--no-open", action="store_true", help="do not open the dashboard in a browser")
    desktop.set_defaults(func=cmd_desktop)

    diagnostics = subparsers.add_parser("diagnostics", help="print startup diagnostics and exit")
    add_db_arg(diagnostics)
    diagnostics.set_defaults(func=cmd_diagnostics)

    plugins = subparsers.add_parser("plugins", help="inspect data plugins")
    plugins_sub = plugins.add_subparsers(dest="plugins_command", required=True)
    plugins_list = plugins_sub.add_parser("list", help="list loaded plugin manifests")
    add_config_args(plugins_list)
    plugins_list.add_argument("--json", action="store_true")
    plugins_list.set_defaults(func=cmd_plugins_list)
    plugins_validate = plugins_sub.add_parser("validate", help="validate one plugin manifest")
    plugins_validate.add_argument("file")
    plugins_validate.add_argument("--json", action="store_true")
    plugins_validate.set_defaults(func=cmd_plugins_validate)

    export = subparsers.add_parser("export", help="export stored scan results")
    add_db_arg(export)
    export.add_argument("scan_id")
    export.add_argument("--format", choices=["json", "csv", "ndjson", "xlsx"], default="json")
    export.add_argument("--output", help="output file path; stdout if omitted")
    export.add_argument("--limit", type=int, default=1_000_000)
    export.add_argument("--offset", type=int, default=0)
    export.add_argument("--open-only", action="store_true")
    export.add_argument("--state", choices=RESULT_STATES)
    export.add_argument("--protocol", choices=RESULT_PROTOCOLS)
    export.add_argument("--service", help="filter by exact service name")
    export.add_argument(
        "--bundle-evidence",
        action="store_true",
        help="write a ZIP containing results.csv and attached image files; requires --format csv --output",
    )
    export.set_defaults(func=cmd_export)

    report = subparsers.add_parser("report", help="generate a stored scan report")
    add_db_arg(report)
    report.add_argument("scan_id")
    report.add_argument("--format", choices=sorted(REPORT_FORMATS), default="html")
    report.add_argument("--output", help="output file path; stdout if omitted")
    report.add_argument("--limit", type=int, default=1_000_000)
    report.add_argument(
        "--embed-evidence",
        action="store_true",
        help="embed up to 50 MB of image evidence in an HTML report for offline viewing",
    )
    report.set_defaults(func=cmd_report)

    return parser


def add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", help="SQLite database path")


def add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="scaprobe.toml path; defaults to ./scaprobe.toml or user config directory")
    parser.add_argument("--env", dest="config_env", help="config environment such as local, lab, or corp")
    parser.add_argument("--plugin", action="append", default=[], help="JSON plugin manifest or directory; repeatable")


def add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", action="append", default=[], help="authorized CIDR range; repeatable")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="confirm you are authorized to actively test these targets",
    )


def add_send_common_args(parser: argparse.ArgumentParser) -> None:
    add_scope_args(parser)
    parser.add_argument("--target", required=True, help="destination IP")
    parser.add_argument("--count", type=int, default=1, help="number of packets/requests")
    parser.add_argument("--interval-ms", type=int, default=1000, help="milliseconds between packets/requests")
    parser.add_argument("--payload-text", help="UTF-8 payload text")
    parser.add_argument("--payload-base64", help="base64 payload")
    parser.add_argument("--dry-run", action="store_true", help="validate and preview without sending traffic")
    parser.add_argument("--json", action="store_true", help="emit JSON")


def cmd_scan(args: argparse.Namespace) -> int:
    if args.capture_evidence:
        if not 1_000 <= args.screenshot_timeout_ms <= 30_000:
            raise ValueError("screenshot timeout must be between 1000 and 30000 milliseconds")
        if not 1 <= args.screenshot_max <= 100:
            raise ValueError("screenshot maximum must be between 1 and 100")
    config = load_config(args.config)
    plugin_catalog = load_effective_plugin_catalog(config, args.plugin)
    plugin_paths = tuple(plugin.path for plugin in plugin_catalog.plugins if plugin.path)
    options = resolve_scan_options(
        config=config,
        env=args.config_env,
        values=vars(args),
        explicit_fields=cli_explicit_scan_fields(args),
        disable_service_probe=args.no_service_probe,
    )
    scope = require_active_authorization(args.confirm_authorized, options["scope"])
    targets, target_expr = resolve_targets(
        targets=args.targets,
        targets_file=args.targets_file,
        exclude=options["exclude"],
        max_hosts=options["max_hosts"],
    )
    scope.require_targets(targets)
    ports, port_expr = resolve_ports(
        ports=options["ports"],
        ports_file=options["ports_file"],
        port_profile=options["port_profile"],
        top_ports=options["top_ports"],
        port_profiles={**config.port_profiles, **plugin_catalog.port_profiles},
    )
    workload = validate_scan_workload(
        targets,
        ports,
        max_attempts=int(options["max_attempts"]),
        confirm_large_scan=args.confirm_large_scan,
    )

    repo = SQLiteRepository(args.db)
    settings = EngineSettings(
        timeout_ms=options["timeout_ms"],
        concurrency=options["concurrency"],
        rate_limit_per_sec=options["rate_limit_per_sec"],
        service_probe=options["service_probe"],
        protocol=options["protocol"],
        udp_retries=options["udp_retries"],
        plugin_paths=plugin_paths,
    )
    scan_id = repo.create_scan_job(
        targets=target_expr,
        ports=port_expr,
        scope=list(options["scope"]),
        params={
            **asdict(settings),
            "max_hosts": options["max_hosts"],
            "max_attempts": options["max_attempts"],
            "workload": workload,
            "confirm_large_scan": args.confirm_large_scan,
            "targets_file": args.targets_file,
            "ports_file": options["ports_file"],
            "exclude": list(options["exclude"]),
            "port_profile": options["port_profile"],
            "top_ports": options["top_ports"],
            "config_path": options["config_path"],
            "config_env": options["config_env"],
            "plugins": plugin_paths,
            "capture_screenshots": args.capture_evidence,
            "screenshot_timeout_ms": args.screenshot_timeout_ms,
            "screenshot_max": args.screenshot_max,
        },
    )
    repo.mark_scan_started(scan_id)
    try:
        results, summary = run_scan(
            scan_id=scan_id,
            targets=targets,
            ports=ports,
            target_expr=target_expr,
            port_expr=port_expr,
            settings=settings,
            engine_path=args.engine_path,
        )
        repo.add_port_results(results)
        screenshot_summary = _capture_scan_evidence(repo, scan_id, args)
        repo.complete_scan(scan_id, summary)
    except Exception as exc:  # noqa: BLE001
        repo.fail_scan(scan_id, str(exc))
        raise

    if args.json:
        stored_results = repo.get_results(scan_id, limit=max(1, len(results)))
        print(
            json.dumps(
                {
                    "scan_id": scan_id,
                    "summary": summary.to_dict(),
                    "results": public_result_dicts(stored_results),
                },
                indent=2,
            )
        )
    else:
        print(f"scan_id: {scan_id}")
        print(f"scanned {len(targets)} hosts x {len(ports)} ports over {settings.protocol}")
        print_summary(summary.to_dict())
        open_results = [result for result in results if result.state == "open"]
        for result in open_results:
            service = f" {result.service_name}" if result.service_name else ""
            print(f"OPEN {result.host}:{result.port}/{result.protocol}{service}")
        if not open_results:
            print("no open ports found")
        if screenshot_summary and screenshot_summary.candidates:
            print(
                f"evidence: {screenshot_summary.captured} captured "
                f"(web={screenshot_summary.web_screenshots}, "
                f"terminal={screenshot_summary.terminal_transcripts}), "
                f"{screenshot_summary.failed} failed"
            )
    return 0


def _capture_scan_evidence(
    repo: SQLiteRepository,
    scan_id: str,
    args: argparse.Namespace,
) -> ScreenshotCaptureSummary | None:
    if not args.capture_evidence:
        return None
    stored_results = repo.get_automatic_evidence_candidates(scan_id, limit=args.screenshot_max)

    def store_screenshot(
        result: dict[str, Any],
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

    summary = capture_automatic_evidence(
        stored_results,
        store=store_screenshot,
        timeout_ms=args.screenshot_timeout_ms,
        maximum=args.screenshot_max,
    )
    for error in summary.errors:
        print(f"warning: automatic evidence: {error}", file=sys.stderr)
    return summary


def cli_explicit_scan_fields(args: argparse.Namespace) -> set[str]:
    explicit: set[str] = set()
    for field in (
        "ports",
        "ports_file",
        "port_profile",
        "top_ports",
        "timeout_ms",
        "concurrency",
        "rate_limit_per_sec",
        "udp_retries",
        "protocol",
        "max_hosts",
        "max_attempts",
    ):
        if getattr(args, field, None) is not None:
            explicit.add(field)
    if getattr(args, "scope", None):
        explicit.add("scope")
    if getattr(args, "exclude", None):
        explicit.add("exclude")
    if getattr(args, "no_service_probe", False):
        explicit.add("service_probe")
    return explicit


def cmd_pcap(args: argparse.Namespace) -> int:
    summary = analyze_pcap(args.file, top=args.top)
    analysis_id = SQLiteRepository(args.db).save_pcap_analysis(args.file, summary.to_dict())
    if args.json:
        print(json.dumps({"analysis_id": analysis_id, "summary": summary.to_dict()}, indent=2))
    else:
        print(f"analysis_id: {analysis_id}")
        print(f"file: {summary.file}")
        print(f"packets: {summary.packet_count}")
        if summary.first_ts is not None and summary.last_ts is not None:
            print(f"duration: {round(summary.last_ts - summary.first_ts, 3)}s")
        print_map("protocols", summary.protocols)
        print_pairs("top talkers", summary.top_talkers)
        print_pairs("conversations", summary.conversations)
        print_json_list("conversation metrics", summary.conversation_metrics)
        print_list("dns queries", summary.dns_queries)
        print_result_group("dns responses", summary.dns_responses)
        print_list("http hosts", summary.http_hosts)
        print_list("http user agents", summary.http_user_agents)
        print_list("http status lines", summary.http_status_lines)
        print_json_list("tls metadata", summary.tls_metadata)
        print_map("arp", summary.arp_summary)
        print_map("icmp", summary.icmp_summary)
        print_map("dhcp", summary.dhcp_messages)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    request = LiveCaptureRequest(
        output=args.output,
        confirm_authorized=args.confirm_authorized,
        duration_s=args.duration_s,
        count=args.count,
        iface=args.iface,
        bpf_filter=args.bpf_filter,
        analyze=not args.no_analyze,
        top=args.top,
    )
    result = execute_live_capture(request)
    analysis_id = None
    if result.analysis:
        analysis_id = SQLiteRepository(args.db).save_pcap_analysis(result.file, result.analysis)
    if args.json:
        print(json.dumps({"analysis_id": analysis_id, "capture": result.to_dict()}, indent=2))
    else:
        print(f"file: {result.file}")
        print(f"packets: {result.packet_count}")
        print(f"duration: {result.duration_s}s")
        if analysis_id:
            print(f"analysis_id: {analysis_id}")
        if result.analysis_error:
            print(f"analysis_error: {result.analysis_error}")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    request = PacketRequest(
        template=args.template,
        target=args.target,
        scope=args.scope,
        confirm_authorized=args.confirm_authorized,
        count=args.count,
        interval_ms=args.interval_ms,
        dport=getattr(args, "dport", None),
        sport=getattr(args, "sport", None),
        flags=getattr(args, "flags", "S"),
        payload_text=args.payload_text,
        payload_base64=args.payload_base64,
        dns_name=getattr(args, "dns_name", None),
        http_method=getattr(args, "http_method", "GET"),
        http_path=getattr(args, "http_path", "/"),
        http_host=getattr(args, "http_host", None),
        dry_run=args.dry_run,
    )
    result = execute_packet_request(request)
    audit_id = SQLiteRepository(args.db).save_packet_audit(request=asdict(request), result=result)
    if args.json:
        print(json.dumps({"audit_id": audit_id, "result": result.to_dict()}, indent=2))
    else:
        print(f"audit_id: {audit_id}")
        print_result(result.to_dict())
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    if args.check:
        payload = diagnostics_payload(args.db)
        config = load_config(args.config)
        payload["plugins"] = load_effective_plugin_catalog(config, args.plugin).to_dict()
        print(json.dumps(payload, indent=2))
        return 0
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("serve requires FastAPI dependencies. Install with: pip install -e .") from exc
    from .api import create_app

    api_token = resolve_api_token(getattr(args, "api_token", None), args.host)
    if api_token:
        print(f"Scaprobe API token: {api_token}")
        print(f"Dashboard: http://{args.host}:{args.port}/dashboard?token={api_token}")
    uvicorn.run(
        create_app(
            args.db,
            config_path=args.config,
            config_env=args.config_env,
            plugin_paths=args.plugin,
            api_token=api_token,
        ),
        host=args.host,
        port=args.port,
    )
    return 0


def cmd_desktop(args: argparse.Namespace) -> int:
    from .desktop import DesktopSettings, run_desktop

    return run_desktop(
        DesktopSettings(
            host=args.host,
            port=args.port,
            db_path=args.db,
            config_path=args.config,
            config_env=args.config_env,
            plugin_paths=tuple(args.plugin),
            open_browser=not args.no_open,
            api_token=getattr(args, "api_token", None),
        )
    )


def cmd_diagnostics(args: argparse.Namespace) -> int:
    print(json.dumps(diagnostics_payload(args.db), indent=2))
    return 0


def diagnostics_payload(db_path: str | None = None) -> dict[str, object]:
    diagnostics = collect_diagnostics().to_dict()
    if db_path:
        diagnostics["database_path"] = str(SQLiteRepository(db_path).path)
    return diagnostics


def cmd_plugins_list(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    catalog = load_effective_plugin_catalog(config, args.plugin)
    payload = catalog.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if not catalog.plugins:
            print("no plugins loaded")
            return 0
        for plugin in catalog.plugins:
            print(f"{plugin.name} {plugin.version} {plugin.path or ''}")
        if catalog.port_profiles:
            print("port_profiles: " + ", ".join(sorted(catalog.port_profiles)))
        if catalog.has_runtime_fingerprints:
            print("runtime_fingerprints: true")
    return 0


def cmd_plugins_validate(args: argparse.Namespace) -> int:
    plugin = load_plugin_manifest(args.file)
    payload = plugin.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"valid: {plugin.name} {plugin.version}")
        print(f"port_profiles: {len(plugin.port_profiles)}")
        print(f"tcp_services: {len(plugin.tcp_services)}")
        print(f"udp_services: {len(plugin.udp_services)}")
        print(f"tcp_banner_rules: {len(plugin.tcp_banner_rules)}")
        print(f"udp_response_rules: {len(plugin.udp_response_rules)}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    repo = SQLiteRepository(args.db)
    job = repo.get_job(args.scan_id)
    if not job:
        raise ValueError(f"scan not found: {args.scan_id}")
    validate_result_query_args(args)
    results = repo.get_results(
        args.scan_id,
        limit=args.limit,
        offset=args.offset,
        open_only=args.open_only,
        state=args.state,
        protocol=args.protocol,
        service=args.service,
    )
    if args.bundle_evidence:
        if args.format != "csv":
            raise ValueError("--bundle-evidence requires --format csv")
        if not args.output:
            raise ValueError("--bundle-evidence requires --output with a .zip path")
        bundle = format_results_csv_bundle(
            job,
            results,
            load_evidence=repo.get_evidence_content,
        )
        Path(args.output).write_bytes(bundle)
        return 0
    if args.format == "xlsx":
        if not args.output:
            raise ValueError("--format xlsx requires --output")
        workbook = format_results_xlsx(
            job,
            results,
            load_evidence=repo.get_evidence_content,
        )
        Path(args.output).write_bytes(workbook)
        return 0
    if args.format == "json":
        text = format_results_json(job, results)
    elif args.format == "csv":
        text = format_results_csv(results)
    else:
        text = format_results_ndjson(job, results)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    repo = SQLiteRepository(args.db)
    job = repo.get_job(args.scan_id)
    if not job:
        raise ValueError(f"scan not found: {args.scan_id}")
    results = repo.get_report_results(args.scan_id, limit=args.limit)
    counts = repo.summarize_report_counts(args.scan_id)
    report = build_scan_report(
        job,
        results,
        total_result_count=counts["total"],
        counts=counts,
        host_summaries=repo.summarize_results_by_host(args.scan_id),
    )
    if args.embed_evidence:
        if args.format != "html":
            raise ValueError("--embed-evidence requires --format html")
        embed_report_evidence(report, repo.get_evidence_content)
    text = format_scan_report(report, args.format)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    return 0


def validate_result_query_args(args: argparse.Namespace) -> None:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.offset < 0:
        raise ValueError("--offset must be at least 0")
    if args.open_only and args.state and args.state != "open":
        raise ValueError("--open-only can only be combined with --state open")


def print_summary(summary: dict[str, Any]) -> None:
    print(
        "summary: "
        f"total={summary.get('total', 0)} "
        f"open={summary.get('open', 0)} "
        f"closed={summary.get('closed', 0)} "
        f"open|filtered={summary.get('open_filtered', 0)} "
        f"filtered={summary.get('filtered', 0)} "
        f"error={summary.get('error', 0)}"
    )


def print_result(data: dict[str, Any]) -> None:
    for key, value in data.items():
        print(f"{key}: {value}")


def print_map(title: str, values: dict[str, int]) -> None:
    if not values:
        return
    print(f"{title}:")
    for key, value in values.items():
        print(f"  {key}: {value}")


def print_result_group(title: str, values: dict[str, Any]) -> None:
    if not values:
        return
    print(f"{title}:")
    for key, value in values.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for nested_key, nested_value in value.items():
                print(f"    {nested_key}: {nested_value}")
        else:
            print(f"  {key}: {value}")


def print_pairs(title: str, values: list[tuple[str, int]]) -> None:
    if not values:
        return
    print(f"{title}:")
    for key, value in values:
        print(f"  {key}: {value}")


def print_list(title: str, values: list[str]) -> None:
    if not values:
        return
    print(f"{title}:")
    for value in values:
        print(f"  {value}")


def print_json_list(title: str, values: list[dict[str, Any]]) -> None:
    if not values:
        return
    print(f"{title}:")
    for value in values:
        print(f"  {json.dumps(value, sort_keys=True)}")


if __name__ == "__main__":
    raise SystemExit(main())
