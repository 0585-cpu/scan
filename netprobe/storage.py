from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import uuid
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .evidence import detect_image_media_type, image_extension, safe_original_name
from .models import PortResult, ScanSummary, SendResult
from .oast import new_oast_token
from .ports import parse_ports
from .scope import parse_target_expr


SCHEMA_VERSION = 8
PORT_RESULT_INSERT_SQL = """
    INSERT INTO port_results(
        scan_id, host, port, protocol, state, latency_ms,
        service_name, service_confidence, banner, evidence, error, tags_json, note
    )
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _port_result_values(result: PortResult) -> tuple[Any, ...]:
    return (
        result.scan_id,
        result.host,
        result.port,
        result.protocol,
        result.state,
        result.latency_ms,
        result.service_name,
        result.service_confidence,
        result.banner,
        result.evidence,
        result.error,
        json.dumps(result.tags),
        result.note,
    )


def default_db_path() -> Path:
    system = platform.system().lower()
    if system == "windows":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "Scaprobe" / "scaprobe.db"
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / "scaprobe" / "scaprobe.db"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "scaprobe" / "scaprobe.db"


class SQLiteRepository:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # Streaming scan results commits often. The rollback journal forces a
        # disk flush per commit, which is the slowest thing this app does on a
        # spinning disk or a cheap SSD. WAL keeps readers (dashboard polling,
        # recovery threads) from blocking the writer; synchronous=NORMAL drops
        # the per-commit flush. A machine crash can then lose the most recent
        # commits - never the database itself, and never on a process crash.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @property
    def evidence_root(self) -> Path:
        return self.path.parent / f"{self.path.stem}-artifacts"

    @contextmanager
    def session(self) -> Iterable[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init(self) -> None:
        with self.session() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    started_at TEXT,
                    completed_at TEXT,
                    summary_json TEXT,
                    worker_token TEXT
                );
                CREATE TABLE IF NOT EXISTS port_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    latency_ms REAL,
                    service_name TEXT,
                    service_confidence REAL,
                    banner TEXT,
                    evidence TEXT,
                    error TEXT,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    note TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_port_results_scan ON port_results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_port_results_host ON port_results(host);
                -- Result pages are always "one scan, ordered by host then port".
                -- Without this the whole filtered set is sorted in a temporary
                -- b-tree for every page, which is what hurts on a slow disk.
                CREATE INDEX IF NOT EXISTS idx_port_results_scan_host_port
                    ON port_results(scan_id, host, port);
                CREATE TABLE IF NOT EXISTS result_evidence_files (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    source_url TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_result_evidence_target
                ON result_evidence_files(scan_id, host, port, protocol);
                CREATE TABLE IF NOT EXISTS pcap_analyses (
                    id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS packet_audit (
                    id TEXT PRIMARY KEY,
                    template TEXT NOT NULL,
                    target TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS oast_sessions (
                    id TEXT PRIMARY KEY,
                    token TEXT NOT NULL UNIQUE,
                    label TEXT,
                    base_url TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS oast_interactions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT NOT NULL DEFAULT '',
                    client_host TEXT,
                    headers_json TEXT NOT NULL,
                    body_preview TEXT,
                    body_truncated INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(session_id) REFERENCES oast_sessions(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_oast_interactions_session ON oast_interactions(session_id);
                """
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        job_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scan_jobs)").fetchall()}
        if "worker_token" not in job_columns:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN worker_token TEXT")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(port_results)").fetchall()}
        if "evidence" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN evidence TEXT")
        if "tags_json" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'")
        if "note" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN note TEXT")
        conn.execute(
            """
            DELETE FROM port_results
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM port_results
                GROUP BY scan_id, host, port, protocol
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_port_results_unique
            ON port_results(scan_id, host, port, protocol)
            """
        )

    def create_scan_job(self, *, targets: str, ports: str, scope: list[str], params: dict[str, Any]) -> str:
        scan_id = str(uuid.uuid4())
        with self.session() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs(id, status, targets, ports, scope_json, params_json)
                VALUES(?, 'queued', ?, ?, ?, ?)
                """,
                (scan_id, targets, ports, json.dumps(scope), json.dumps(params)),
            )
        return scan_id

    def mark_scan_started(self, scan_id: str) -> bool:
        with self.session() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status='running', started_at=COALESCE(started_at, CURRENT_TIMESTAMP),
                    completed_at=NULL, worker_token=NULL
                WHERE id=? AND status='queued'
                """,
                (scan_id,),
            )
        return cursor.rowcount > 0

    def list_recoverable_scan_jobs(self) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, status, targets, ports, scope_json, params_json,
                       created_at, started_at, completed_at, summary_json, worker_token
                FROM scan_jobs
                WHERE status IN ('queued', 'running', 'recovering', 'cancel_requested')
                ORDER BY created_at ASC
                """
            ).fetchall()
        jobs: list[dict[str, Any]] = []
        for row in rows:
            job = self._scan_job_row_to_dict(row)
            if not job["params"].get("resumable"):
                continue
            job["_worker_token"] = row["worker_token"]
            jobs.append(job)
        return jobs

    def claim_scan_for_recovery(self, scan_id: str, *, status: str, worker_token: str | None) -> str | None:
        recovery_token = str(uuid.uuid4())
        with self.session() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status='recovering', worker_token=?, completed_at=NULL,
                    summary_json=?
                WHERE id=? AND status=? AND worker_token IS ?
                """,
                (
                    recovery_token,
                    json.dumps({"recovering": True}),
                    scan_id,
                    status,
                    worker_token,
                ),
            )
        return recovery_token if cursor.rowcount > 0 else None

    def mark_recovered_scan_started(self, scan_id: str, recovery_token: str) -> bool:
        with self.session() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status='running', started_at=COALESCE(started_at, CURRENT_TIMESTAMP)
                WHERE id=? AND status='recovering' AND worker_token=?
                """,
                (scan_id, recovery_token),
            )
        return cursor.rowcount > 0

    def complete_scan(self, scan_id: str, summary: ScanSummary) -> None:
        with self.session() as conn:
            stored_total = conn.execute(
                "SELECT COUNT(*) AS count FROM port_results WHERE scan_id=?",
                (scan_id,),
            ).fetchone()["count"]
            if int(stored_total) != summary.total:
                raise ValueError(
                    f"scan summary total mismatch for {scan_id}: "
                    f"summary={summary.total} stored_results={stored_total}"
                )
            conn.execute(
                """
                UPDATE scan_jobs
                SET status='completed', completed_at=CURRENT_TIMESTAMP, summary_json=?, worker_token=NULL
                WHERE id=?
                """,
                (json.dumps(summary.to_dict()), scan_id),
            )

    def fail_scan(self, scan_id: str, error: str) -> None:
        with self.session() as conn:
            conn.execute(
                """
                UPDATE scan_jobs
                SET status='failed', completed_at=CURRENT_TIMESTAMP, summary_json=?, worker_token=NULL
                WHERE id=?
                """,
                (json.dumps({"error": error}), scan_id),
            )

    def request_scan_cancel(self, scan_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                "SELECT status FROM scan_jobs WHERE id=?",
                (scan_id,),
            ).fetchone()
            if not row:
                return None
            status = row["status"]
            if status in {"queued", "running", "recovering"}:
                conn.execute(
                    """
                    UPDATE scan_jobs
                    SET status='cancel_requested', summary_json=?
                    WHERE id=?
                    """,
                    (json.dumps({"cancel_requested": True}), scan_id),
                )
            elif status == "cancel_requested":
                pass
            else:
                raise ValueError(f"scan cannot be cancelled from status: {status}")
        return self.get_job(scan_id)

    def is_scan_cancel_requested(self, scan_id: str) -> bool:
        with self.session() as conn:
            row = conn.execute("SELECT status FROM scan_jobs WHERE id=?", (scan_id,)).fetchone()
        return bool(row and row["status"] == "cancel_requested")

    def mark_scan_cancelled(self, scan_id: str, reason: str = "cancelled") -> None:
        summary = self.summarize_scan_results(scan_id).to_dict()
        summary["cancelled"] = True
        summary["reason"] = reason
        with self.session() as conn:
            conn.execute(
                """
                UPDATE scan_jobs
                SET status='cancelled', completed_at=CURRENT_TIMESTAMP, summary_json=?, worker_token=NULL
                WHERE id=?
                """,
                (json.dumps(summary), scan_id),
            )

    def delete_scan(self, scan_id: str) -> bool:
        with self.session() as conn:
            cursor = conn.execute("DELETE FROM scan_jobs WHERE id=?", (scan_id,))
        deleted = cursor.rowcount > 0
        if deleted:
            self._remove_scan_evidence_directory(scan_id)
        return deleted

    def cleanup_scan_jobs(
        self,
        *,
        older_than_days: int,
        statuses: Iterable[str] | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if older_than_days < 1:
            raise ValueError("older_than_days must be at least 1")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).strftime("%Y-%m-%d %H:%M:%S")
        selected_statuses = tuple(statuses or ("completed", "failed", "cancelled"))
        if not selected_statuses:
            raise ValueError("at least one status is required")
        placeholders = ",".join("?" for _ in selected_statuses)
        params: list[Any] = [cutoff, *selected_statuses]
        with self.session() as conn:
            rows = conn.execute(
                f"""
                SELECT id, status, completed_at
                FROM scan_jobs
                WHERE completed_at IS NOT NULL
                  AND completed_at < ?
                  AND status IN ({placeholders})
                ORDER BY completed_at ASC
                """,
                params,
            ).fetchall()
            scan_ids = [row["id"] for row in rows]
            if scan_ids and not dry_run:
                delete_placeholders = ",".join("?" for _ in scan_ids)
                conn.execute(f"DELETE FROM scan_jobs WHERE id IN ({delete_placeholders})", scan_ids)
        if not dry_run:
            for scan_id in scan_ids:
                self._remove_scan_evidence_directory(scan_id)
        return {
            "older_than_days": older_than_days,
            "statuses": list(selected_statuses),
            "dry_run": dry_run,
            "count": len(scan_ids),
            "scan_ids": scan_ids,
        }

    def add_port_result(self, result: PortResult) -> None:
        self.add_port_results((result,))

    def add_port_results(self, results: Iterable[PortResult]) -> None:
        values = [_port_result_values(result) for result in results]
        if not values:
            return
        with self.session() as conn:
            conn.executemany(PORT_RESULT_INSERT_SQL, values)

    def add_result_evidence(
        self,
        scan_id: str,
        *,
        host: str,
        port: int,
        protocol: str = "tcp",
        data: bytes,
        file_name: str | None = None,
        evidence_type: str = "manual",
        source_url: str | None = None,
    ) -> dict[str, Any]:
        if evidence_type not in {"manual", "web_screenshot", "protocol_snapshot", "terminal_transcript"}:
            raise ValueError(
                "evidence type must be 'manual', 'web_screenshot', 'protocol_snapshot', or 'terminal_transcript'"
            )
        if not self.get_result(scan_id, host=host, port=port, protocol=protocol):
            raise ValueError(f"scan result not found: {scan_id} {host}:{port}/{protocol}")

        media_type = detect_image_media_type(data)
        safe_name = safe_original_name(file_name, media_type)
        evidence_id = str(uuid.uuid4())
        relative_path = Path(scan_id) / f"{evidence_id}{image_extension(media_type)}"
        destination = self._resolve_evidence_path(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(destination)
        digest = hashlib.sha256(data).hexdigest()

        try:
            with self.session() as conn:
                conn.execute(
                    """
                    INSERT INTO result_evidence_files(
                        id, scan_id, host, port, protocol, evidence_type, file_name,
                        stored_path, mime_type, size_bytes, sha256, source_url
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        scan_id,
                        host,
                        port,
                        protocol,
                        evidence_type,
                        safe_name,
                        relative_path.as_posix(),
                        media_type,
                        len(data),
                        digest,
                        source_url,
                    ),
                )
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        evidence = self.get_evidence_file(evidence_id)
        if evidence is None:  # pragma: no cover - insert and immediate select are atomic in normal operation.
            raise RuntimeError("failed to load stored evidence")
        return evidence

    def list_result_evidence(
        self,
        scan_id: str,
        *,
        host: str,
        port: int,
        protocol: str = "tcp",
    ) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, scan_id, host, port, protocol, evidence_type, file_name,
                       stored_path, mime_type, size_bytes, sha256, source_url, created_at
                FROM result_evidence_files
                WHERE scan_id=? AND host=? AND port=? AND protocol=?
                ORDER BY created_at, id
                """,
                (scan_id, host, port, protocol),
            ).fetchall()
        return [_evidence_file_row_to_dict(row) for row in rows]

    def get_evidence_file(self, evidence_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, scan_id, host, port, protocol, evidence_type, file_name,
                       stored_path, mime_type, size_bytes, sha256, source_url, created_at
                FROM result_evidence_files
                WHERE id=?
                """,
                (evidence_id,),
            ).fetchone()
        return _evidence_file_row_to_dict(row) if row else None

    def get_evidence_content(self, evidence_id: str) -> tuple[dict[str, Any], Path] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, scan_id, host, port, protocol, evidence_type, file_name,
                       stored_path, mime_type, size_bytes, sha256, source_url, created_at
                FROM result_evidence_files
                WHERE id=?
                """,
                (evidence_id,),
            ).fetchone()
        if not row:
            return None
        path = self._resolve_evidence_path(row["stored_path"])
        if not path.is_file():
            return None
        return _evidence_file_row_to_dict(row), path

    def delete_evidence_file(self, evidence_id: str) -> bool:
        with self.session() as conn:
            row = conn.execute(
                "SELECT stored_path FROM result_evidence_files WHERE id=?",
                (evidence_id,),
            ).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM result_evidence_files WHERE id=?", (evidence_id,))
        self._resolve_evidence_path(row["stored_path"]).unlink(missing_ok=True)
        return True

    def list_jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, status, targets, ports, scope_json, params_json,
                       created_at, started_at, completed_at, summary_json, worker_token
                FROM scan_jobs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._scan_job_row_to_dict(row) for row in rows]

    def get_job(self, scan_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, status, targets, ports, scope_json, params_json,
                       created_at, started_at, completed_at, summary_json, worker_token
                FROM scan_jobs
                WHERE id=?
                """,
                (scan_id,),
            ).fetchone()
        return self._scan_job_row_to_dict(row) if row else None

    def get_result_keys(self, scan_id: str, *, protocol: str) -> set[tuple[str, int]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT host, port
                FROM port_results
                WHERE scan_id=? AND protocol=?
                """,
                (scan_id, protocol),
            ).fetchall()
        return {(str(row["host"]), int(row["port"])) for row in rows}

    def get_results(
        self,
        scan_id: str,
        *,
        limit: int = 10000,
        offset: int = 0,
        open_only: bool = False,
        state: str | None = None,
        protocol: str | None = None,
        service: str | None = None,
        host: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT scan_id, host, port, protocol, state, latency_ms,
                   service_name, service_confidence, banner, evidence, error,
                   tags_json, note, created_at
            FROM port_results
            WHERE scan_id=?
        """
        params: list[Any] = [scan_id]
        query, params = self._append_result_filters(
            query,
            params,
            open_only=open_only,
            state=state,
            protocol=protocol,
            service=service,
            host=host,
            search=search,
        )
        query += " ORDER BY host, port LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
            results = [_port_result_row_to_dict(row) for row in rows]
            self._attach_evidence_files(conn, results, scan_id)
        return results

    def get_report_results(self, scan_id: str, *, limit: int = 1_000_000) -> list[dict[str, Any]]:
        """Return bounded report details with actionable rows ahead of routine states."""
        if limit < 1:
            return []
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, host, port, protocol, state, latency_ms,
                       service_name, service_confidence, banner, evidence, error,
                       tags_json, note, created_at
                FROM port_results
                WHERE scan_id=?
                ORDER BY
                    CASE
                        WHEN state='open' THEN 0
                        WHEN state IN ('error', 'open|filtered') THEN 1
                        WHEN note IS NOT NULL OR tags_json != '[]' OR EXISTS (
                            SELECT 1
                            FROM result_evidence_files evidence_file
                            WHERE evidence_file.scan_id=port_results.scan_id
                              AND evidence_file.host=port_results.host
                              AND evidence_file.port=port_results.port
                              AND evidence_file.protocol=port_results.protocol
                        ) THEN 2
                        ELSE 3
                    END,
                    host, port
                LIMIT ?
                """,
                (scan_id, limit),
            ).fetchall()
            results = [_port_result_row_to_dict(row) for row in rows]
            self._attach_evidence_files(conn, results, scan_id)
        return results

    def get_automatic_evidence_candidates(self, scan_id: str, *, limit: int) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        query = """
            SELECT scan_id, host, port, protocol, state, latency_ms,
                   service_name, service_confidence, banner, evidence, error,
                   tags_json, note, created_at
            FROM port_results
            WHERE scan_id=? AND state IN ('open', 'open|filtered')
              AND NOT EXISTS (
                  SELECT 1
                  FROM result_evidence_files evidence
                  WHERE evidence.scan_id=port_results.scan_id
                    AND evidence.host=port_results.host
                    AND evidence.port=port_results.port
                    AND evidence.protocol=port_results.protocol
                    AND evidence.evidence_type IN (
                        'web_screenshot', 'protocol_snapshot', 'terminal_transcript'
                    )
              )
            ORDER BY host, port
            LIMIT ?
        """
        with self.session() as conn:
            rows = conn.execute(query, (scan_id, limit)).fetchall()
            results = [_port_result_row_to_dict(row) for row in rows]
            self._attach_evidence_files(conn, results, scan_id)
        return results

    def count_results(
        self,
        scan_id: str,
        *,
        open_only: bool = False,
        state: str | None = None,
        protocol: str | None = None,
        service: str | None = None,
        host: str | None = None,
        search: str | None = None,
    ) -> int:
        query = "SELECT COUNT(*) AS count FROM port_results WHERE scan_id=?"
        params: list[Any] = [scan_id]
        query, params = self._append_result_filters(
            query,
            params,
            open_only=open_only,
            state=state,
            protocol=protocol,
            service=service,
            host=host,
            search=search,
        )
        with self.session() as conn:
            row = conn.execute(query, params).fetchone()
        return int(row["count"])

    def summarize_results_by_host(self, scan_id: str) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT host, state, COUNT(*) AS count
                FROM port_results
                WHERE scan_id=?
                GROUP BY host, state
                ORDER BY host, state
                """,
                (scan_id,),
            ).fetchall()
        summaries: dict[str, dict[str, Any]] = {}
        for row in rows:
            host = str(row["host"])
            count = int(row["count"])
            summary = summaries.setdefault(host, {"host": host, "total": 0, "states": {}})
            summary["total"] += count
            summary["states"][str(row["state"])] = count
        return list(summaries.values())

    def summarize_report_counts(self, scan_id: str) -> dict[str, Any]:
        """Return complete scan aggregates without loading individual results."""
        with self.session() as conn:
            state_rows = conn.execute(
                """
                SELECT state, COUNT(*) AS count
                FROM port_results
                WHERE scan_id=?
                GROUP BY state
                """,
                (scan_id,),
            ).fetchall()
            protocol_rows = conn.execute(
                """
                SELECT protocol, COUNT(*) AS count
                FROM port_results
                WHERE scan_id=?
                GROUP BY protocol
                """,
                (scan_id,),
            ).fetchall()
            service_rows = conn.execute(
                """
                SELECT COALESCE(NULLIF(service_name, ''), 'unknown') AS service, COUNT(*) AS count
                FROM port_results
                WHERE scan_id=? AND state='open'
                GROUP BY COALESCE(NULLIF(service_name, ''), 'unknown')
                ORDER BY count DESC, service
                LIMIT 10
                """,
                (scan_id,),
            ).fetchall()
            host_row = conn.execute(
                """
                SELECT COUNT(DISTINCT host) AS count
                FROM port_results
                WHERE scan_id=? AND state='open'
                """,
                (scan_id,),
            ).fetchone()
        states = {str(row["state"]): int(row["count"]) for row in state_rows}
        return {
            "states": states,
            "protocols": {str(row["protocol"]): int(row["count"]) for row in protocol_rows},
            "services": {str(row["service"]): int(row["count"]) for row in service_rows},
            "hosts_with_open_ports": int(host_row["count"]),
            "total": sum(states.values()),
        }

    def count_results_by_state(self, scan_id: str) -> dict[str, int]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT state, COUNT(*) AS count
                FROM port_results
                WHERE scan_id=?
                GROUP BY state
                """,
                (scan_id,),
            ).fetchall()
        return {row["state"]: int(row["count"]) for row in rows}

    def summarize_scan_results(self, scan_id: str) -> ScanSummary:
        states = self.count_results_by_state(scan_id)
        summary = ScanSummary(scan_id=scan_id)
        for state, count in states.items():
            summary.total += count
            if state == "open":
                summary.open += count
            elif state == "closed":
                summary.closed += count
            elif state == "open|filtered":
                summary.open_filtered += count
            elif state == "filtered":
                summary.filtered += count
            else:
                summary.error += count
        return summary

    def get_scan_progress(self, scan_id: str) -> dict[str, Any] | None:
        job = self.get_job(scan_id)
        if not job:
            return None
        target_count = _count_targets(job["targets"], job["params"].get("max_hosts"))
        port_count = _count_ports(job["ports"])
        planned_total = target_count * port_count
        completed_results = self.count_results(scan_id)
        states = self.count_results_by_state(scan_id)
        percent = 100.0 if planned_total == 0 else min(100.0, round((completed_results / planned_total) * 100, 2))
        if job["status"] in {"completed", "failed", "cancelled"}:
            percent = 100.0
        return {
            "scan_id": scan_id,
            "status": job["status"],
            "target_count": target_count,
            "port_count": port_count,
            "planned_total": planned_total,
            "completed_results": completed_results,
            "percent": percent,
            "states": states,
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "completed_at": job["completed_at"],
        }

    def update_result_metadata(
        self,
        scan_id: str,
        *,
        host: str,
        port: int,
        protocol: str = "tcp",
        tags: list[str] | None = None,
        note: str | None = None,
    ) -> dict[str, Any] | None:
        existing = self.get_result(scan_id, host=host, port=port, protocol=protocol)
        if not existing:
            return None
        source_tags = tags if tags is not None else existing.get("tags", [])
        next_tags = sorted({tag.strip() for tag in source_tags if tag and tag.strip()})
        next_note = note if note is not None else existing.get("note")
        with self.session() as conn:
            conn.execute(
                """
                UPDATE port_results
                SET tags_json=?, note=?
                WHERE scan_id=? AND host=? AND port=? AND protocol=?
                """,
                (json.dumps(next_tags), next_note, scan_id, host, port, protocol),
            )
        return self.get_result(scan_id, host=host, port=port, protocol=protocol)

    def get_result(self, scan_id: str, *, host: str, port: int, protocol: str = "tcp") -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT scan_id, host, port, protocol, state, latency_ms,
                       service_name, service_confidence, banner, evidence, error,
                       tags_json, note, created_at
                FROM port_results
                WHERE scan_id=? AND host=? AND port=? AND protocol=?
                """,
                (scan_id, host, port, protocol),
            ).fetchone()
            if not row:
                return None
            result = _port_result_row_to_dict(row)
            self._attach_evidence_files(conn, [result], scan_id)
        return result

    def save_pcap_analysis(self, file_path: str, summary: dict[str, Any]) -> str:
        analysis_id = str(uuid.uuid4())
        with self.session() as conn:
            conn.execute(
                "INSERT INTO pcap_analyses(id, file_path, summary_json) VALUES(?, ?, ?)",
                (analysis_id, file_path, json.dumps(summary)),
            )
        return analysis_id

    def get_pcap_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, file_path, summary_json, created_at
                FROM pcap_analyses
                WHERE id=?
                """,
                (analysis_id,),
            ).fetchone()
        return _pcap_analysis_row_to_dict(row) if row else None

    def list_pcap_analyses(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, file_path, summary_json, created_at
                FROM pcap_analyses
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [_pcap_analysis_row_to_dict(row) for row in rows]

    def save_packet_audit(self, *, request: dict[str, Any], result: SendResult) -> str:
        audit_id = str(uuid.uuid4())
        with self.session() as conn:
            conn.execute(
                """
                INSERT INTO packet_audit(id, template, target, request_json, result_json)
                VALUES(?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    result.template,
                    result.target,
                    json.dumps(request),
                    json.dumps(result.to_dict()),
                ),
            )
        return audit_id

    def get_packet_audit(self, audit_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, template, target, request_json, result_json, created_at
                FROM packet_audit
                WHERE id=?
                """,
                (audit_id,),
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["request"] = json.loads(data.pop("request_json"))
        data["result"] = json.loads(data.pop("result_json"))
        return data

    def list_packet_audits(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        template: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, template, target, request_json, result_json, created_at
            FROM packet_audit
            WHERE 1=1
        """
        params: list[Any] = []
        if template:
            query += " AND template=?"
            params.append(template)
        if target:
            query += " AND target=?"
            params.append(target)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.session() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_packet_audit_row_to_dict(row) for row in rows]

    def create_oast_session(
        self,
        *,
        label: str | None = None,
        base_url: str | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%d %H:%M:%S")
        with self.session() as conn:
            for _ in range(5):
                token = new_oast_token()
                try:
                    conn.execute(
                        """
                        INSERT INTO oast_sessions(id, token, label, base_url, expires_at)
                        VALUES(?, ?, ?, ?, ?)
                        """,
                        (session_id, token, label, base_url, expires_at),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise RuntimeError("could not allocate a unique OAST token")
        session = self.get_oast_session(session_id)
        assert session is not None
        return session

    def get_oast_session(self, session_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, token, label, base_url, expires_at, created_at
                FROM oast_sessions
                WHERE id=?
                """,
                (session_id,),
            ).fetchone()
        return _oast_session_row_to_dict(row) if row else None

    def get_active_oast_session_by_token(self, token: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, token, label, base_url, expires_at, created_at
                FROM oast_sessions
                WHERE token=? AND expires_at > CURRENT_TIMESTAMP
                """,
                (token,),
            ).fetchone()
        return _oast_session_row_to_dict(row) if row else None

    def list_oast_sessions(self, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, token, label, base_url, expires_at, created_at
                FROM oast_sessions
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [_oast_session_row_to_dict(row) for row in rows]

    def delete_oast_session(self, session_id: str) -> bool:
        with self.session() as conn:
            cursor = conn.execute("DELETE FROM oast_sessions WHERE id=?", (session_id,))
        return cursor.rowcount > 0

    def save_oast_interaction(self, *, session_id: str, interaction: dict[str, Any]) -> dict[str, Any]:
        interaction_id = str(uuid.uuid4())
        with self.session() as conn:
            conn.execute(
                """
                INSERT INTO oast_interactions(
                    id, session_id, method, path, query_string, client_host,
                    headers_json, body_preview, body_truncated
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    interaction_id,
                    session_id,
                    interaction["method"],
                    interaction["path"],
                    interaction.get("query_string", ""),
                    interaction.get("client_host"),
                    json.dumps(interaction.get("headers", {})),
                    interaction.get("body_preview"),
                    1 if interaction.get("body_truncated") else 0,
                ),
            )
        saved = self.get_oast_interaction(interaction_id)
        assert saved is not None
        return saved

    def get_oast_interaction(self, interaction_id: str) -> dict[str, Any] | None:
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT id, session_id, method, path, query_string, client_host,
                       headers_json, body_preview, body_truncated, created_at
                FROM oast_interactions
                WHERE id=?
                """,
                (interaction_id,),
            ).fetchone()
        return _oast_interaction_row_to_dict(row) if row else None

    def list_oast_interactions(
        self,
        *,
        session_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, method, path, query_string, client_host,
                       headers_json, body_preview, body_truncated, created_at
                FROM oast_interactions
                WHERE session_id=?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (session_id, limit, offset),
            ).fetchall()
        return [_oast_interaction_row_to_dict(row) for row in rows]

    def export_database(self) -> dict[str, Any]:
        with self.session() as conn:
            job_rows = conn.execute(
                """
                SELECT id, status, targets, ports, scope_json, params_json,
                       created_at, started_at, completed_at, summary_json
                FROM scan_jobs
                ORDER BY created_at ASC
                """
            ).fetchall()
            result_rows = conn.execute(
                """
                SELECT scan_id, host, port, protocol, state, latency_ms,
                       service_name, service_confidence, banner, evidence, error,
                       tags_json, note, created_at
                FROM port_results
                ORDER BY scan_id, host, port
                """
            ).fetchall()
            evidence_rows = conn.execute(
                """
                SELECT id, scan_id, host, port, protocol, evidence_type, file_name,
                       stored_path, mime_type, size_bytes, sha256, source_url, created_at
                FROM result_evidence_files
                ORDER BY created_at, id
                """
            ).fetchall()
            pcap_rows = conn.execute(
                "SELECT id, file_path, summary_json, created_at FROM pcap_analyses ORDER BY created_at ASC"
            ).fetchall()
            audit_rows = conn.execute(
                """
                SELECT id, template, target, request_json, result_json, created_at
                FROM packet_audit
                ORDER BY created_at ASC
                """
            ).fetchall()
            oast_session_rows = conn.execute(
                """
                SELECT id, token, label, base_url, expires_at, created_at
                FROM oast_sessions
                ORDER BY created_at ASC
                """
            ).fetchall()
            oast_interaction_rows = conn.execute(
                """
                SELECT id, session_id, method, path, query_string, client_host,
                       headers_json, body_preview, body_truncated, created_at
                FROM oast_interactions
                ORDER BY created_at ASC
                """
            ).fetchall()
        evidence_files: list[dict[str, Any]] = []
        for row in evidence_rows:
            path = self._resolve_evidence_path(row["stored_path"])
            if not path.is_file():
                continue
            evidence = _evidence_file_row_to_backup(row)
            evidence["content_base64"] = base64.b64encode(path.read_bytes()).decode("ascii")
            evidence_files.append(evidence)
        return {
            "schema_version": SCHEMA_VERSION,
            "scan_jobs": [self._scan_job_row_to_dict(row) for row in job_rows],
            "port_results": [_port_result_row_to_dict(row) for row in result_rows],
            "result_evidence_files": evidence_files,
            "pcap_analyses": [_pcap_analysis_row_to_dict(row) for row in pcap_rows],
            "packet_audit": [_packet_audit_row_to_dict(row) for row in audit_rows],
            "oast_sessions": [_oast_session_row_to_dict(row) for row in oast_session_rows],
            "oast_interactions": [_oast_interaction_row_to_dict(row) for row in oast_interaction_rows],
        }

    def import_database(self, data: dict[str, Any], *, replace: bool = False) -> dict[str, int]:
        counts = {
            "scan_jobs": 0,
            "port_results": 0,
            "result_evidence_files": 0,
            "pcap_analyses": 0,
            "packet_audit": 0,
            "oast_sessions": 0,
            "oast_interactions": 0,
        }
        evidence_backup: Path | None = None
        if replace and self.evidence_root.is_dir():
            evidence_backup = self.evidence_root.with_name(
                f"{self.evidence_root.name}.backup-{uuid.uuid4()}"
            )
            self.evidence_root.replace(evidence_backup)
        written_evidence_paths: list[Path] = []
        try:
            with self.session() as conn:
                if replace:
                    conn.execute("DELETE FROM oast_interactions")
                    conn.execute("DELETE FROM oast_sessions")
                    conn.execute("DELETE FROM packet_audit")
                    conn.execute("DELETE FROM pcap_analyses")
                    conn.execute("DELETE FROM scan_jobs")
                for job in data.get("scan_jobs", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO scan_jobs(
                            id, status, targets, ports, scope_json, params_json,
                            created_at, started_at, completed_at, summary_json
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            job["id"],
                            job["status"],
                            job["targets"],
                            job["ports"],
                            json.dumps(job.get("scope", [])),
                            json.dumps(job.get("params", {})),
                            job.get("created_at") or _now_sql(),
                            job.get("started_at"),
                            job.get("completed_at"),
                            json.dumps(job["summary"]) if job.get("summary") is not None else None,
                        ),
                    )
                    counts["scan_jobs"] += 1
                for result in data.get("port_results", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO port_results(
                            scan_id, host, port, protocol, state, latency_ms,
                            service_name, service_confidence, banner, evidence, error,
                            tags_json, note, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result["scan_id"],
                            result["host"],
                            result["port"],
                            result.get("protocol", "tcp"),
                            result["state"],
                            result.get("latency_ms"),
                            result.get("service_name"),
                            result.get("service_confidence"),
                            result.get("banner"),
                            result.get("evidence"),
                            result.get("error"),
                            json.dumps(result.get("tags", [])),
                            result.get("note"),
                            result.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["port_results"] += 1
                for evidence in data.get("result_evidence_files", []):
                    encoded = evidence.get("content_base64")
                    if not encoded:
                        continue
                    try:
                        content = base64.b64decode(encoded, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ValueError("invalid evidence content_base64") from exc
                    media_type = detect_image_media_type(content)
                    expected_hash = evidence.get("sha256")
                    actual_hash = hashlib.sha256(content).hexdigest()
                    if expected_hash and expected_hash != actual_hash:
                        raise ValueError(f"evidence checksum mismatch: {evidence.get('id')}")
                    evidence_type = evidence.get("type", "manual")
                    if evidence_type not in {
                        "manual",
                        "web_screenshot",
                        "protocol_snapshot",
                        "terminal_transcript",
                    }:
                        raise ValueError(
                            "evidence type must be 'manual', 'web_screenshot', 'protocol_snapshot', "
                            "or 'terminal_transcript'"
                        )
                    target_exists = conn.execute(
                        """
                        SELECT 1 FROM port_results
                        WHERE scan_id=? AND host=? AND port=? AND protocol=?
                        """,
                        (
                            evidence["scan_id"],
                            evidence["host"],
                            evidence["port"],
                            evidence.get("protocol", "tcp"),
                        ),
                    ).fetchone()
                    if not target_exists:
                        raise ValueError(f"evidence target result not found: {evidence.get('id')}")
                    evidence_id = str(evidence.get("id") or uuid.uuid4())
                    relative_path = Path(evidence["scan_id"]) / f"{evidence_id}{image_extension(media_type)}"
                    destination = self._resolve_evidence_path(relative_path)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    written_evidence_paths.append(destination)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO result_evidence_files(
                            id, scan_id, host, port, protocol, evidence_type, file_name,
                            stored_path, mime_type, size_bytes, sha256, source_url, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            evidence_id,
                            evidence["scan_id"],
                            evidence["host"],
                            evidence["port"],
                            evidence.get("protocol", "tcp"),
                            evidence_type,
                            safe_original_name(evidence.get("file_name"), media_type),
                            relative_path.as_posix(),
                            media_type,
                            len(content),
                            actual_hash,
                            evidence.get("source_url"),
                            evidence.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["result_evidence_files"] += 1
                for analysis in data.get("pcap_analyses", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO pcap_analyses(id, file_path, summary_json, created_at)
                        VALUES(?, ?, ?, ?)
                        """,
                        (
                            analysis["id"],
                            analysis["file_path"],
                            json.dumps(analysis.get("summary", {})),
                            analysis.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["pcap_analyses"] += 1
                for audit in data.get("packet_audit", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO packet_audit(
                            id, template, target, request_json, result_json, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?)
                        """,
                        (
                            audit["id"],
                            audit["template"],
                            audit["target"],
                            json.dumps(audit.get("request", {})),
                            json.dumps(audit.get("result", {})),
                            audit.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["packet_audit"] += 1
                for session in data.get("oast_sessions", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO oast_sessions(
                            id, token, label, base_url, expires_at, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session["id"],
                            session["token"],
                            session.get("label"),
                            session.get("base_url"),
                            session["expires_at"],
                            session.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["oast_sessions"] += 1
                for interaction in data.get("oast_interactions", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO oast_interactions(
                            id, session_id, method, path, query_string, client_host,
                            headers_json, body_preview, body_truncated, created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            interaction["id"],
                            interaction["session_id"],
                            interaction["method"],
                            interaction["path"],
                            interaction.get("query_string", ""),
                            interaction.get("client_host"),
                            json.dumps(interaction.get("headers", {})),
                            interaction.get("body_preview"),
                            1 if interaction.get("body_truncated") else 0,
                            interaction.get("created_at") or _now_sql(),
                        ),
                    )
                    counts["oast_interactions"] += 1
        except Exception:
            for path in written_evidence_paths:
                path.unlink(missing_ok=True)
            if replace and self.evidence_root.is_dir():
                shutil.rmtree(self.evidence_root)
            if evidence_backup and evidence_backup.is_dir():
                evidence_backup.replace(self.evidence_root)
            raise
        if evidence_backup and evidence_backup.is_dir():
            shutil.rmtree(evidence_backup, ignore_errors=True)
        return counts

    def _attach_evidence_files(
        self,
        conn: sqlite3.Connection,
        results: list[dict[str, Any]],
        scan_id: str,
    ) -> None:
        if not results:
            return
        rows = conn.execute(
            """
            SELECT id, scan_id, host, port, protocol, evidence_type, file_name,
                   stored_path, mime_type, size_bytes, sha256, source_url, created_at
            FROM result_evidence_files
            WHERE scan_id=?
            ORDER BY created_at, id
            """,
            (scan_id,),
        ).fetchall()
        grouped: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
        for row in rows:
            key = (row["host"], int(row["port"]), row["protocol"])
            grouped.setdefault(key, []).append(_evidence_file_row_to_dict(row))
        for result in results:
            key = (str(result["host"]), int(result["port"]), str(result["protocol"]))
            result["evidence_files"] = grouped.get(key, [])

    def _resolve_evidence_path(self, stored_path: str | Path) -> Path:
        root = self.evidence_root.resolve()
        candidate = (root / Path(stored_path)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("invalid evidence storage path") from exc
        return candidate

    def _remove_scan_evidence_directory(self, scan_id: str) -> None:
        root = self.evidence_root.resolve()
        candidate = (root / scan_id).resolve()
        if candidate.parent != root:
            raise ValueError("invalid scan evidence directory")
        if candidate.is_dir():
            shutil.rmtree(candidate)

    @staticmethod
    def _append_result_filters(
        query: str,
        params: list[Any],
        *,
        open_only: bool,
        state: str | None,
        protocol: str | None,
        service: str | None,
        host: str | None,
        search: str | None,
    ) -> tuple[str, list[Any]]:
        if open_only:
            query += " AND state='open'"
        if state:
            query += " AND state=?"
            params.append(state)
        if protocol:
            query += " AND protocol=?"
            params.append(protocol)
        if service:
            query += " AND service_name=?"
            params.append(service)
        if host:
            query += " AND host=?"
            params.append(host)
        if search:
            query += """
                AND (
                    host LIKE ? OR CAST(port AS TEXT) LIKE ? OR protocol LIKE ? OR
                    state LIKE ? OR COALESCE(service_name, '') LIKE ? OR
                    COALESCE(banner, '') LIKE ? OR COALESCE(tags_json, '') LIKE ? OR
                    COALESCE(note, '') LIKE ?
                )
            """
            pattern = f"%{search}%"
            params.extend([pattern] * 8)
        return query, params

    @staticmethod
    def _scan_job_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data.pop("worker_token", None)
        data["scope"] = json.loads(data.pop("scope_json"))
        data["params"] = json.loads(data.pop("params_json"))
        summary_json = data.pop("summary_json")
        data["summary"] = json.loads(summary_json) if summary_json else None
        return data


def _count_targets(expr: str, max_hosts: object = None) -> int:
    try:
        limit = int(max_hosts) if max_hosts is not None else 1_000_000
        return len(parse_target_expr(expr, max_hosts=limit))
    except Exception:  # noqa: BLE001 - progress should tolerate legacy/corrupt expressions.
        return len([part for part in expr.split(",") if part.strip()])


def _count_ports(expr: str) -> int:
    try:
        return len(parse_ports(expr))
    except Exception:  # noqa: BLE001 - progress should tolerate legacy/corrupt expressions.
        return len([part for part in expr.split(",") if part.strip()])


def _port_result_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    tags_json = data.pop("tags_json", "[]") or "[]"
    try:
        tags = json.loads(tags_json)
    except json.JSONDecodeError:
        tags = []
    data["tags"] = tags if isinstance(tags, list) else []
    return data


def _evidence_file_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data.pop("stored_path", None)
    data["type"] = data.pop("evidence_type")
    data["download_url"] = f"/v1/evidence/{data['id']}/content"
    return data


def _evidence_file_row_to_backup(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data.pop("stored_path", None)
    data["type"] = data.pop("evidence_type")
    return data


def _pcap_analysis_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["summary"] = json.loads(data.pop("summary_json"))
    return data


def _packet_audit_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["request"] = json.loads(data.pop("request_json"))
    data["result"] = json.loads(data.pop("result_json"))
    return data


def _oast_session_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _oast_interaction_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["headers"] = json.loads(data.pop("headers_json"))
    data["body_truncated"] = bool(data["body_truncated"])
    return data


def _now_sql() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
