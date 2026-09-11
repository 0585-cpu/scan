from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Mapping
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
# A resumed scan re-runs the work it believes is missing, and that belief can be
# stale, so writing a port twice has to be ordinary rather than fatal. The fresh
# observation replaces the old one; the tags and note a person attached to the
# row are theirs and are left alone.
PORT_RESULT_INSERT_SQL = """
    INSERT INTO port_results(
        scan_id, host, port, protocol, state, latency_ms,
        service_name, service_confidence, banner, evidence, error, tags_json, note
    )
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id, host, port, protocol) DO UPDATE SET
        state=excluded.state,
        latency_ms=excluded.latency_ms,
        service_name=excluded.service_name,
        service_confidence=excluded.service_confidence,
        banner=excluded.banner,
        evidence=excluded.evidence,
        error=excluded.error
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


# Above this many ports of one state on one host, the individual rows carry no
# information the count does not already give. Below it they do: three filtered
# ports among a thousand closed ones name the firewall rule. nmap draws the same
# line at roughly this size.
# Evidence Netroach captured itself, as opposed to a file an operator attached.
AUTOMATIC_EVIDENCE_TYPES = ("web_screenshot", "protocol_snapshot", "terminal_transcript")
_EVIDENCE_NOT_CAPTURED_SQL = """
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
"""

# A host keeps up to this many rows of one state rather than folding them into
# a count, because a handful of closed ports reads better as ports than as a
# range. The allowance is per host, so a scan of one subnet keeps a few hundred
# rows and a scan of ten keeps tens of thousands - detail nobody reads, on a
# scale where only the open ports are looked at.
COLLAPSE_THRESHOLD = 25
# Above this many hosts the allowance is dropped and everything foldable folds.
# The ranges are kept either way, so the detail is still there; what changes is
# whether it is carried as rows.
COLLAPSE_DETAIL_HOST_LIMIT = 100
COLLAPSIBLE_STATES = ("closed", "filtered")
# What `open_only` selects. A UDP port that did not refuse is open as far as a
# scan can tell, which is why the evidence pass and the re-scan both count it.
OPEN_STATES = ("open", "open|filtered")


def parse_port_ranges(text: str | None) -> list[tuple[int, int]]:
    """Read "1-3,7,9-11" back into inclusive (low, high) pairs."""
    ranges: list[tuple[int, int]] = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        low, _, high = part.partition("-")
        ranges.append((int(low), int(high or low)))
    return ranges


def format_port_ranges(ranges: Iterable[tuple[int, int]]) -> str:
    return ",".join(f"{low}" if low == high else f"{low}-{high}" for low, high in ranges)


def _is_foldable(result: PortResult) -> bool:
    """Whether a result says nothing beyond its state, so a count can carry it."""
    return (
        result.state in COLLAPSIBLE_STATES
        and not result.banner
        and not result.evidence
    )


def _group_foldable(
    results: Iterable[PortResult],
) -> list[tuple[str, str, str, str, list[int]]]:
    grouped: dict[tuple[str, str, str, str], list[int]] = {}
    for result in results:
        key = (result.scan_id or "", result.host, result.protocol, result.state)
        grouped.setdefault(key, []).append(result.port)
    return [(*key, ports) for key, ports in grouped.items()]


def merge_port_ranges(existing: str | None, ports: Iterable[int]) -> str:
    """Add ports to a range string, keeping it sorted and coalesced.

    A scan folds tens of thousands of ports per host, and storing them
    individually would defeat the point of folding at all. Consecutive ports
    are the normal case, so ranges keep this to a handful of characters.
    """
    points: list[tuple[int, int]] = list(parse_port_ranges(existing))
    points.extend((port, port) for port in ports)
    if not points:
        return ""
    points.sort()
    merged: list[tuple[int, int]] = [points[0]]
    for low, high in points[1:]:
        last_low, last_high = merged[-1]
        if low <= last_high + 1:
            merged[-1] = (last_low, max(last_high, high))
        else:
            merged.append((low, high))
    return format_port_ranges(merged)


def merge_range_strings(existing: str | None, incoming: str | None) -> str:
    """Merge two range strings without expanding either into ports.

    A summary covering ten thousand ports arrives as a handful of ranges, and
    turning it into ten thousand integers to merge it would cost as much as the
    per-probe lines the summary exists to replace.
    """
    points = parse_port_ranges(existing) + parse_port_ranges(incoming)
    if not points:
        return ""
    points.sort()
    merged: list[tuple[int, int]] = [points[0]]
    for low, high in points[1:]:
        last_low, last_high = merged[-1]
        if low <= last_high + 1:
            merged[-1] = (last_low, max(last_high, high))
        else:
            merged.append((low, high))
    return format_port_ranges(merged)


def default_db_path() -> Path:
    system = platform.system().lower()
    if system == "windows":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "Netroach" / "netroach.db"
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / "netroach" / "netroach.db"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "netroach" / "netroach.db"


def legacy_db_path() -> Path:
    """Where the data lived when the project was still called Scaprobe."""
    system = platform.system().lower()
    if system == "windows":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "Scaprobe" / "scaprobe.db"
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / "scaprobe" / "scaprobe.db"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "scaprobe" / "scaprobe.db"


def migrate_legacy_data(new_path: Path, legacy_path: Path | None = None) -> bool:
    """Move a pre-rename database and its artifacts to the new location.

    Only runs when there is nothing at the new path yet, so it can never
    overwrite current data, and it is a no-op on every later start. A failure
    here must not stop the application: the worst case is an empty history
    plus the untouched old directory, which the user can still copy by hand.
    """
    legacy = legacy_path or legacy_db_path()
    if new_path.exists() or not legacy.is_file():
        return False
    legacy_artifacts = legacy.parent / f"{legacy.stem}-artifacts"
    try:
        new_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(os.fspath(legacy), os.fspath(new_path))
        if legacy_artifacts.is_dir():
            shutil.move(
                os.fspath(legacy_artifacts),
                os.fspath(new_path.parent / f"{new_path.stem}-artifacts"),
            )
    except OSError:
        return False
    return True


class SQLiteRepository:
    def __init__(self, path: str | Path | None = None) -> None:
        if path:
            self.path = Path(path)
        else:
            self.path = default_db_path()
            migrate_legacy_data(self.path)
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
    def session(self) -> Iterator[sqlite3.Connection]:
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
                    worker_token TEXT,
                    heartbeat_at TEXT
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
                -- Per-host counts are a GROUP BY host, state over every row of
                -- a scan. Without a covering index SQLite builds a temporary
                -- b-tree for it: 210ms at half a million rows, against 45ms
                -- once the index answers the query outright.
                CREATE INDEX IF NOT EXISTS idx_port_results_scan_host_state
                    ON port_results(scan_id, host, state);
                -- The progress strip groups by state alone every poll. The
                -- host index above cannot answer that without a temporary
                -- b-tree: 110ms at half a million rows, 34ms with this one.
                CREATE INDEX IF NOT EXISTS idx_port_results_scan_state
                    ON port_results(scan_id, state);
                CREATE INDEX IF NOT EXISTS idx_port_results_scan_host_port
                    ON port_results(scan_id, host, port);
                -- How many probes of one state were folded away for a host.
                -- A scan of a firewalled range answers "filtered" hundreds of
                -- thousands of times with nothing to distinguish one from the
                -- next; nmap prints that as a single "Not shown" line and this
                -- is the same idea, stored rather than printed.
                CREATE TABLE IF NOT EXISTS scan_state_counts (
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    collapsed INTEGER NOT NULL,
                    -- Which ports were folded, as "1-1998,2001-3000". A resumed
                    -- scan asks what has already been probed, and a bare count
                    -- cannot answer that - it would re-probe the whole range.
                    ports TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(scan_id, host, protocol, state),
                    FOREIGN KEY(scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
                );
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
                    capture_agent TEXT,
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
        evidence_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(result_evidence_files)").fetchall()
        }
        if "heartbeat_at" not in job_columns:
            # Lets recovery tell a dead worker from a live peer; rows without one
            # count as dead, which is how every existing row behaves today.
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN heartbeat_at TEXT")
        if "capture_agent" not in evidence_columns:
            # Rows written before this column exist and stay readable; they
            # simply cannot say what produced them.
            conn.execute("ALTER TABLE result_evidence_files ADD COLUMN capture_agent TEXT")
        folded_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(scan_state_counts)").fetchall()
        }
        if folded_columns and "ports" not in folded_columns:
            # Written by a build that stored only the count. Those rows keep
            # their totals; a scan resumed from one re-probes what it folded.
            conn.execute("ALTER TABLE scan_state_counts ADD COLUMN ports TEXT NOT NULL DEFAULT ''")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(port_results)").fetchall()}
        if "evidence" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN evidence TEXT")
        if "tags_json" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'")
        if "note" not in columns:
            conn.execute("ALTER TABLE port_results ADD COLUMN note TEXT")
        # Both statements below read every row of port_results, so they may
        # only run against a database that predates the unique index. Left
        # unguarded they cost a full table scan on every start - fifteen
        # seconds on a multi-gigabyte history, which the desktop shell counts
        # against its backend startup deadline.
        if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_port_results_unique'"
        ).fetchone():
            return
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
            CREATE UNIQUE INDEX idx_port_results_unique
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

    def record_scan_heartbeat(self, scan_id: str) -> None:
        """Stamp a job as still being worked on by a live process.

        `worker_token` cannot answer this: a normal run leaves it NULL, so
        recovery had no way to tell a job whose process died from one another
        instance is running against the same database.
        """
        with self.session() as conn:
            conn.execute(
                "UPDATE scan_jobs SET heartbeat_at=CURRENT_TIMESTAMP WHERE id=?",
                (scan_id,),
            )

    def scan_looks_alive(self, scan_id: str, *, stale_after_s: float) -> bool:
        """Whether some process claimed this job recently enough to still own it.

        A job that never recorded a heartbeat - every row written before this
        column existed - counts as dead, which keeps those jobs recoverable.
        """
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT CAST(
                    (julianday(CURRENT_TIMESTAMP) - julianday(heartbeat_at)) * 86400.0 AS REAL
                ) AS age
                FROM scan_jobs
                WHERE id=? AND heartbeat_at IS NOT NULL
                """,
                (scan_id,),
            ).fetchone()
        if row is None or row["age"] is None:
            return False
        return float(row["age"]) <= stale_after_s

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
            if cursor.rowcount > 0:
                self._forget_collapsed_counts(conn, scan_id)
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
            if cursor.rowcount > 0:
                self._forget_collapsed_counts(conn, scan_id)
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
            rows = conn.execute(
                "SELECT COUNT(*) AS count FROM port_results WHERE scan_id=?",
                (scan_id,),
            ).fetchone()["count"]
            # The check exists to catch results lost between the engine and
            # this table. A folded result is recorded, not lost, so it has to
            # count - reading rows alone fails every scan large enough to fold.
            folded = conn.execute(
                "SELECT COALESCE(SUM(collapsed), 0) AS count FROM scan_state_counts WHERE scan_id=?",
                (scan_id,),
            ).fetchone()["count"]
            stored_total = int(rows) + int(folded)
            if stored_total != summary.total:
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

    def record_evidence_capture_failures(
        self,
        scan_id: str,
        *,
        candidates: int,
        captured: int,
        without_evidence: int,
        errors: Iterable[str],
        eligible: int | None = None,
    ) -> None:
        """Attach what happened during evidence capture to the finished job.

        Without this a failed screenshot leaves no trace at all: the API path
        discarded the capture summary, so the operator saw a scan carrying less
        evidence than they asked for and nothing anywhere said why.

        `without_evidence` counts candidates that ended up with nothing, which
        is not the same as the number of errors: a web screenshot can fail and
        still leave a terminal transcript behind. Storing that count as
        `failed` produced a summary reading `failed: 0` beside a populated
        error list, which is accurate and looks like a contradiction.
        """
        reasons = [str(error) for error in errors][:20]
        # Ports the limit kept out of the candidate list were never tried, so
        # nothing about them failed. Silence there reads as full coverage.
        not_attempted = max(0, int(eligible) - int(candidates)) if eligible is not None else 0
        if without_evidence <= 0 and not reasons and not not_attempted:
            return
        with self.session() as conn:
            row = conn.execute("SELECT summary_json FROM scan_jobs WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                return
            try:
                summary = json.loads(row["summary_json"]) if row["summary_json"] else {}
            except json.JSONDecodeError:
                summary = {}
            if not isinstance(summary, dict):
                summary = {}
            summary["evidence"] = {
                "eligible": int(eligible) if eligible is not None else int(candidates),
                "candidates": int(candidates),
                "captured": int(captured),
                "not_attempted": not_attempted,
                "without_evidence": int(without_evidence),
                "errors": reasons,
            }
            conn.execute(
                "UPDATE scan_jobs SET summary_json=? WHERE id=?",
                (json.dumps(summary), scan_id),
            )

    def park_scan_for_later_recovery(self, scan_id: str, reason: str) -> bool:
        """Park a job that cannot be resumed right now but is not lost.

        Leaving it in 'running' would be a lie a reader acts on: the dashboard
        treats a running job as live work and holds its progress strip and fast
        poll open for as long as the row says so. 'recovering' is already a
        recoverable status, so a later start that can resume it still will.
        """
        with self.session() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status='recovering', worker_token=NULL, summary_json=?
                WHERE id=? AND status IN ('queued', 'running')
                """,
                (json.dumps({"interrupted": reason}), scan_id),
            )
        return cursor.rowcount > 0

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
            self._reclaim_free_pages()
        return deleted

    # ponytail: a whole-file rewrite, which is what SQLite offers. Switching the
    # database to incremental auto-vacuum would reclaim in the background, but
    # that setting can only be changed by a full VACUUM anyway.
    RECLAIM_FREE_PAGE_RATIO = 0.1

    def _reclaim_free_pages(self) -> None:
        """Give the disk back after a delete, rather than only the rows.

        SQLite keeps the pages a delete frees on its own free list and the file
        stays the size it grew to - so deleting scans to recover from a
        database that had grown to gigabytes did nothing the operator could
        see, which is the reason they were deleting them.

        Only worth the rewrite when there is something to reclaim, and only if
        the database is free to be rewritten: a scan in progress holds it, and
        the pages simply stay on the free list for the next delete to pick up.
        """
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
            free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
            if not pages or free < pages * self.RECLAIM_FREE_PAGE_RATIO:
                return
            conn.execute("VACUUM")
        except sqlite3.DatabaseError:
            return
        finally:
            conn.close()

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
            if scan_ids:
                self._reclaim_free_pages()
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
        batch = list(results)
        if not batch:
            return
        by_scan: dict[str, set[str]] = {}
        for result in batch:
            if result.scan_id:
                by_scan.setdefault(result.scan_id, set()).add(result.host)

        # A wide scan folds every uninformative result into a per-host count, so
        # writing those rows first only to group, count and delete them is work
        # with no output. At tens of millions of probes that round trip is the
        # whole cost of storing a sweep: counted straight from the batch, the
        # rows never exist. A narrow scan keeps them, so it takes the old path.
        wide = {
            scan_id
            for scan_id, hosts in by_scan.items()
            if len(hosts) > COLLAPSE_DETAIL_HOST_LIMIT
        }
        counted: list[PortResult] = []
        kept = batch
        if wide:
            counted = [
                result
                for result in batch
                if result.scan_id in wide and _is_foldable(result)
            ]
            if counted:
                kept = [
                    result
                    for result in batch
                    if not (result.scan_id in wide and _is_foldable(result))
                ]

        values = [_port_result_values(result) for result in kept]
        with self.session() as conn:
            if values:
                conn.executemany(PORT_RESULT_INSERT_SQL, values)
            for scan_id, host, protocol, state, ports in _group_foldable(counted):
                self._add_state_count(conn, scan_id, host, protocol, state, ports)
            for scan_id, hosts in by_scan.items():
                if scan_id in wide and not any(
                    r.scan_id == scan_id for r in kept if _is_foldable(r)
                ):
                    # Nothing foldable was written for this scan, so there is
                    # nothing for the fold to find.
                    continue
                self._collapse_bulk_states(conn, scan_id, sorted(hosts))

    def add_state_summaries(self, summaries: Iterable[Mapping[str, Any]]) -> int:
        """Record many summaries on one connection.

        Opening a connection costs a handful of PRAGMAs, which is nothing until
        a scan of thousands of hosts sends a summary each: paid per summary it
        was most of the time the summaries take.
        """
        batch = list(summaries)
        if not batch:
            return 0
        covered = 0
        with self.session() as conn:
            for summary in batch:
                covered += self._apply_state_summary(
                    conn,
                    str(summary["scan_id"]),
                    host=str(summary["host"]),
                    protocol=str(summary.get("protocol", "tcp")),
                    state=str(summary["state"]),
                    ports=str(summary.get("ports", "")),
                )
        return covered

    def add_state_summary(
        self,
        scan_id: str,
        *,
        host: str,
        protocol: str,
        state: str,
        ports: str,
    ) -> int:
        """Record many results of one state on one host without their rows.

        The engine sends the bulk states this way rather than a line per probe,
        so the rows they would have become are never built, sent, parsed or
        written. Returns how many ports the summary covered.
        """
        with self.session() as conn:
            return self._apply_state_summary(
                conn, scan_id, host=host, protocol=protocol, state=state, ports=ports
            )

    def _apply_state_summary(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        *,
        host: str,
        protocol: str,
        state: str,
        ports: str,
    ) -> int:
        spans = parse_port_ranges(ports)
        if not spans:
            return 0
        covered = sum(high - low + 1 for low, high in spans)
        previous = conn.execute(
            """
            SELECT ports FROM scan_state_counts
            WHERE scan_id=? AND host=? AND protocol=? AND state=?
            """,
            (scan_id, host, protocol, state),
        ).fetchone()
        merged = merge_range_strings(previous["ports"] if previous else "", ports)
        conn.execute(
            """
            INSERT INTO scan_state_counts(scan_id, host, protocol, state, collapsed, ports)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, host, protocol, state)
            DO UPDATE SET collapsed=collapsed + excluded.collapsed, ports=excluded.ports
            """,
            (scan_id, host, protocol, state, covered, merged),
        )
        return covered

    def _add_state_count(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        host: str,
        protocol: str,
        state: str,
        ports: list[int],
    ) -> None:
        previous = conn.execute(
            """
            SELECT ports FROM scan_state_counts
            WHERE scan_id=? AND host=? AND protocol=? AND state=?
            """,
            (scan_id, host, protocol, state),
        ).fetchone()
        merged = merge_port_ranges(previous["ports"] if previous else "", ports)
        conn.execute(
            """
            INSERT INTO scan_state_counts(scan_id, host, protocol, state, collapsed, ports)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, host, protocol, state)
            DO UPDATE SET collapsed=collapsed + excluded.collapsed, ports=excluded.ports
            """,
            (scan_id, host, protocol, state, len(ports), merged),
        )

    def _collapse_bulk_states(self, conn: sqlite3.Connection, scan_id: str, hosts: list[str]) -> None:
        """Replace uninformative runs of one state on one host with a count.

        Only rows that say nothing beyond their state qualify: a banner or an
        evidence reference makes a row worth keeping however many peers it has.
        A host whose count already exists keeps folding, so the rows that
        arrive after the fold do not accumulate into an arbitrary sample of
        whichever probes happened to land last.
        """
        # The batch spans every host the scan is working on, so its own size
        # says how wide the scan is without asking the database.
        threshold = COLLAPSE_THRESHOLD if len(hosts) <= COLLAPSE_DETAIL_HOST_LIMIT else 0
        placeholders = ",".join("?" * len(hosts))
        states = ",".join("?" * len(COLLAPSIBLE_STATES))
        groups = conn.execute(
            f"""
            SELECT host, protocol, state, COUNT(*) AS count
            FROM port_results
            WHERE scan_id=? AND host IN ({placeholders}) AND state IN ({states})
              AND banner IS NULL AND evidence IS NULL
            GROUP BY host, protocol, state
            """,
            (scan_id, *hosts, *COLLAPSIBLE_STATES),
        ).fetchall()
        if not groups:
            return
        collapsing = {
            (str(row["host"]), str(row["protocol"]), str(row["state"]))
            for row in conn.execute(
                "SELECT host, protocol, state FROM scan_state_counts"
                f" WHERE scan_id=? AND host IN ({placeholders})",
                (scan_id, *hosts),
            )
        }
        for row in groups:
            key = (str(row["host"]), str(row["protocol"]), str(row["state"]))
            count = int(row["count"])
            if count <= threshold and key not in collapsing:
                continue
            folding = [
                int(found["port"])
                for found in conn.execute(
                    """
                    SELECT port FROM port_results
                    WHERE scan_id=? AND host=? AND protocol=? AND state=?
                      AND banner IS NULL AND evidence IS NULL
                    """,
                    (scan_id, *key),
                )
            ]
            previous = conn.execute(
                """
                SELECT ports FROM scan_state_counts
                WHERE scan_id=? AND host=? AND protocol=? AND state=?
                """,
                (scan_id, *key),
            ).fetchone()
            ports = merge_port_ranges(previous["ports"] if previous else "", folding)
            conn.execute(
                """
                INSERT INTO scan_state_counts(scan_id, host, protocol, state, collapsed, ports)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, host, protocol, state)
                DO UPDATE SET collapsed=collapsed + excluded.collapsed, ports=excluded.ports
                """,
                (scan_id, *key, len(folding), ports),
            )
            conn.execute(
                """
                DELETE FROM port_results
                WHERE scan_id=? AND host=? AND protocol=? AND state=?
                  AND banner IS NULL AND evidence IS NULL
                """,
                (scan_id, *key),
            )

    def _collapsed_counts(
        self, conn: sqlite3.Connection, scan_id: str
    ) -> list[tuple[str, str, str, int]]:
        return [
            (str(row["host"]), str(row["protocol"]), str(row["state"]), int(row["collapsed"]))
            for row in conn.execute(
                "SELECT host, protocol, state, collapsed FROM scan_state_counts WHERE scan_id=?",
                (scan_id,),
            )
        ]

    def _forget_collapsed_counts(self, conn: sqlite3.Connection, scan_id: str) -> None:
        """A re-run re-probes every port, so its counts must start from zero."""
        conn.execute("DELETE FROM scan_state_counts WHERE scan_id=?", (scan_id,))

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
        capture_agent: str | None = None,
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
                        stored_path, mime_type, size_bytes, sha256, source_url,
                        capture_agent
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        capture_agent,
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
                       stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                       created_at
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
                       stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                       created_at
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
                       stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                       created_at
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

    def delete_automatic_evidence(
        self, scan_id: str, *, host: str, port: int, protocol: str = "tcp",
        except_id: str | None = None,
    ) -> int:
        """Drop the evidence Netroach captured for one port, keeping the rest.

        A file an operator attached by hand is theirs and survives; only what
        this program photographed is replaced.

        `except_id` spares one row, which is how a replacement is done safely:
        store the new picture first, then drop the old ones but not it. Doing
        it the other way round - clearing and then storing - left the port with
        nothing at all whenever the store failed, and a store can fail on a
        malformed image, a scan deleted mid-run, or a full disk.
        """
        placeholders = ",".join("?" * len(AUTOMATIC_EVIDENCE_TYPES))
        spare = " AND id != ?" if except_id is not None else ""
        parameters: list[Any] = [scan_id, host, port, protocol, *AUTOMATIC_EVIDENCE_TYPES]
        if except_id is not None:
            parameters.append(except_id)
        with self.session() as conn:
            rows = conn.execute(
                f"""
                SELECT id, stored_path FROM result_evidence_files
                WHERE scan_id=? AND host=? AND port=? AND protocol=?
                  AND evidence_type IN ({placeholders}){spare}
                """,
                parameters,
            ).fetchall()
            for row in rows:
                conn.execute("DELETE FROM result_evidence_files WHERE id=?", (row["id"],))
        for row in rows:
            self._resolve_evidence_path(row["stored_path"]).unlink(missing_ok=True)
        return len(rows)

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
                       created_at, started_at, completed_at, summary_json, worker_token,
                       CAST((julianday(CURRENT_TIMESTAMP) - julianday(heartbeat_at)) * 86400.0 AS REAL) AS heartbeat_age_s
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
                       created_at, started_at, completed_at, summary_json, worker_token,
                       CAST((julianday(CURRENT_TIMESTAMP) - julianday(heartbeat_at)) * 86400.0 AS REAL) AS heartbeat_age_s
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
            folded = conn.execute(
                """
                SELECT host, ports FROM scan_state_counts
                WHERE scan_id=? AND protocol=?
                """,
                (scan_id, protocol),
            ).fetchall()
        keys = {(str(row["host"]), int(row["port"])) for row in rows}
        # A folded port was probed; leaving it out here would make a resumed
        # scan repeat every port it had already finished.
        for row in folded:
            host = str(row["host"])
            for low, high in parse_port_ranges(row["ports"]):
                keys.update((host, port) for port in range(low, high + 1))
        return keys

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

    def get_automatic_evidence_candidates(
        self, scan_id: str, *, limit: int, include_captured: bool = False
    ) -> list[dict[str, Any]]:
        """Open results evidence can be captured for.

        `include_captured` asks for every open result rather than only the ones
        still missing evidence - a recapture redoes the scan's evidence rather
        than filling its gaps, because the reason to run one is usually that
        what is there was taken with the wrong settings.
        """
        if limit < 1:
            return []
        captured_filter = "" if include_captured else _EVIDENCE_NOT_CAPTURED_SQL
        query = f"""
            SELECT scan_id, host, port, protocol, state, latency_ms,
                   service_name, service_confidence, banner, evidence, error,
                   tags_json, note, created_at
            FROM port_results
            WHERE scan_id=? AND state IN ('open', 'open|filtered')
              {captured_filter}
            ORDER BY host, port
            LIMIT ?
        """
        with self.session() as conn:
            rows = conn.execute(query, (scan_id, limit)).fetchall()
            results = [_port_result_row_to_dict(row) for row in rows]
            self._attach_evidence_files(conn, results, scan_id)
        return results

    def open_result_targets(self, scan_id: str) -> tuple[list[str], list[int]]:
        """The hosts and ports a scan found open, ready to be scanned again.

        Returned as two lists rather than pairs because that is what a scan
        takes: it crosses every target with every port. Re-scanning a hundred
        hosts that answered on four hundred ports between them therefore probes
        more than it found - still a rounding error against the range the ports
        were found in.

        `open|filtered` counts as open here, as it does everywhere else in this
        module: it is what a UDP scan calls a port that did not refuse, and
        leaving it out would give a UDP scan nothing to re-scan.
        """
        with self.session() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT host, port
                FROM port_results
                WHERE scan_id=? AND state IN ('open', 'open|filtered')
                """,
                (scan_id,),
            ).fetchall()
        hosts = sorted({str(row["host"]) for row in rows})
        ports = sorted({int(row["port"]) for row in rows})
        return hosts, ports

    def count_open_results(self, scan_id: str) -> int:
        """Every open result, whether or not it already carries evidence."""
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count FROM port_results
                WHERE scan_id=? AND state IN ('open', 'open|filtered')
                """,
                (scan_id,),
            ).fetchone()
        return int(row["count"])

    def count_automatic_evidence_candidates(self, scan_id: str) -> int:
        """How many ports evidence could be captured for, before any limit.

        The capture limit truncates the candidate list itself, so the capture
        summary alone cannot tell a scan that photographed everything from one
        that photographed the first twenty of a thousand.
        """
        with self.session() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
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
                """,
                (scan_id,),
            ).fetchone()
        return int(row["count"])

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
        """Per-host counts over the whole scan, deliberately unfiltered.

        This list also populates the host picker, so narrowing it by the active
        host filter would collapse the picker to the host already selected and
        leave no way back to the others.
        """
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
            collapsed = self._collapsed_counts(conn, scan_id)
        summaries: dict[str, dict[str, Any]] = {}

        def add(host: str, state: str, count: int) -> None:
            summary = summaries.setdefault(host, {"host": host, "total": 0, "states": {}})
            summary["total"] += count
            summary["states"][state] = summary["states"].get(state, 0) + count

        for row in rows:
            add(str(row["host"]), str(row["state"]), int(row["count"]))
        # A host whose every port was folded away has no rows at all, and
        # dropping it here would take it out of the host picker - hiding the
        # fact that it was scanned rather than reporting what was found.
        for host, _protocol, state, count in collapsed:
            add(host, state, count)
        return sorted(summaries.values(), key=lambda summary: str(summary["host"]))

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
                WHERE scan_id=? AND state IN ('open', 'open|filtered')
                """,
                (scan_id,),
            ).fetchone()
            collapsed = self._collapsed_counts(conn, scan_id)
        states = {str(row["state"]): int(row["count"]) for row in state_rows}
        protocols = {str(row["protocol"]): int(row["count"]) for row in protocol_rows}
        for _host, protocol, state, count in collapsed:
            states[state] = states.get(state, 0) + count
            protocols[protocol] = protocols.get(protocol, 0) + count
        return {
            "states": states,
            "protocols": protocols,
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
            collapsed = self._collapsed_counts(conn, scan_id)
        counts = {str(row["state"]): int(row["count"]) for row in rows}
        for _host, _protocol, state, count in collapsed:
            counts[state] = counts.get(state, 0) + count
        return counts

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
        # Every result carries a state, so the per-state counts already add up
        # to the total. Counting the table twice per poll cost 24ms of the 127
        # this call took at half a million rows.
        states = self.count_results_by_state(scan_id)
        completed_results = sum(states.values())
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

    # Every table a scan's findings live in, in the order a foreign key needs
    # them: a result cannot land before the job it belongs to.
    MERGED_TABLES = (
        "scan_jobs",
        "port_results",
        "scan_state_counts",
        "result_evidence_files",
        "pcap_analyses",
        "packet_audit",
        "oast_sessions",
        "oast_interactions",
    )

    def import_from_database(self, source: str | Path) -> dict[str, int]:
        """Merge another Netroach database, and its evidence images, into this one.

        Written for the ordinary case of carrying a scan back from the machine
        that ran it: point at that machine's netroach.db and the images beside
        it come too. Rows are added rather than replacing what is here, and a
        row already present is left alone - importing the same database twice
        does nothing the second time.

        The copy runs in SQLite rather than Python because the alternative,
        reading every row out as JSON with the images base64-encoded, needs the
        whole scan in memory at once.
        """
        source_path = Path(source)
        if not source_path.is_file():
            raise ValueError(f"database not found: {source_path}")
        # sqlite3's context manager ends the transaction but leaves the
        # connection open, which on Windows keeps a lock on the file.
        try:
            probe = sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"could not open database: {source_path}") from exc
        try:
            probe.execute("SELECT 1 FROM scan_jobs LIMIT 1").fetchall()
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"not a Netroach database: {source_path}") from exc
        finally:
            probe.close()

        counts: dict[str, int] = {}
        # Its own connection: ATTACH only reads a file: URI when the connection
        # was opened in URI mode, and the source is attached read-only so an
        # import cannot write to the database it was handed.
        conn = sqlite3.connect(self.path, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            conn.execute("ATTACH DATABASE ? AS source", (f"file:{source_path.as_posix()}?mode=ro",))
            try:
                for table in self.MERGED_TABLES:
                    here = {
                        str(row["name"])
                        for row in conn.execute(f"PRAGMA main.table_info({table})").fetchall()
                    }
                    columns = [
                        str(row["name"])
                        for row in conn.execute(f"PRAGMA source.table_info({table})").fetchall()
                        # A rowid surrogate means nothing outside its own
                        # database: carrying it over would collide with a row
                        # this database already numbered, and INSERT OR IGNORE
                        # would silently drop the incoming one. Let SQLite
                        # assign a new one and conflict on the real key.
                        if not (row["pk"] and str(row["type"]).upper() == "INTEGER")
                        # Only what both sides have. The database being carried
                        # in was written by whatever build ran that scan, which
                        # is the whole reason to carry it: a column added since
                        # this one was built would otherwise fail the import
                        # outright rather than bring across the rest.
                        and str(row["name"]) in here
                    ]
                    if not columns:
                        # An older database may predate the table entirely.
                        counts[table] = 0
                        continue
                    names = ", ".join(columns)
                    cursor = conn.execute(
                        f"INSERT OR IGNORE INTO main.{table}({names}) SELECT {names} FROM source.{table}"
                    )
                    counts[table] = cursor.rowcount if cursor.rowcount > 0 else 0
                conn.commit()
            finally:
                # An import that failed part way leaves its transaction open,
                # and DETACH then raises "database source is locked" - which
                # replaces the real reason on the way out with a message that
                # says nothing about what went wrong.
                conn.rollback()
                conn.execute("DETACH DATABASE source")
        finally:
            conn.close()

        counts["evidence_files"] = self._copy_evidence_tree(
            source_path.parent / f"{source_path.stem}-artifacts"
        )
        return counts

    def _copy_evidence_tree(self, source_root: Path) -> int:
        """Bring the images across, keeping the paths the rows already record.

        Stored paths are relative to the evidence root and start with the scan
        id, so two machines' trees can be laid on top of each other without
        colliding. A file already here is left as it is: it is addressed by a
        uuid, so a name that matches is the same image.
        """
        if not source_root.is_dir():
            return 0
        destination_root = self.evidence_root
        copied = 0
        for source_file in source_root.rglob("*"):
            if not source_file.is_file():
                continue
            destination = destination_root / source_file.relative_to(source_root)
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)
            copied += 1
        return copied

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
                       stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                       created_at
                FROM result_evidence_files
                ORDER BY created_at, id
                """
            ).fetchall()
            folded_rows = conn.execute(
                """
                SELECT scan_id, host, protocol, state, collapsed, ports
                FROM scan_state_counts
                ORDER BY scan_id, host, protocol, state
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
            # Folded results live only here. Leaving them out of a backup would
            # restore a scan with most of its findings silently missing.
            "scan_state_counts": [dict(row) for row in folded_rows],
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
            "scan_state_counts": 0,
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
                for folded in data.get("scan_state_counts", []):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO scan_state_counts(
                            scan_id, host, protocol, state, collapsed, ports
                        )
                        VALUES(?, ?, ?, ?, ?, ?)
                        """,
                        (
                            folded["scan_id"],
                            folded["host"],
                            folded.get("protocol", "tcp"),
                            folded["state"],
                            int(folded.get("collapsed", 0)),
                            folded.get("ports") or "",
                        ),
                    )
                    counts["scan_state_counts"] += 1
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
                            stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                            created_at
                        )
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            evidence.get("capture_agent"),
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
                   stored_path, mime_type, size_bytes, sha256, source_url, capture_agent,
                   created_at
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
            # `open|filtered` counts as open here too, as the rest of this
            # module already has it: it is what a UDP scan calls a port that
            # did not refuse. Exporting only the exact state left a UDP scan's
            # findings out of the assessment workbook while the summary, the
            # evidence pass and the re-scan all went on counting them.
            query += f" AND state IN ({','.join('?' * len(OPEN_STATES))})"
            params.extend(OPEN_STATES)
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
        data["heartbeat_age_s"] = data.pop("heartbeat_age_s", None)
        data["scope"] = json.loads(data.pop("scope_json"))
        data["params"] = json.loads(data.pop("params_json"))
        summary_json = data.pop("summary_json")
        data["summary"] = json.loads(summary_json) if summary_json else None
        return data


def _count_targets(expr: str, max_hosts: Any = None) -> int:
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
