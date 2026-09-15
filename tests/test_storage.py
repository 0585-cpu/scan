import sqlite3
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from netroach.models import PortResult, ScanSummary, SendResult
from netroach.storage import SQLiteRepository, parse_port_ranges, spans_cover


class StorageTests(unittest.TestCase):
    def test_recoverable_jobs_are_claimed_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"resumable": True},
            )
            repo.mark_scan_started(scan_id)

            job = repo.list_recoverable_scan_jobs()[0]
            token = repo.claim_scan_for_recovery(
                scan_id,
                status=job["status"],
                worker_token=job["_worker_token"],
            )

            self.assertIsNotNone(token)
            self.assertIsNone(
                repo.claim_scan_for_recovery(scan_id, status=job["status"], worker_token=job["_worker_token"])
            )
            self.assertTrue(repo.mark_recovered_scan_started(scan_id, token))
            self.assertEqual(repo.get_job(scan_id)["status"], "running")

    def test_scan_job_and_results_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"timeout_ms": 800},
            )
            repo.mark_scan_started(scan_id)
            result = PortResult(
                scan_id=scan_id,
                host="127.0.0.1",
                port=80,
                state="open",
                latency_ms=1.2,
                service_confidence=0.98,
                evidence="test evidence",
            )
            repo.add_port_result(result)
            summary = ScanSummary(scan_id=scan_id)
            summary.observe(result)
            repo.complete_scan(scan_id, summary)

            job = repo.get_job(scan_id)
            self.assertIsNotNone(job)
            self.assertEqual(job["status"], "completed")
            stored = repo.get_results(scan_id)[0]
            self.assertEqual(stored["state"], "open")
            self.assertEqual(stored["evidence"], "test evidence")
            self.assertEqual(stored["latency_ms"], 1.2)
            self.assertEqual(stored["service_confidence"], 0.98)

    def test_packet_audit_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            audit_id = repo.save_packet_audit(
                request={"template": "icmp", "target": "127.0.0.1", "count": 1},
                result=SendResult(template="icmp", target="127.0.0.1", sent=1, duration_s=0.1, details={"payload_bytes": 0}),
            )
            self.assertTrue(audit_id)
            audit = repo.get_packet_audit(audit_id)
            self.assertIsNotNone(audit)
            self.assertEqual(audit["template"], "icmp")
            self.assertEqual(audit["target"], "127.0.0.1")
            self.assertEqual(audit["request"]["count"], 1)
            self.assertEqual(audit["result"]["sent"], 1)
            self.assertEqual(audit["result"]["details"]["payload_bytes"], 0)
            audits = repo.list_packet_audits(template="icmp")
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0]["id"], audit_id)

    def test_pcap_history_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            analysis_id = repo.save_pcap_analysis(
                "capture.pcap",
                {"packet_count": 3, "protocols": {"TCP": 2, "UDP": 1}},
            )

            analysis = repo.get_pcap_analysis(analysis_id)
            self.assertIsNotNone(analysis)
            self.assertEqual(analysis["file_path"], "capture.pcap")
            self.assertEqual(analysis["summary"]["packet_count"], 3)
            self.assertEqual(repo.list_pcap_analyses()[0]["id"], analysis_id)

    def test_oast_session_and_interaction_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            session = repo.create_oast_session(label="lab", base_url="http://127.0.0.1:8765", ttl_seconds=3600)
            interaction = repo.save_oast_interaction(
                session_id=session["id"],
                interaction={
                    "method": "POST",
                    "path": f"/oast/{session['token']}",
                    "query_string": "x=1",
                    "client_host": "127.0.0.1",
                    "headers": {"user-agent": "tester", "authorization": "[redacted]"},
                    "body_preview": "hello",
                    "body_truncated": False,
                },
            )

            self.assertEqual(repo.get_active_oast_session_by_token(session["token"])["id"], session["id"])
            interactions = repo.list_oast_interactions(session_id=session["id"])
            self.assertEqual(interactions[0]["id"], interaction["id"])
            self.assertEqual(interactions[0]["headers"]["authorization"], "[redacted]")
            self.assertFalse(interactions[0]["body_truncated"])

    def test_result_filters_and_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="53,80",
                scope=["127.0.0.0/8"],
                params={"protocol": "udp"},
            )
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=53,
                        protocol="udp",
                        state="open",
                        latency_ms=1.0,
                        service_name="dns",
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=80,
                        protocol="tcp",
                        state="closed",
                        latency_ms=2.0,
                    ),
                ]
            )

            results = repo.get_results(scan_id, state="open", protocol="udp", service="dns")

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["port"], 53)
            self.assertEqual(repo.count_results(scan_id, protocol="tcp"), 1)
            self.assertEqual(repo.get_results(scan_id, limit=1, offset=1)[0]["port"], 80)

    def test_result_host_search_and_state_summaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1,127.0.0.2",
                ports="22,80",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=22,
                        protocol="tcp",
                        state="open",
                        latency_ms=1.0,
                        service_name="ssh",
                        banner="OpenSSH test",
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=80,
                        protocol="tcp",
                        state="closed",
                        latency_ms=1.0,
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.2",
                        port=80,
                        protocol="tcp",
                        state="open",
                        latency_ms=1.0,
                        service_name="http",
                    ),
                ]
            )

            filtered = repo.get_results(scan_id, host="127.0.0.1", search="openssh")
            summaries = repo.summarize_results_by_host(scan_id)
            report_counts = repo.summarize_report_counts(scan_id)

            self.assertEqual([result["port"] for result in filtered], [22])
            self.assertEqual(repo.count_results(scan_id, host="127.0.0.1", state="closed"), 1)
            self.assertEqual(
                summaries,
                [
                    {"host": "127.0.0.1", "total": 2, "states": {"closed": 1, "open": 1}},
                    {"host": "127.0.0.2", "total": 1, "states": {"open": 1}},
                ],
            )
            self.assertEqual(report_counts["states"], {"closed": 1, "open": 2})
            self.assertEqual(report_counts["protocols"], {"tcp": 3})
            self.assertEqual(report_counts["services"], {"http": 1, "ssh": 1})
            self.assertEqual(report_counts["hosts_with_open_ports"], 2)
            self.assertEqual(report_counts["total"], 3)

    def test_report_results_prioritize_open_and_review_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="1,2,65000",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=1,
                        state="closed",
                        latency_ms=1.0,
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=2,
                        state="error",
                        latency_ms=1.0,
                        error="denied",
                    ),
                    PortResult(
                        scan_id=scan_id,
                        host="127.0.0.1",
                        port=65000,
                        state="open",
                        latency_ms=1.0,
                        service_name="http",
                    ),
                ]
            )

            prioritized = repo.get_report_results(scan_id, limit=2)

            self.assertEqual([result["port"] for result in prioritized], [65000, 2])

    def test_result_metadata_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_result(
                PortResult(scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="open", latency_ms=1.0)
            )

            result = repo.update_result_metadata(
                scan_id,
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                tags=["prod", "review", "prod"],
                note="check owner",
            )

            self.assertIsNotNone(result)
            self.assertEqual(result["tags"], ["prod", "review"])
            self.assertEqual(result["note"], "check owner")
            self.assertEqual(repo.get_results(scan_id)[0]["tags"], ["prod", "review"])

    def test_scan_progress_cancel_and_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1,127.0.0.2",
                ports="80,443",
                scope=["127.0.0.0/8"],
                params={"max_hosts": 10},
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_result(
                PortResult(scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="open", latency_ms=1.0)
            )

            progress = repo.get_scan_progress(scan_id)
            self.assertIsNotNone(progress)
            self.assertEqual(progress["status"], "running")
            self.assertEqual(progress["planned_total"], 4)
            self.assertEqual(progress["completed_results"], 1)
            self.assertEqual(progress["states"], {"open": 1})

            job = repo.request_scan_cancel(scan_id)
            self.assertIsNotNone(job)
            self.assertEqual(job["status"], "cancel_requested")
            self.assertTrue(repo.is_scan_cancel_requested(scan_id))

            repo.mark_scan_cancelled(scan_id, "test cancellation")
            self.assertEqual(repo.get_job(scan_id)["status"], "cancelled")

            self.assertTrue(repo.delete_scan(scan_id))
            self.assertIsNone(repo.get_job(scan_id))
            self.assertFalse(repo.delete_scan(scan_id))

    def test_cleanup_scan_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            old_id = repo.create_scan_job(targets="127.0.0.1", ports="80", scope=["127.0.0.0/8"], params={})
            new_id = repo.create_scan_job(targets="127.0.0.2", ports="80", scope=["127.0.0.0/8"], params={})
            with repo.session() as conn:
                conn.execute(
                    "UPDATE scan_jobs SET status='completed', completed_at='2000-01-01 00:00:00' WHERE id=?",
                    (old_id,),
                )
                conn.execute(
                    "UPDATE scan_jobs SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_id,),
                )

            dry_run = repo.cleanup_scan_jobs(older_than_days=1, dry_run=True)
            self.assertEqual(dry_run["scan_ids"], [old_id])
            self.assertIsNotNone(repo.get_job(old_id))

            result = repo.cleanup_scan_jobs(older_than_days=1)
            self.assertEqual(result["scan_ids"], [old_id])
            self.assertIsNone(repo.get_job(old_id))
            self.assertIsNotNone(repo.get_job(new_id))

    def test_database_export_import_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = SQLiteRepository(Path(tmp) / "source.db")
            scan_id = source.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={"protocol": "tcp"},
            )
            source.add_port_result(
                PortResult(
                    scan_id=scan_id,
                    host="127.0.0.1",
                    port=80,
                    protocol="tcp",
                    state="open",
                    latency_ms=1.0,
                    tags=["edge"],
                    note="important",
                )
            )
            evidence = source.add_result_evidence(
                scan_id,
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                data=b"\x89PNG\r\n\x1a\nbackup evidence",
                file_name="proof.png",
                evidence_type="terminal_transcript",
            )
            analysis_id = source.save_pcap_analysis("capture.pcap", {"packet_count": 1})
            audit_id = source.save_packet_audit(
                request={"template": "icmp", "target": "127.0.0.1"},
                result=SendResult(template="icmp", target="127.0.0.1", sent=1, duration_s=0.1),
            )
            oast_session = source.create_oast_session(label="lab", base_url="http://127.0.0.1:8765", ttl_seconds=3600)
            oast_interaction = source.save_oast_interaction(
                session_id=oast_session["id"],
                interaction={
                    "method": "GET",
                    "path": f"/oast/{oast_session['token']}",
                    "query_string": "",
                    "client_host": "127.0.0.1",
                    "headers": {"user-agent": "tester"},
                    "body_preview": "",
                    "body_truncated": False,
                },
            )

            backup = source.export_database()
            target = SQLiteRepository(Path(tmp) / "target.db")
            counts = target.import_database(backup, replace=True)

            self.assertEqual(counts["scan_jobs"], 1)
            self.assertEqual(counts["oast_sessions"], 1)
            self.assertEqual(counts["oast_interactions"], 1)
            self.assertEqual(counts["result_evidence_files"], 1)
            self.assertEqual(target.get_job(scan_id)["params"]["protocol"], "tcp")
            self.assertEqual(target.get_results(scan_id)[0]["tags"], ["edge"])
            restored_evidence = target.get_results(scan_id)[0]["evidence_files"][0]
            self.assertEqual(restored_evidence["id"], evidence["id"])
            self.assertEqual(restored_evidence["type"], "terminal_transcript")
            self.assertEqual(target.get_evidence_content(evidence["id"])[1].read_bytes(), b"\x89PNG\r\n\x1a\nbackup evidence")
            self.assertEqual(target.get_pcap_analysis(analysis_id)["summary"]["packet_count"], 1)
            self.assertEqual(target.get_packet_audit(audit_id)["result"]["sent"], 1)
            self.assertEqual(target.get_oast_session(oast_session["id"])["token"], oast_session["token"])
            self.assertEqual(
                target.list_oast_interactions(session_id=oast_session["id"])[0]["id"],
                oast_interaction["id"],
            )

    def test_result_image_evidence_round_trip_and_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_result(
                PortResult(
                    scan_id=scan_id,
                    host="127.0.0.1",
                    port=80,
                    state="open",
                    latency_ms=1.0,
                    service_name="http",
                )
            )

            evidence = repo.add_result_evidence(
                scan_id,
                host="127.0.0.1",
                port=80,
                data=b"\x89PNG\r\n\x1a\nmanual evidence",
                file_name="..\\proof.png",
            )

            self.assertEqual(evidence["file_name"], "proof.png")
            self.assertEqual(evidence["type"], "manual")
            self.assertIn("/v1/evidence/", evidence["download_url"])
            self.assertNotIn("stored_path", evidence)
            result = repo.get_result(scan_id, host="127.0.0.1", port=80)
            self.assertEqual(result["evidence_files"][0]["sha256"], evidence["sha256"])
            metadata, path = repo.get_evidence_content(evidence["id"])
            self.assertEqual(metadata["mime_type"], "image/png")
            self.assertTrue(path.is_file())
            with self.assertRaisesRegex(ValueError, "PNG, JPEG, GIF, or WebP"):
                repo.add_result_evidence(
                    scan_id,
                    host="127.0.0.1",
                    port=80,
                    data=b"plain text",
                    file_name="bad.txt",
                )

            self.assertTrue(repo.delete_evidence_file(evidence["id"]))
            self.assertFalse(path.exists())
            self.assertEqual(repo.get_result(scan_id, host="127.0.0.1", port=80)["evidence_files"], [])

    def test_a_port_never_gets_a_second_row(self):
        """One row per (scan, host, port, protocol), and the latest reading wins.

        This used to raise IntegrityError on the second write. The invariant
        worth keeping is the single row - raising was only the mechanism, and it
        was the wrong one: a resumed scan legitimately re-observes ports it
        already stored, and the exception killed the recovery thread.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80",
                scope=["127.0.0.0/8"],
                params={},
            )
            result = PortResult(scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="open", latency_ms=1.0)

            repo.add_port_result(result)
            repo.add_port_result(
                PortResult(
                    scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="closed", latency_ms=9.0
                )
            )

            self.assertEqual(repo.count_results(scan_id), 1)
            self.assertEqual(repo.get_result(scan_id, host="127.0.0.1", port=80)["state"], "closed")

    def test_complete_scan_rejects_summary_count_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1",
                ports="80,443",
                scope=["127.0.0.0/8"],
                params={},
            )
            repo.add_port_result(
                PortResult(scan_id=scan_id, host="127.0.0.1", port=80, protocol="tcp", state="open", latency_ms=1.0)
            )
            summary = ScanSummary(scan_id=scan_id, total=2, open=2)

            with self.assertRaisesRegex(ValueError, "summary total mismatch"):
                repo.complete_scan(scan_id, summary)


PNG_BYTES = bytes.fromhex("89504e470d0a1a0a") + b"evidence"


class ScanProgressCostTests(unittest.TestCase):
    """The progress strip polls this every 700ms while a scan runs."""

    def test_progress_counts_the_table_once(self):
        """It used to call COUNT(*) and then GROUP BY state, counting the same
        rows twice - 24ms of the 127 this took at half a million rows. Every
        result has a state, so the per-state counts already sum to the total."""
        from unittest.mock import patch

        from netroach.storage import PortResult, SQLiteRepository

        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="127.0.0.1", ports="1-3", scope=["127.0.0.1/32"], params={}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results(
                [
                    PortResult(scan_id=scan_id, host="127.0.0.1", port=1, state="open", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="127.0.0.1", port=2, state="closed", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="127.0.0.1", port=3, state="filtered", latency_ms=1.0),
                ]
            )

            with patch.object(SQLiteRepository, "count_results", side_effect=AssertionError("counted twice")):
                progress = repo.get_scan_progress(scan_id)

            self.assertEqual(progress["completed_results"], 3)
            self.assertEqual(progress["states"], {"open": 1, "closed": 1, "filtered": 1})

    def test_the_per_state_group_by_has_an_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.db"
            SQLiteRepository(path)
            conn = sqlite3.connect(path)
            try:
                names = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='port_results'"
                )}
            finally:
                conn.close()
            self.assertIn("idx_port_results_scan_state", names)
            self.assertIn("idx_port_results_scan_host_state", names)


class ScanHeartbeatTests(unittest.TestCase):
    """Distinguishing a dead worker from a live one in another process.

    Recovery claims any job that still reads 'running', and `worker_token`
    cannot tell a corpse from a peer: a normal run leaves it NULL. Two
    instances sharing the default database therefore both resumed the same
    scan. A heartbeat gives recovery something to check.
    """

    def _repo_with_running_job(self, tmp):
        from netroach.storage import SQLiteRepository

        repo = SQLiteRepository(Path(tmp) / "netroach.db")
        scan_id = repo.create_scan_job(
            targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={"resumable": True}
        )
        repo.mark_scan_started(scan_id)
        return repo, scan_id

    def test_a_database_without_the_column_gains_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._repo_with_running_job(tmp)
            conn = sqlite3.connect(Path(tmp) / "netroach.db")
            try:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_jobs)")}
            finally:
                conn.close()
            self.assertIn("heartbeat_at", columns)

    def test_a_fresh_heartbeat_marks_the_job_as_claimed_elsewhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_running_job(tmp)

            repo.record_scan_heartbeat(scan_id)

            self.assertTrue(repo.scan_looks_alive(scan_id, stale_after_s=60))

    def test_an_old_heartbeat_means_the_worker_is_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_running_job(tmp)
            repo.record_scan_heartbeat(scan_id)
            # Backdated rather than slept for: CURRENT_TIMESTAMP has one-second
            # resolution, so a real wait would make this test slow and flaky.
            conn = sqlite3.connect(Path(tmp) / "netroach.db")
            try:
                conn.execute(
                    "UPDATE scan_jobs SET heartbeat_at=datetime(CURRENT_TIMESTAMP, '-600 seconds') WHERE id=?",
                    (scan_id,),
                )
                conn.commit()
            finally:
                conn.close()

            self.assertFalse(repo.scan_looks_alive(scan_id, stale_after_s=120))
            self.assertTrue(repo.scan_looks_alive(scan_id, stale_after_s=1200))

    def test_a_job_that_never_beat_is_treated_as_dead(self):
        """Rows written before this column existed must stay recoverable."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_running_job(tmp)

            self.assertFalse(repo.scan_looks_alive(scan_id, stale_after_s=3600))


class ResumedScanIdempotenceTests(unittest.TestCase):
    """Re-observing a port must not kill the scan writing it.

    Recovery re-runs the work it believes is missing, and that belief can be
    stale - another worker, a batch that failed after a partial write, a crash
    between insert and commit. A resumed 65,535-port scan died on
    `UNIQUE constraint failed: port_results...`, leaving the job stuck in
    'running' with no thread behind it.
    """

    def _repo(self, tmp):
        from netroach.storage import SQLiteRepository

        return SQLiteRepository(Path(tmp) / "netroach.db")

    def _result(self, scan_id, **overrides):
        from netroach.storage import PortResult

        values = {
            "scan_id": scan_id,
            "host": "127.0.0.1",
            "port": 80,
            "state": "open",
            "latency_ms": 1.0,
            "service_name": "http",
        }
        values.update(overrides)
        return PortResult(**values)

    def test_rescanning_a_port_updates_it_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            scan_id = repo.create_scan_job(targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={})
            repo.add_port_results([self._result(scan_id, state="filtered", service_name=None)])

            repo.add_port_results([self._result(scan_id, state="open", service_name="http", latency_ms=2.5)])

            stored = repo.get_result(scan_id, host="127.0.0.1", port=80)
            self.assertEqual(stored["state"], "open")
            self.assertEqual(stored["service_name"], "http")
            self.assertEqual(repo.count_results(scan_id), 1)

    def test_a_batch_containing_a_repeat_still_writes_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            scan_id = repo.create_scan_job(targets="127.0.0.1", ports="80,81", scope=["127.0.0.1/32"], params={})
            repo.add_port_results([self._result(scan_id, port=80)])

            repo.add_port_results([self._result(scan_id, port=80), self._result(scan_id, port=81)])

            self.assertEqual(repo.count_results(scan_id), 2)

    def test_operator_annotations_survive_a_rescan(self):
        """A re-observation replaces what was measured, never what a person wrote."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            scan_id = repo.create_scan_job(targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={})
            repo.add_port_results([self._result(scan_id)])
            repo.update_result_metadata(scan_id, host="127.0.0.1", port=80, tags=["reviewed"], note="checked by hand")

            repo.add_port_results([self._result(scan_id, state="closed")])

            stored = repo.get_result(scan_id, host="127.0.0.1", port=80)
            self.assertEqual(stored["state"], "closed")
            self.assertEqual(stored["tags"], ["reviewed"])
            self.assertEqual(stored["note"], "checked by hand")


class EvidenceCaptureAgentTests(unittest.TestCase):
    def _repo_with_result(self, tmp):
        from netroach.storage import PortResult, SQLiteRepository

        repo = SQLiteRepository(Path(tmp) / "netroach.db")
        scan_id = repo.create_scan_job(targets="127.0.0.1", ports="80", scope=["127.0.0.1/32"], params={})
        repo.add_port_result(
            PortResult(scan_id=scan_id, host="127.0.0.1", port=80, state="open", latency_ms=1.0)
        )
        return repo, scan_id

    def test_evidence_records_what_captured_it(self):
        """Evidence that cannot say how it was produced is weaker evidence.

        The bundled browser is pinned so a screenshot stays reproducible; that
        only pays off if the record names the renderer and the viewport it used.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_result(tmp)

            evidence = repo.add_result_evidence(
                scan_id,
                host="127.0.0.1",
                port=80,
                data=PNG_BYTES,
                file_name="shot.png",
                evidence_type="web_screenshot",
                capture_agent="chromium 151.0.7922.34 800x600",
            )

            self.assertEqual(evidence["capture_agent"], "chromium 151.0.7922.34 800x600")
            stored = repo.get_evidence_file(evidence["id"])
            self.assertEqual(stored["capture_agent"], "chromium 151.0.7922.34 800x600")

    def test_every_read_path_exposes_the_agent(self):
        """Storing it is useless if the API's read paths drop the column.

        The result listing builds evidence through a separate query from
        get_evidence_file, and that one was missed the first time.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_result(tmp)
            agent = "chromium 151.0.7922.34 800x600"
            repo.add_result_evidence(
                scan_id,
                host="127.0.0.1",
                port=80,
                data=PNG_BYTES,
                file_name="shot.png",
                evidence_type="web_screenshot",
                capture_agent=agent,
            )

            listed = repo.list_result_evidence(scan_id, host="127.0.0.1", port=80)
            result = repo.get_result(scan_id, host="127.0.0.1", port=80)
            report = repo.get_report_results(scan_id)

            self.assertEqual(listed[0]["capture_agent"], agent)
            self.assertEqual(result["evidence_files"][0]["capture_agent"], agent)
            self.assertEqual(report[0]["evidence_files"][0]["capture_agent"], agent)

    def test_evidence_without_an_agent_is_still_accepted(self):
        """Manual uploads have no capturing tool, and old rows predate the column."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo_with_result(tmp)

            evidence = repo.add_result_evidence(
                scan_id, host="127.0.0.1", port=80, data=PNG_BYTES, file_name="m.png"
            )

            self.assertIsNone(evidence["capture_agent"])

    def test_a_database_without_the_column_gains_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.db"
            repo, scan_id = self._repo_with_result(tmp)
            repo.add_result_evidence(
                scan_id, host="127.0.0.1", port=80, data=PNG_BYTES, file_name="old.png"
            )
            # sqlite3's context manager commits but does not close, and an open
            # handle stops Windows removing the temporary directory.
            conn = sqlite3.connect(path)
            try:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(result_evidence_files)")}
            finally:
                conn.close()
            self.assertIn("capture_agent", columns)


class LegacyDataMigrationTests(unittest.TestCase):
    def test_pre_rename_database_and_artifacts_are_moved_once(self):
        from netroach.storage import migrate_legacy_data

        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "Scaprobe" / "scaprobe.db"
            legacy.parent.mkdir()
            legacy.write_bytes(b"old database")
            (legacy.parent / "scaprobe-artifacts").mkdir()
            (legacy.parent / "scaprobe-artifacts" / "shot.png").write_bytes(b"png")
            new = Path(tmp) / "Netroach" / "netroach.db"

            self.assertTrue(migrate_legacy_data(new, legacy))
            self.assertEqual(new.read_bytes(), b"old database")
            self.assertEqual((new.parent / "netroach-artifacts" / "shot.png").read_bytes(), b"png")
            self.assertFalse(legacy.exists())
            # A second start has nothing left to move.
            self.assertFalse(migrate_legacy_data(new, legacy))

    def test_existing_data_is_never_overwritten(self):
        from netroach.storage import migrate_legacy_data

        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "Scaprobe" / "scaprobe.db"
            legacy.parent.mkdir()
            legacy.write_bytes(b"old database")
            new = Path(tmp) / "Netroach" / "netroach.db"
            new.parent.mkdir()
            new.write_bytes(b"current database")

            self.assertFalse(migrate_legacy_data(new, legacy))
            self.assertEqual(new.read_bytes(), b"current database")
            self.assertTrue(legacy.is_file())


class MigrationCostTests(unittest.TestCase):
    """The dedupe below is a full table scan. It must run once, not per start."""

    def _sql_of_second_open(self, path):
        SQLiteRepository(path)
        statements = []
        real_connect = sqlite3.connect

        def tracing_connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)
            conn.set_trace_callback(statements.append)
            return conn

        sqlite3.connect = tracing_connect
        try:
            SQLiteRepository(path)
        finally:
            sqlite3.connect = real_connect
        return " ".join(statements)

    def test_dedupe_does_not_rerun_once_the_unique_index_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            sql = self._sql_of_second_open(Path(tmp) / "netroach.db")
            self.assertNotIn("DELETE FROM port_results", sql)

    def test_dedupe_still_runs_on_a_database_that_predates_the_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(path)
            scan_id = repo.create_scan_job(targets="127.0.0.1", ports="80", scope=[], params={})
            with repo.session() as conn:
                conn.execute("DROP INDEX idx_port_results_unique")
                for _ in range(2):
                    conn.execute(
                        "INSERT INTO port_results(scan_id, host, port, protocol, state)"
                        " VALUES(?, '127.0.0.1', 80, 'tcp', 'open')",
                        (scan_id,),
                    )

            SQLiteRepository(path)

            with SQLiteRepository(path).session() as conn:
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM port_results").fetchone()[0], 1
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='idx_port_results_unique'"
                    ).fetchone()
                )


class CollapsedStateTests(unittest.TestCase):
    """Bulk closed/filtered ports are kept as a count, the way nmap does it."""

    def _repo(self, tmp):
        repo = SQLiteRepository(Path(tmp) / "netroach.db")
        scan_id = repo.create_scan_job(targets="10.0.0.1", ports="1-3000", scope=[], params={})
        return repo, scan_id

    def _write(self, repo, scan_id, host, state, count, first_port=1):
        repo.add_port_results(
            [
                PortResult(
                    scan_id=scan_id,
                    host=host,
                    port=first_port + offset,
                    protocol="tcp",
                    state=state,
                    latency_ms=None,
                )
                for offset in range(count)
            ]
        )

    def test_a_small_group_stays_row_by_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 25)

            self.assertEqual(repo.count_results_by_state(scan_id), {"filtered": 25})
            with repo.session() as conn:
                stored = conn.execute("SELECT count(*) FROM port_results").fetchone()[0]
            self.assertEqual(stored, 25)

    def test_a_large_group_is_replaced_by_its_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)

            # The count is still exact, which is what progress and the host
            # list are built from.
            self.assertEqual(repo.count_results_by_state(scan_id), {"filtered": 2000})
            with repo.session() as conn:
                stored = conn.execute("SELECT count(*) FROM port_results").fetchone()[0]
            self.assertEqual(stored, 0)

    def test_a_scan_narrow_per_host_and_wide_overall_still_folds(self):
        """The allowance was counted per host and nowhere else.

        A hundred hosts with fifteen quiet ports each left fifteen hundred rows
        in the table - every host inside its own allowance, the table past what
        anyone reads - and one more host crossed the host limit and folded the
        same fifteen hundred away. That is a cliff rather than a rule, and the
        wrong side of it is the ordinary shape of an assessment: a host list
        with a short port list.

        A genuinely small scan still keeps its rows, because a handful of
        closed ports does read better as ports than as a range.
        """
        def stored(hosts, ports):
            with tempfile.TemporaryDirectory() as tmp:
                repo = SQLiteRepository(Path(tmp) / "netroach.db")
                scan_id = repo.create_scan_job(
                    targets="10.0.0.0/24", ports="1-100", scope=[], params={}
                )
                repo.add_port_results([
                    PortResult(
                        scan_id=scan_id, host=f"10.0.{host // 256}.{host % 256}",
                        port=1000 + port, protocol="tcp", state="filtered",
                        latency_ms=None, error="timeout",
                    )
                    for host in range(hosts) for port in range(ports)
                ])
                return len(repo.get_results(scan_id))

        # Small enough to read: kept, as before.
        self.assertEqual(stored(10, 15), 150)
        # Past what anyone reads, however it is spread: folded.
        self.assertEqual(stored(50, 15), 0)
        self.assertEqual(stored(100, 15), 0)
        # One host with more than its own allowance folds, as before.
        self.assertEqual(stored(1, 100), 0)

    def _without_cascade(self, db: Path) -> None:
        """Rebuild scan_state_counts the way a build without the clause made it.

        `CREATE TABLE IF NOT EXISTS` never alters a table that exists, so a
        database created by such a build keeps that definition for good.
        """
        conn = sqlite3.connect(db)
        conn.executescript(
            """
            PRAGMA foreign_keys = OFF;
            ALTER TABLE scan_state_counts RENAME TO old_counts;
            CREATE TABLE scan_state_counts (
                scan_id TEXT NOT NULL, host TEXT NOT NULL, protocol TEXT NOT NULL,
                state TEXT NOT NULL, collapsed INTEGER NOT NULL,
                ports TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(scan_id, host, protocol, state),
                FOREIGN KEY(scan_id) REFERENCES scan_jobs(id)
            );
            INSERT INTO scan_state_counts SELECT * FROM old_counts;
            DROP TABLE old_counts;
            """
        )
        conn.commit()
        conn.close()

    def test_a_scan_deletes_from_a_database_written_without_the_cascade(self):
        """Deleting relied on ON DELETE CASCADE being in the database it got.

        It is in this schema and has been from the first release, but a
        database this application opens may have been written by another build
        on another machine - loading someone else's results is a feature - and
        one created without the clause keeps its definition. The delete then
        raised FOREIGN KEY constraint failed and removed nothing, which is what
        a user reported. Reproduced with a single folded row.

        It also stopped being rare when it did: folding only began filling that
        table on an ordinary assessment once its allowance counted the scan
        rather than each host, so a database that had always been missing the
        clause had nothing in it to trip over until then.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db)
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="1-50", scope=[], params={}
            )
            repo.add_port_results([
                PortResult(
                    scan_id=scan_id, host="10.0.0.1", port=port, protocol="tcp",
                    state="filtered", latency_ms=None, error="timeout",
                )
                for port in range(1, 51)
            ])
            self._without_cascade(db)
            conn = sqlite3.connect(db)
            folded = conn.execute("SELECT COUNT(*) FROM scan_state_counts").fetchone()[0]
            conn.close()
            self.assertGreater(folded, 0, "the row that used to block the delete")

            self.assertTrue(repo.delete_scan(scan_id))

            conn = sqlite3.connect(db)
            for table in ("scan_jobs", "port_results", "scan_state_counts"):
                self.assertEqual(
                    conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table
                )
            conn.close()

    def test_a_scan_deletes_from_a_database_carrying_tables_we_never_made(self):
        """Which children there are is asked of the database, not listed here.

        The bundle the results manager exports is a database this application
        opens and did not write. It declares five references to a scan and none
        of them cascade, two being tables of its own - so a list of the three
        this schema knows deleted those three and failed on the rest, measured
        against a bundle built from the manager's own definition.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "bundle.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                CREATE TABLE scan_jobs(
                    id TEXT PRIMARY KEY, status TEXT NOT NULL, targets TEXT NOT NULL,
                    ports TEXT NOT NULL, scope_json TEXT NOT NULL, params_json TEXT NOT NULL,
                    created_at TEXT, started_at TEXT, completed_at TEXT, summary_json TEXT,
                    worker_token TEXT, heartbeat_at TEXT);
                CREATE TABLE port_results(
                    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scan_jobs(id),
                    host TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
                    state TEXT NOT NULL, latency_ms REAL, service_name TEXT,
                    service_confidence REAL, banner TEXT, evidence TEXT, error TEXT,
                    tags_json TEXT, note TEXT, created_at TEXT);
                CREATE TABLE scan_state_counts(
                    scan_id TEXT NOT NULL REFERENCES scan_jobs(id), host TEXT NOT NULL,
                    protocol TEXT NOT NULL, state TEXT NOT NULL, collapsed INTEGER NOT NULL,
                    ports TEXT DEFAULT '', PRIMARY KEY(scan_id, host, protocol, state));
                CREATE TABLE result_evidence_files(
                    id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scan_jobs(id),
                    host TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
                    stored_path TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL);
                -- The two the manager adds, which this schema has never heard of.
                CREATE TABLE manager_endpoint_metadata(
                    scan_id TEXT REFERENCES scan_jobs(id), host TEXT, protocol TEXT,
                    port INTEGER, context_json TEXT,
                    PRIMARY KEY(scan_id, host, protocol, port));
                CREATE TABLE manager_observation_order(
                    ordinal INTEGER PRIMARY KEY, scan_id TEXT REFERENCES scan_jobs(id),
                    host TEXT, protocol TEXT, port INTEGER);
                INSERT INTO scan_jobs VALUES
                    ('s1','completed','10.0.0.1','80','[]','{}','t','t','t','{}',NULL,NULL);
                INSERT INTO port_results VALUES
                    (1,'s1','10.0.0.1',80,'tcp','open',1.0,'http',0.9,'x',NULL,NULL,'[]',NULL,'t');
                INSERT INTO scan_state_counts VALUES('s1','10.0.0.1','tcp','filtered',49,'1-79');
                INSERT INTO result_evidence_files VALUES('e1','s1','10.0.0.1',80,'tcp','p',1,'h');
                INSERT INTO manager_endpoint_metadata VALUES('s1','10.0.0.1','tcp',80,'{}');
                INSERT INTO manager_observation_order VALUES(1,'s1','10.0.0.1','tcp',80);
                """
            )
            conn.commit()
            conn.close()

            self.assertTrue(SQLiteRepository(db).delete_scan("s1"))

            conn = sqlite3.connect(db)
            for table in (
                "scan_jobs", "port_results", "scan_state_counts", "result_evidence_files",
                "manager_endpoint_metadata", "manager_observation_order",
            ):
                self.assertEqual(
                    conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table
                )
            conn.close()

    def test_a_port_list_stored_spelled_out_is_rewritten_as_ranges(self):
        """The job list sends this string on every dashboard poll.

        A build old enough wrote it port by port. Measured on a real history: a
        single 65,535-port job holds 382KB, thirty-nine jobs hold 2.0MB, and
        the list shipped all of it every 700 milliseconds while a scan ran.
        New jobs are stored as ranges; the rows already written kept what they
        had, and a database handed over from another machine brings them along.
        """
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "netroach.db"
            repo = SQLiteRepository(db)
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="1-3", scope=[], params={}
            )
            short = repo.create_scan_job(
                targets="10.0.0.1", ports="80,443", scope=[], params={}
            )
            spelled_out = ",".join(str(port) for port in range(1, 65536))
            conn = sqlite3.connect(db)
            conn.execute("UPDATE scan_jobs SET ports=? WHERE id=?", (spelled_out, scan_id))
            conn.commit()
            conn.close()
            self.assertGreater(len(spelled_out), 380_000)

            SQLiteRepository(db)  # opening it is what migrates

            conn = sqlite3.connect(db)
            rewritten = conn.execute(
                "SELECT ports FROM scan_jobs WHERE id=?", (scan_id,)
            ).fetchone()[0]
            untouched = conn.execute(
                "SELECT ports FROM scan_jobs WHERE id=?", (short,)
            ).fetchone()[0]
            conn.close()

            self.assertEqual(rewritten, "1-65535")
            # The same set of ports, written the short way.
            self.assertEqual(parse_port_ranges(rewritten), [(1, 65535)])
            # A list already short enough to read is left exactly as it was.
            self.assertEqual(untouched, "80,443")

    def test_open_ports_are_never_collapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "open", 100)

            with repo.session() as conn:
                stored = conn.execute("SELECT count(*) FROM port_results").fetchone()[0]
            self.assertEqual(stored, 100)

    def test_a_few_filtered_ports_survive_a_flood_of_closed_ones(self):
        """The minority state is the interesting one - it must stay addressable."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "closed", 2000, first_port=1)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 3, first_port=9000)

            with repo.session() as conn:
                ports = [
                    row["port"]
                    for row in conn.execute("SELECT port FROM port_results ORDER BY port")
                ]
            self.assertEqual(ports, [9000, 9001, 9002])
            self.assertEqual(
                repo.count_results_by_state(scan_id), {"closed": 2000, "filtered": 3}
            )

    def test_a_wide_scan_does_not_keep_a_few_rows_per_host(self):
        """The allowance is per host, so its cost is the host count.

        A handful of closed ports reads better as ports than as a range, which
        is why small groups are kept. Across ten subnets that same allowance is
        tens of thousands of rows nobody reads, on a scan where only the open
        ports are looked at. The ranges are recorded either way.
        """
        from netroach.models import PortResult

        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            # One batch spanning many hosts, each with fewer rows than the
            # per-host allowance would keep.
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host=f"10.0.{block}.{host}",
                        port=port,
                        protocol="tcp",
                        state="closed",
                        latency_ms=None,
                    )
                    for block in range(2)
                    for host in range(1, 101)
                    for port in range(1, 6)
                ]
            )

            with repo.session() as conn:
                stored = conn.execute("SELECT count(*) FROM port_results").fetchone()[0]
            self.assertEqual(stored, 0, "a wide scan keeps no uninformative rows")
            self.assertEqual(repo.count_results_by_state(scan_id), {"closed": 1000})

    def test_a_narrow_scan_still_keeps_the_detail(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "closed", 5)

            with repo.session() as conn:
                stored = conn.execute("SELECT count(*) FROM port_results").fetchone()[0]
            self.assertEqual(stored, 5, "a few ports on one host stay addressable")

    def test_a_row_carrying_a_banner_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)
            repo.add_port_results(
                [
                    PortResult(
                        scan_id=scan_id,
                        host="10.0.0.1",
                        port=8080,
                        protocol="tcp",
                        state="filtered",
                        latency_ms=None,
                        banner="partial response",
                    )
                ]
            )

            with repo.session() as conn:
                kept = conn.execute("SELECT port, banner FROM port_results").fetchall()
            self.assertEqual([(row["port"], row["banner"]) for row in kept], [(8080, "partial response")])
            self.assertEqual(repo.count_results_by_state(scan_id), {"filtered": 2001})

    def test_the_host_list_still_reports_a_fully_filtered_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)

            summaries = repo.summarize_results_by_host(scan_id)
            self.assertEqual(
                summaries,
                [{"host": "10.0.0.1", "total": 2000, "states": {"filtered": 2000}}],
            )

    def test_rerunning_a_scan_does_not_double_count(self):
        """Recovery re-probes everything, so the counters must start over."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            repo.mark_scan_started(scan_id)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)

            token = repo.claim_scan_for_recovery(scan_id, status="running", worker_token=None)
            self.assertIsNotNone(token)
            self.assertEqual(repo.count_results_by_state(scan_id), {})
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)

            self.assertEqual(repo.count_results_by_state(scan_id), {"filtered": 2000})

    def test_scans_recorded_before_this_shipped_are_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            with repo.session() as conn:
                conn.executemany(
                    "INSERT INTO port_results(scan_id, host, port, protocol, state)"
                    " VALUES(?, '10.0.0.1', ?, 'tcp', 'filtered')",
                    [(scan_id, port) for port in range(1, 2001)],
                )

            self.assertEqual(repo.count_results_by_state(scan_id), {"filtered": 2000})
            self.assertEqual(
                repo.summarize_results_by_host(scan_id),
                [{"host": "10.0.0.1", "total": 2000, "states": {"filtered": 2000}}],
            )

    def test_completion_counts_folded_results_as_stored(self):
        """The check guards against lost results; folded ones are not lost."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            repo.mark_scan_started(scan_id)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)
            summary = ScanSummary(scan_id=scan_id, total=2000, filtered=2000)

            repo.complete_scan(scan_id, summary)

            self.assertEqual(repo.get_job(scan_id)["status"], "completed")

    def test_completion_still_rejects_results_that_went_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            repo.mark_scan_started(scan_id)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)
            summary = ScanSummary(scan_id=scan_id, total=2500, filtered=2500)

            with self.assertRaisesRegex(ValueError, "summary total mismatch"):
                repo.complete_scan(scan_id, summary)

    def test_a_resumed_scan_knows_which_folded_ports_were_done(self):
        """Folding must not make finished work look unfinished."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            repo.mark_scan_started(scan_id)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000, first_port=1)

            spans = repo.get_completed_port_spans(scan_id, protocol="tcp")

            self.assertEqual(spans, {"10.0.0.1": [(1, 2000)]})
            self.assertTrue(spans_cover(spans["10.0.0.1"], 1))
            self.assertTrue(spans_cover(spans["10.0.0.1"], 2000))
            self.assertFalse(spans_cover(spans["10.0.0.1"], 2001))

    def test_folded_ports_survive_a_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._repo(tmp)
            self._write(repo, scan_id, "10.0.0.1", "filtered", 2000)
            exported = repo.export_database()

            restored = SQLiteRepository(Path(tmp) / "restored.db")
            restored.import_database(exported)

            self.assertEqual(restored.count_results_by_state(scan_id), {"filtered": 2000})
            self.assertEqual(
                restored.get_completed_port_spans(scan_id, protocol="tcp"),
                {"10.0.0.1": [(1, 2000)]},
            )


_PNG_BYTES = bytes([137, 80, 78, 71, 13, 10, 26, 10]) + b"shot"


class DatabaseMergeTests(unittest.TestCase):
    """Loading another machine's Netroach data folder into this one."""

    def _populate(self, path, *, host):
        repo = SQLiteRepository(path)
        scan_id = repo.create_scan_job(targets=host, ports="1-100", scope=[], params={})
        repo.add_port_results(
            [
                PortResult(
                    scan_id=scan_id, host=host, port=80, protocol="tcp",
                    state="open", latency_ms=1.0,
                )
            ]
            + [
                PortResult(
                    scan_id=scan_id, host=host, port=port, protocol="tcp",
                    state="filtered", latency_ms=None,
                )
                for port in range(1000, 1100)
            ]
        )
        repo.add_result_evidence(
            scan_id, host=host, port=80, data=_PNG_BYTES, file_name="shot.png"
        )
        return repo, scan_id

    def test_another_databases_scans_results_and_evidence_are_merged_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, source_scan = self._populate(Path(tmp) / "source" / "netroach.db", host="10.0.0.1")
            target, target_scan = self._populate(Path(tmp) / "target" / "netroach.db", host="192.168.0.1")

            counts = target.import_from_database(source.path)

            self.assertEqual(counts["scan_jobs"], 1)
            # Both scans are present: importing adds, it does not replace.
            self.assertEqual({str(job["id"]) for job in target.list_jobs(limit=10)},
                             {source_scan, target_scan})
            self.assertEqual(target.count_results_by_state(source_scan), {"open": 1, "filtered": 100})
            evidence = target.list_result_evidence(source_scan, host="10.0.0.1", port=80)
            self.assertEqual(len(evidence), 1)
            found = target.get_evidence_content(evidence[0]["id"])
            self.assertIsNotNone(found, "the evidence image itself has to travel with the row")
            self.assertEqual(found[1].read_bytes(), _PNG_BYTES)

    def test_importing_the_same_database_twice_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, source_scan = self._populate(Path(tmp) / "source" / "netroach.db", host="10.0.0.1")
            target = SQLiteRepository(Path(tmp) / "target" / "netroach.db")

            target.import_from_database(source.path)
            target.import_from_database(source.path)

            self.assertEqual(len(target.list_jobs(limit=10)), 1)
            self.assertEqual(target.count_results_by_state(source_scan), {"open": 1, "filtered": 100})

    def test_a_column_the_other_build_added_does_not_fail_the_whole_import(self):
        """The database being carried in was written by whatever build ran that
        scan, which is the reason to carry it. A newer source used to fail the
        import outright instead of bringing across everything both sides hold."""
        with tempfile.TemporaryDirectory() as tmp:
            source, source_scan = self._populate(Path(tmp) / "source" / "netroach.db", host="10.0.0.1")
            conn = sqlite3.connect(source.path)
            try:
                conn.execute("ALTER TABLE port_results ADD COLUMN future_note TEXT")
                conn.execute("UPDATE port_results SET future_note='from a later build'")
                conn.commit()
            finally:
                conn.close()
            target = SQLiteRepository(Path(tmp) / "target" / "netroach.db")

            target.import_from_database(source.path)

            self.assertEqual(target.count_results_by_state(source_scan), {"open": 1, "filtered": 100})

    def test_a_udp_scans_hosts_are_counted_as_holding_something_open(self):
        """The report card reads "open 포트 보유 호스트". A UDP scan whose ports
        are open|filtered used to put 0 there while listing them as open."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="10.0.0.1,10.0.0.2", ports="161", scope=[], params={"protocol": "udp"}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results([
                PortResult(scan_id=scan_id, host="10.0.0.1", port=161, protocol="udp",
                           state="open|filtered", latency_ms=None),
                PortResult(scan_id=scan_id, host="10.0.0.2", port=161, protocol="udp",
                           state="open|filtered", latency_ms=None),
                PortResult(scan_id=scan_id, host="10.0.0.3", port=161, protocol="udp",
                           state="closed", latency_ms=1.0),
            ])

            counts = repo.summarize_report_counts(scan_id)

            self.assertEqual(counts["hosts_with_open_ports"], 2)

    def test_deleting_a_scan_gives_the_disk_back(self):
        """SQLite keeps the pages a delete frees and the file stays the size it
        grew to. An operator deleting scans to recover from a database that had
        grown to gigabytes saw nothing change - which is what they were
        deleting them for."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = SQLiteRepository(root / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="1-4000", scope=[], params={}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results([
                PortResult(scan_id=scan_id, host="10.0.0.1", port=port, protocol="tcp",
                           state="open", latency_ms=1.0, banner="x" * 200)
                for port in range(1, 4001)
            ])
            repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))
            def size() -> int:
                return sum(f.stat().st_size for f in root.glob("netroach.db*"))

            before = size()

            self.assertTrue(repo.delete_scan(scan_id))

            self.assertLess(size(), before / 2, "the file kept the pages the delete freed")
            # And the database still works afterwards.
            self.assertEqual(repo.list_jobs(limit=10), [])

    def test_open_only_carries_the_state_a_udp_port_answers_with(self):
        """The assessment workbook is exported with this filter. A UDP port
        that did not refuse is open|filtered, and the summary, the evidence
        pass and the re-scan all count it - leaving it out here dropped a UDP
        scan's findings out of the report while the app went on reporting them."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="10.0.0.1", ports="53,161", scope=[], params={"protocol": "udp"}
            )
            repo.mark_scan_started(scan_id)
            repo.add_port_results([
                PortResult(scan_id=scan_id, host="10.0.0.1", port=53, protocol="udp",
                           state="open", latency_ms=2.0),
                PortResult(scan_id=scan_id, host="10.0.0.1", port=161, protocol="udp",
                           state="open|filtered", latency_ms=None),
                PortResult(scan_id=scan_id, host="10.0.0.1", port=99, protocol="udp",
                           state="closed", latency_ms=1.0),
            ])

            exported = repo.get_results(scan_id, open_only=True)

            self.assertEqual(
                {(row["port"], row["state"]) for row in exported},
                {(53, "open"), (161, "open|filtered")},
            )
            self.assertEqual(len(exported), repo.count_open_results(scan_id))
            # state= stays an exact filter: it is how an operator narrows to one.
            self.assertEqual(
                [row["port"] for row in repo.get_results(scan_id, state="open|filtered")], [161]
            )

    def test_importing_a_file_that_is_not_a_database_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = SQLiteRepository(Path(tmp) / "netroach.db")
            junk = Path(tmp) / "notes.txt"
            junk.write_text("not a database", encoding="utf-8")

            with self.assertRaises(ValueError):
                target.import_from_database(junk)

    def test_importing_a_missing_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = SQLiteRepository(Path(tmp) / "netroach.db")

            with self.assertRaises(ValueError):
                target.import_from_database(Path(tmp) / "nothing.db")


class EvidenceCoverageTests(unittest.TestCase):
    """An operator has to be able to see that most ports were never tried."""

    def _scan_with_open_ports(self, tmp, count):
        repo = SQLiteRepository(Path(tmp) / "netroach.db")
        scan_id = repo.create_scan_job(targets="10.0.0.1", ports="1-2000", scope=[], params={})
        repo.add_port_results(
            [
                PortResult(
                    scan_id=scan_id, host="10.0.0.1", port=8000 + offset, protocol="tcp",
                    state="open", latency_ms=1.0,
                )
                for offset in range(count)
            ]
        )
        return repo, scan_id

    def _scan_with_open_ports_per_host(self, tmp, counts):
        """Open ports spread unevenly over several hosts.

        The single-host fixture above cannot see a per-host budget at all: with
        one host, sharing the budget between hosts and spending it all on the
        first are the same behaviour.
        """
        repo = SQLiteRepository(Path(tmp) / "netroach.db")
        scan_id = repo.create_scan_job(
            targets=",".join(counts), ports="1-2000", scope=[], params={}
        )
        repo.add_port_results(
            [
                PortResult(
                    scan_id=scan_id, host=host, port=port, protocol="tcp",
                    state="open", latency_ms=1.0,
                )
                for host, ports in counts.items()
                for port in ports
            ]
        )
        return repo, scan_id

    def test_one_host_cannot_take_the_whole_capture_budget(self):
        """A host with many open ports used to leave the next hosts with none.

        Ordered by host and port and cut at a total, the first host consumed
        the candidate list and every host after it was never a candidate - so
        the scan reported evidence while whole hosts had none at all.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports_per_host(
                tmp,
                {
                    "10.0.0.1": range(1, 51),
                    "10.0.0.2": [22, 80, 443],
                    "10.0.0.3": range(1, 51),
                },
            )

            candidates = repo.get_automatic_evidence_candidates(
                scan_id, limit=1000, per_host=10
            )

            taken = Counter(str(candidate["host"]) for candidate in candidates)
            self.assertEqual(taken["10.0.0.1"], 10)
            self.assertEqual(taken["10.0.0.2"], 3, "a host is never padded past what it has")
            self.assertEqual(taken["10.0.0.3"], 10, "the third host is still reached")

    def test_a_host_spends_its_budget_on_its_lowest_ports(self):
        """Which ports the budget buys decides whether it bought anything.

        A full-port scan of a Windows host finds its services low and a tail of
        ephemeral RPC ports above 49152. Spent on the tail, a per-host budget
        photographs nothing worth reporting.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports_per_host(
                tmp, {"10.0.0.1": [135, 139, 445, 3389, 5985, 49152, 49153, 49154]}
            )

            candidates = repo.get_automatic_evidence_candidates(
                scan_id, limit=1000, per_host=5
            )

            self.assertEqual(
                [int(candidate["port"]) for candidate in candidates],
                [135, 139, 445, 3389, 5985],
            )

    def test_a_port_that_answered_outranks_one_that_only_stayed_silent(self):
        """A UDP scan fills the budget with ports that replied nothing.

        `open|filtered` means the probe drew no reply, and it is worth a record
        - but not ahead of a port that answered. Ranked by port alone, a host
        whose 161 and 500 replied and whose thirteen other ports did not spent
        nine of its ten places on silence and left 500 with no evidence at all,
        which is the one row an assessment would have quoted.
        """
        answered = {161, 500}
        ports = [53, 67, 68, 69, 80, 108, 111, 131, 161, 162, 445, 500, 514, 542, 3391]
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(
                targets="10.0.0.5", ports=",".join(map(str, ports)), scope=[],
                params={"protocol": "udp"},
            )
            repo.add_port_results([
                PortResult(
                    scan_id=scan_id, host="10.0.0.5", port=port, protocol="udp",
                    state="open" if port in answered else "open|filtered",
                    latency_ms=1.0 if port in answered else None,
                )
                for port in ports
            ])

            candidates = repo.get_automatic_evidence_candidates(
                scan_id, limit=1000, per_host=10
            )

            taken = {int(candidate["port"]) for candidate in candidates}
            self.assertEqual(len(taken), 10)
            self.assertTrue(answered <= taken, sorted(taken))
            # The rest of the budget still goes to the lowest silent ports.
            self.assertEqual(sorted(taken - answered), [53, 67, 68, 69, 80, 108, 111, 131])

    def test_the_total_still_bounds_a_scan_of_many_hosts(self):
        """The per-host budget raises coverage; it must not remove the ceiling
        that keeps the evidence pass from running for hours."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports_per_host(
                tmp, {f"10.0.0.{last}": range(1, 51) for last in range(1, 6)}
            )

            candidates = repo.get_automatic_evidence_candidates(
                scan_id, limit=25, per_host=10
            )

            self.assertEqual(len(candidates), 25)
            taken = Counter(str(candidate["host"]) for candidate in candidates)
            self.assertEqual(sorted(taken.values(), reverse=True), [10, 10, 5])

    def test_the_eligible_count_ignores_the_capture_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports(tmp, 100)

            # These hundred ports are all on one host, so the per-host budget
            # is what binds rather than the total of twenty - which is the
            # point of it. The eligible count still reports all hundred, and
            # that gap is what tells the operator coverage was partial.
            candidates = repo.get_automatic_evidence_candidates(scan_id, limit=20, per_host=10)
            self.assertEqual(len(candidates), 10)
            self.assertEqual(repo.count_automatic_evidence_candidates(scan_id), 100)

    def test_a_scan_that_only_tried_some_of_its_ports_records_that(self):
        """captured == candidates looks like success; it is not when the
        candidate list was cut to the limit before anything was tried."""
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports(tmp, 100)
            repo.mark_scan_started(scan_id)
            repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))

            repo.record_evidence_capture_failures(
                scan_id, candidates=20, captured=20, without_evidence=0, errors=[], eligible=100
            )

            evidence = repo.get_job(scan_id)["summary"]["evidence"]
            self.assertEqual(evidence["eligible"], 100)
            self.assertEqual(evidence["captured"], 20)
            self.assertEqual(evidence["not_attempted"], 80)

    def test_a_scan_that_covered_everything_records_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, scan_id = self._scan_with_open_ports(tmp, 5)
            repo.mark_scan_started(scan_id)
            repo.complete_scan(scan_id, repo.summarize_scan_results(scan_id))

            repo.record_evidence_capture_failures(
                scan_id, candidates=5, captured=5, without_evidence=0, errors=[], eligible=5
            )

            self.assertNotIn("evidence", repo.get_job(scan_id)["summary"])


class OpenResultTargetsTests(unittest.TestCase):
    """Turning what a scan found back into what a scan takes."""

    def test_the_open_hosts_and_ports_come_back_as_expressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(targets="10.0.0.0/24", ports="1-100", scope=[], params={})
            repo.add_port_results(
                [
                    PortResult(scan_id=scan_id, host="10.0.0.2", port=80, protocol="tcp",
                               state="open", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="10.0.0.2", port=81, protocol="tcp",
                               state="open", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="10.0.0.1", port=443, protocol="tcp",
                               state="open", latency_ms=1.0),
                    PortResult(scan_id=scan_id, host="10.0.0.9", port=22, protocol="tcp",
                               state="closed", latency_ms=1.0),
                ]
            )

            targets, ports = repo.open_result_targets(scan_id)

            self.assertEqual(targets, ["10.0.0.1", "10.0.0.2"])
            self.assertEqual(ports, [80, 81, 443])

    def test_a_udp_scans_open_filtered_ports_count_as_open(self):
        """It is what a UDP scan calls a port that did not refuse; leaving it
        out would give a UDP scan nothing to re-scan."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(targets="10.0.0.1", ports="53", scope=[], params={})
            repo.add_port_results(
                [
                    PortResult(scan_id=scan_id, host="10.0.0.1", port=53, protocol="udp",
                               state="open|filtered", latency_ms=None),
                ]
            )

            self.assertEqual(repo.open_result_targets(scan_id), (["10.0.0.1"], [53]))

    def test_a_scan_with_nothing_open_gives_nothing_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SQLiteRepository(Path(tmp) / "netroach.db")
            scan_id = repo.create_scan_job(targets="10.0.0.1", ports="1-10", scope=[], params={})

            self.assertEqual(repo.open_result_targets(scan_id), ([], []))


if __name__ == "__main__":
    unittest.main()
