import sqlite3
import tempfile
import unittest
from pathlib import Path

from netroach.models import PortResult, ScanSummary, SendResult
from netroach.storage import SQLiteRepository


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

    def test_duplicate_port_results_are_rejected(self):
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
            with self.assertRaises(sqlite3.IntegrityError):
                repo.add_port_result(result)

            self.assertEqual(repo.count_results(scan_id), 1)

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


if __name__ == "__main__":
    unittest.main()
