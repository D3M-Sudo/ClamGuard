#!/usr/bin/env python3
import os
import tempfile
import unittest

from src.core.history import HistoryManager


class TestHistory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_history_db_permissions(self):
        """Verify that the history database file has secure 0o600 permissions."""
        db_path = os.path.join(self.tmpdir, "history_test.db")
        manager = HistoryManager(db_path=db_path)
        self.assertIsNotNone(manager)
        self.assertTrue(os.path.exists(db_path))
        mode = os.stat(db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_csv_injection_prevention(self):
        """Verify that CSV exports sanitize formula injection characters to prevent CWE-1236."""
        db_path = os.path.join(self.tmpdir, "history_test.db")
        csv_path = os.path.join(self.tmpdir, "export.csv")
        manager = HistoryManager(db_path=db_path)

        # Targets with various formula injection characters
        targets = [
            "=1+1",
            "+1+1",
            "-1+1",
            "@SUM(A1:A2)",
            "\t=cmd",
            "\r=cmd",
            "normal_target",
        ]

        for idx, target in enumerate(targets):
            scan_id = manager.start_scan("quick", target)
            manager.finish_scan(scan_id, 10 + idx, 0, [])

        manager.export_csv(csv_path)
        self.assertTrue(os.path.exists(csv_path))

        import csv

        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(
                header, ["ID", "Type", "Target", "Start", "End", "Files", "Threats"]
            )

            rows = list(reader)
            # Ordered DESC by start_time, so the last inserted is the first row
            # Let's map target to its sanitized form and verify
            for row in rows:
                target_val = row[2]
                if target_val.endswith("normal_target"):
                    self.assertEqual(target_val, "normal_target")
                else:
                    self.assertTrue(
                        target_val.startswith("'"),
                        f"Failed to sanitize target: {target_val}",
                    )


class TestSummaryStats(unittest.TestCase):
    """Regressione: get_summary_stats() è il metodo che alimenta le tre
    righe statistiche della dashboard (Threats blocked / Files scanned /
    Last scan), che prima venivano impostate una sola volta alla
    creazione della UI e non aggiornate mai più."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "history_test.db")
        self.manager = HistoryManager(db_path=self.db_path)

    def test_no_scans_yet(self):
        stats = self.manager.get_summary_stats()
        self.assertEqual(stats["total_files_scanned"], 0)
        self.assertEqual(stats["total_threats_found"], 0)
        self.assertIsNone(stats["last_scan"])

    def test_aggregates_across_multiple_scans(self):
        s1 = self.manager.start_scan("manual", "/home")
        self.manager.finish_scan(s1, files_scanned=10, threats_found=1, results=[])
        s2 = self.manager.start_scan("manual", "/tmp")
        self.manager.finish_scan(s2, files_scanned=5, threats_found=0, results=[])

        stats = self.manager.get_summary_stats()
        self.assertEqual(stats["total_files_scanned"], 15)
        self.assertEqual(stats["total_threats_found"], 1)
        self.assertIsNotNone(stats["last_scan"])

    def test_in_progress_scan_not_counted_until_finished(self):
        # start_scan senza il corrispondente finish_scan: non deve
        # comparire nei totali né far pensare che ci sia stata una scan.
        self.manager.start_scan("manual", "/home")
        stats = self.manager.get_summary_stats()
        self.assertEqual(stats["total_files_scanned"], 0)
        self.assertIsNone(stats["last_scan"])


if __name__ == "__main__":
    unittest.main()
