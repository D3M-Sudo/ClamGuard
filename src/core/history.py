#!/usr/bin/env python3
"""
HistoryManager — Scan history and threat log with SQLite backend
"""

import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import List, Optional

from . import paths

logger = logging.getLogger("alpha.history")


class ScanRecord:
    def __init__(
        self,
        record_id: int,
        scan_type: str,
        target: str,
        start_time: datetime,
        end_time: Optional[datetime],
        files_scanned: int,
        threats_found: int,
        log_path: Optional[str],
    ):
        self.id = record_id
        self.scan_type = scan_type
        self.target = target
        self.start_time = start_time
        self.end_time = end_time
        self.files_scanned = files_scanned
        self.threats_found = threats_found
        self.log_path = log_path


class HistoryManager:
    """Persistent scan history with export capabilities."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or paths.app_data_dir("history.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
        except Exception:
            pass

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT,
                    target TEXT,
                    start_time REAL,
                    end_time REAL,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    log_path TEXT,
                    results_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    file_path TEXT,
                    virus_name TEXT,
                    file_hash TEXT,
                    action TEXT,
                    timestamp REAL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)

    def start_scan(self, scan_type: str, target: str) -> int:
        """Record scan start, returns scan ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO scans (scan_type, target, start_time) VALUES (?, ?, ?)",
                (scan_type, target, datetime.now().timestamp()),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("INSERT in scans non ha prodotto un lastrowid")
            return cursor.lastrowid

    def finish_scan(
        self,
        scan_id: int,
        files_scanned: int,
        threats_found: int,
        results: list,
        log_path: Optional[str] = None,
    ):
        """Record scan completion."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE scans SET end_time=?, files_scanned=?, threats_found=?, log_path=?, results_json=? WHERE id=?",
                (
                    datetime.now().timestamp(),
                    files_scanned,
                    threats_found,
                    log_path,
                    json.dumps(results),
                    scan_id,
                ),
            )

    def add_threat(
        self,
        scan_id: int,
        file_path: str,
        virus_name: str,
        file_hash: Optional[str],
        action: str = "detected",
    ):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO threats (scan_id, file_path, virus_name, file_hash, action, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    file_path,
                    virus_name,
                    file_hash,
                    action,
                    datetime.now().timestamp(),
                ),
            )

    def get_recent_scans(self, limit: int = 50) -> List[ScanRecord]:
        records = []
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT ?", (limit,)
            ):
                records.append(
                    ScanRecord(
                        record_id=row[0],
                        scan_type=row[1],
                        target=row[2],
                        start_time=datetime.fromtimestamp(row[3]),
                        end_time=datetime.fromtimestamp(row[4]) if row[4] else None,
                        files_scanned=row[5],
                        threats_found=row[6],
                        log_path=row[7],
                    )
                )
        return records

    def export_csv(self, path: str, scan_id: Optional[int] = None):
        import csv

        with sqlite3.connect(self.db_path) as conn, open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["ID", "Type", "Target", "Start", "End", "Files", "Threats"]
            )
            query = "SELECT * FROM scans"
            params = ()
            if scan_id:
                query += " WHERE id=?"
                params = (scan_id,)
            query += " ORDER BY start_time DESC"
            for row in conn.execute(query, params):
                writer.writerow(row[:7])
