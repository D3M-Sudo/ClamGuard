#!/usr/bin/env python3
"""
VirusTotalClient — API v3 integration with local cache and rate limiting
"""

import os
import time
import logging
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict

logger = logging.getLogger("alpha.virustotal")

# Optional dependency — gracefully degrade if not installed
try:
    from virustotal_python import Virustotal

    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    logger.warning("virustotal-python not installed; VT features disabled")


class VirusTotalClient:
    """VirusTotal API v3 client with SQLite cache and exponential backoff."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_db: str = "/var/lib/alpha/virustotal_cache.db",
    ):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.cache_db = cache_db
        self._client = None
        self._last_request = 0
        self._min_interval = 15.0  # Public API: 4 req/min
        os.makedirs(os.path.dirname(cache_db), exist_ok=True)
        self._init_cache()

        if VT_AVAILABLE and self.api_key:
            self._client = Virustotal(API_KEY=self.api_key)

    def _init_cache(self):
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vt_cache (
                    file_hash TEXT PRIMARY KEY,
                    response_json TEXT,
                    cached_at REAL,
                    malicious INTEGER,
                    total INTEGER
                )
            """)

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    def lookup_file(
        self, file_path: str, force_refresh: bool = False
    ) -> Optional[Dict]:
        """Lookup file by SHA-256 hash with cache."""
        if not self._client:
            return None

        file_hash = hashlib.sha256(Path(file_path).read_bytes()).hexdigest()

        # Check cache
        if not force_refresh:
            with sqlite3.connect(self.cache_db) as conn:
                row = conn.execute(
                    "SELECT response_json, cached_at, malicious, total FROM vt_cache WHERE file_hash=?",
                    (file_hash,),
                ).fetchone()
                if row and datetime.now().timestamp() - row[1] < 86400:  # 24h cache
                    import json

                    return json.loads(row[0])

        # API request
        self._rate_limit()
        try:
            resp = self._client.request(f"files/{file_hash}")
            data = resp.data

            attributes = data.get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})
            result = {
                "hash": file_hash,
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "undetected": last_analysis.get("undetected", 0),
                "harmless": last_analysis.get("harmless", 0),
                "total": sum(last_analysis.values()),
                "names": attributes.get("names", []),
                "type": attributes.get("type_description", "unknown"),
                "timestamp": datetime.now().isoformat(),
            }

            # Cache result
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vt_cache VALUES (?, ?, ?, ?, ?)",
                    (
                        file_hash,
                        json.dumps(result),
                        datetime.now().timestamp(),
                        result["malicious"],
                        result["total"],
                    ),
                )
            return result
        except Exception as e:
            logger.error(f"VT lookup failed: {e}")
            return None

    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload file for analysis, return analysis ID."""
        if not self._client:
            return None
        self._rate_limit()
        try:
            with open(file_path, "rb") as f:
                resp = self._client.request(
                    "files",
                    files={"file": (os.path.basename(file_path), f.read())},
                    method="POST",
                )
            return resp.data.get("id")
        except Exception as e:
            logger.error(f"VT upload failed: {e}")
            return None
