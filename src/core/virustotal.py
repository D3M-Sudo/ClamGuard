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

logger = logging.getLogger("clamguard.virustotal")

# Optional dependency — gracefully degrade if not installed
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("python3-requests not installed; VT features disabled")

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    """VirusTotal API v3 client with SQLite cache and exponential backoff."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_db: str = "/var/lib/clamguard/virustotal_cache.db",
    ):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.cache_db = cache_db
        self._session = None
        self._last_request = 0
        self._min_interval = 15.0  # Public API: 4 req/min
        os.makedirs(os.path.dirname(cache_db), exist_ok=True)
        self._init_cache()
        try:
            if os.path.exists(self.cache_db):
                os.chmod(self.cache_db, 0o600)
        except Exception:
            pass

        if REQUESTS_AVAILABLE and self.api_key:
            self._session = requests.Session()
            self._session.headers.update({"x-apikey": self.api_key})

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
        if not self._session:
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
            resp = self._session.get(
                f"{VT_API_BASE}/files/{file_hash}", timeout=(5, 15)
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

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
            import json

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
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                logger.error(f"VirusTotal API rate limit reached (HTTP 429): {e}")
            else:
                logger.error(f"VirusTotal HTTP error: {e}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"VirusTotal connection failed: {e}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"VirusTotal request timed out: {e}")
            return None
        except Exception as e:
            logger.error(f"VT lookup failed: {e}")
            return None

    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload file for analysis, return analysis ID."""
        if not self._session:
            return None
        self._rate_limit()
        try:
            with open(file_path, "rb") as f:
                resp = self._session.post(
                    f"{VT_API_BASE}/files",
                    files={"file": (os.path.basename(file_path), f.read())},
                    timeout=(5, 30),
                )
            resp.raise_for_status()
            return resp.json().get("data", {}).get("id")
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                logger.error(f"VirusTotal API rate limit reached (HTTP 429): {e}")
            else:
                logger.error(f"VirusTotal HTTP error: {e}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"VirusTotal connection failed: {e}")
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"VirusTotal request timed out: {e}")
            return None
        except Exception as e:
            logger.error(f"VT upload failed: {e}")
            return None
