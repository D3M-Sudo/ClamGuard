#!/usr/bin/env python3
"""
VirusTotalClient — API v3 integration with local cache and rate limiting
"""

import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

from . import paths

logger = logging.getLogger("clamguard.virustotal")

# Optional dependency — gracefully degrade if not installed
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("python3-requests not installed; VT features disabled")

VT_API_BASE = "https://www.virustotal.com/api/v3"

# CG-009: limite massimo dimensione file per l'upload a VirusTotal.
# Oltre questa soglia l'upload viene rifiutato PRIMA di leggere il file,
# evitando di caricare in RAM file enormi (OOM). 650MB è il limite
# pratico dell'API pubblica di VirusTotal.
VT_MAX_FILE_SIZE = 650 * 1024 * 1024  # 650 MB


class VirusTotalClient:
    """VirusTotal API v3 client with SQLite cache and exponential backoff."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_db: str | None = None,
    ):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            try:
                from ..services.credentials import CredentialsService

                self.api_key = CredentialsService().get_vt_key()
            except Exception as e:  # noqa: BLE001 - graceful fallback to env var
                logger.debug(f"Could not load VT key from credentials service: {e}")
        self.cache_db = cache_db or paths.app_data_dir("virustotal_cache.db")
        self._session = None
        self._last_request = 0
        self._min_interval = 15.0  # Public API: 4 req/min
        os.makedirs(os.path.dirname(self.cache_db), exist_ok=True)
        self._init_cache()
        try:
            if os.path.exists(self.cache_db):
                os.chmod(self.cache_db, 0o600)
        except OSError as e:
            logger.warning(f"Could not set permissions on cache DB: {e}")

        if REQUESTS_AVAILABLE and self.api_key:
            self._session = requests.Session()
            self._session.headers.update({"x-apikey": self.api_key})
            # CG-017: TLS hardening. Usa il bundle CA di certifi per la
            # verifica dei certificati e ignora le variabili d'ambiente
            # (trust_env=False) che potrebbero disabilitare la verifica
            # TLS o iniettare proxy non attendibili.
            try:
                import certifi

                self._session.verify = certifi.where()
            except ImportError:
                logger.debug("certifi not installed; using system CA store")
            self._session.trust_env = False

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

    def _make_request(
        self, method: str, url: str, **kwargs
    ) -> "requests.Response | None":
        """Esegue una richiesta HTTP con retry esponenziale.

        CG-008: prima del fix non c'era alcun retry su 503/timeout,
        nonostante il docstring della classe dichiarasse "exponential
        backoff". Ora: 3 retry con backoff 2→4→8s su HTTP 503 e timeout.
        Ritorna la Response, o None se la richiesta fallisce definitivamente.
        """
        if not self._session:
            return None
        retries = 3
        backoff = 2.0
        for attempt in range(retries + 1):
            try:
                resp = self._session.request(method, url, **kwargs)
                if resp.status_code == 503 and attempt < retries:
                    logger.warning(
                        f"VT 503 (attempt {attempt + 1}/{retries + 1}), "
                        f"retrying in {backoff}s"
                    )
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except requests.exceptions.Timeout as e:
                if attempt < retries:
                    logger.warning(
                        f"VT timeout (attempt {attempt + 1}/{retries + 1}), "
                        f"retrying in {backoff}s"
                    )
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                logger.error(f"VirusTotal request timed out: {e}")
                return None
            except requests.exceptions.ConnectionError as e:
                logger.error(f"VirusTotal connection failed: {e}")
                return None
        return None

    def lookup_file(self, file_path: str, force_refresh: bool = False) -> dict | None:
        """Lookup file by SHA-256 hash with cache."""
        if not self._session:
            return None

        file_hash = paths.compute_file_hash(file_path)

        # Check cache
        if not force_refresh:
            with sqlite3.connect(self.cache_db) as conn:
                row = conn.execute(
                    "SELECT response_json, cached_at, malicious, total FROM vt_cache WHERE file_hash=?",
                    (file_hash,),
                ).fetchone()
                if (
                    row and datetime.now(timezone.utc).timestamp() - row[1] < 86400
                ):  # 24h cache
                    import json

                    return json.loads(row[0])

        # API request
        self._rate_limit()
        resp = self._make_request(
            "GET", f"{VT_API_BASE}/files/{file_hash}", timeout=(5, 15)
        )
        if resp is None:
            return None
        try:
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Cache result
            import json

            with sqlite3.connect(self.cache_db) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO vt_cache VALUES (?, ?, ?, ?, ?)",
                    (
                        file_hash,
                        json.dumps(result),
                        datetime.now(timezone.utc).timestamp(),
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
        except (OSError, ValueError, sqlite3.Error) as e:
            logger.error(f"VT lookup failed: {e}")
            return None

    def upload_file(self, file_path: str) -> str | None:
        """Upload file for analysis, return analysis ID."""
        if not self._session:
            return None

        # CG-009: rifiuta l'upload PRIMA di leggere il file se supera il
        # limite di dimensione, evitando di caricare in RAM file enormi.
        try:
            size = os.path.getsize(file_path)
        except OSError as e:
            logger.error(f"VT upload: cannot stat {file_path}: {e}")
            return None
        if size > VT_MAX_FILE_SIZE:
            logger.error(
                f"VT upload refused: {file_path} is {size} bytes, "
                f"exceeds the {VT_MAX_FILE_SIZE // (1024 * 1024)}MB limit"
            )
            return None

        self._rate_limit()
        try:
            # Streaming: passiamo l'oggetto file a requests (che lo legge
            # a chunk), invece di f.read() che carica l'intero file in RAM.
            with open(file_path, "rb") as f:
                resp = self._make_request(
                    "POST",
                    f"{VT_API_BASE}/files",
                    files={"file": (os.path.basename(file_path), f)},
                    timeout=(5, 30),
                )
            if resp is None:
                return None
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
        except (OSError, ValueError, sqlite3.Error) as e:
            logger.error(f"VT upload failed: {e}")
            return None
