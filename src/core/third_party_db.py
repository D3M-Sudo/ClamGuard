#!/usr/bin/env python3
"""
ThirdPartyDBManager — Download, verify, and update unofficial signatures
Inspired by Fangfrisch and clamav-unofficial-sigs
"""

import os
import hashlib
import logging
import sqlite3
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from . import paths

logger = logging.getLogger("alpha.third_party_db")


class SignatureProvider:
    """Configuration for a single third-party signature source."""

    def __init__(
        self,
        name: str,
        url: str,
        filename: str,
        interval: int = 3600,
        max_size: int = 10 * 1024 * 1024,
        integrity_check: str = "sha256",
        enabled: bool = True,
    ):
        self.name = name
        self.url = url
        self.filename = filename
        self.interval = interval  # seconds
        self.max_size = max_size
        self.integrity_check = integrity_check
        self.enabled = enabled


class ThirdPartyDBManager:
    """Manages third-party signature databases with atomic updates."""

    DEFAULT_PROVIDERS = [
        SignatureProvider(
            "urlhaus",
            "https://urlhaus.abuse.ch/downloads/urlhaus.ndb",
            "urlhaus.ndb",
            interval=600,
            max_size=2 * 1024 * 1024,
        ),
        SignatureProvider(
            "sanesecurity_junk",
            "https://ftp.swin.edu.au/sanesecurity/junk.ndb",
            "sanesecurity_junk.ndb",
            interval=3600,
        ),
        SignatureProvider(
            "sanesecurity_phish",
            "https://ftp.swin.edu.au/sanesecurity/phish.ndb",
            "sanesecurity_phish.ndb",
            interval=3600,
        ),
        SignatureProvider(
            "twinclams",
            "https://raw.githubusercontent.com/twinwave-security/twinclams/master/twinclams.ldb",
            "twinclams.ldb",
            interval=3600,
            max_size=2 * 1024 * 1024,
        ),
        SignatureProvider(
            "ditekshen",
            "https://raw.githubusercontent.com/ditekshen/detection/master/clamav/clamav.ldb",
            "ditekshen.ldb",
            interval=86400,
            max_size=2 * 1024 * 1024,
        ),
    ]

    def __init__(
        self,
        db_path: Optional[str] = None,
        sig_dir: Optional[str] = None,
        state_dir: Optional[str] = None,
    ):
        # NOTA: /var/lib/clamav (la directory di sistema di ClamAV) è
        # montata read-only nel manifest Flatpak e, in esecuzione nativa,
        # scrivibile solo da root. Il default qui è una directory utente
        # scrivibile senza privilegi elevati; ClamAVScanner la include
        # automaticamente via --database nel fallback clamscan. Per farla
        # vedere anche a un clamd di sistema serve un passo di
        # installazione privilegiato separato (pkexec) — vedi backlog.
        self.state_dir = state_dir or paths.app_data_dir()
        self.sig_dir = sig_dir or paths.app_data_dir("signatures")
        self.db_path = db_path or os.path.join(self.state_dir, "third_party.db")
        os.makedirs(self.sig_dir, exist_ok=True)
        self.providers: List[SignatureProvider] = []
        self._init_db()
        self._load_providers()

    def _init_db(self):
        os.makedirs(self.state_dir, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS downloads (
                    name TEXT PRIMARY KEY,
                    url TEXT,
                    filename TEXT,
                    last_download REAL,
                    etag TEXT,
                    local_hash TEXT,
                    size INTEGER,
                    enabled INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    checked_at REAL,
                    hash_expected TEXT,
                    hash_actual TEXT,
                    passed INTEGER
                )
            """)

    def _load_providers(self):
        """Load providers from DB or initialize defaults."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM downloads").fetchall()
            if not rows:
                for p in self.DEFAULT_PROVIDERS:
                    conn.execute(
                        "INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (p.name, p.url, p.filename, 0, None, None, 0, int(p.enabled)),
                    )
                rows = conn.execute("SELECT * FROM downloads").fetchall()

            for row in rows:
                self.providers.append(
                    SignatureProvider(
                        name=row[0],
                        url=row[1],
                        filename=row[2],
                        interval=3600,
                        enabled=bool(row[7]),
                    )
                )

    def refresh(self) -> Dict[str, dict]:
        """Download and update all enabled providers. Returns results per provider."""
        results = {}
        for provider in self.providers:
            if not provider.enabled:
                continue
            try:
                result = self._update_provider(provider)
                results[provider.name] = result
            except Exception as e:
                logger.error(f"Failed to update {provider.name}: {e}")
                results[provider.name] = {"success": False, "error": str(e)}
        return results

    def _update_provider(self, provider: SignatureProvider) -> dict:
        """Atomic update for a single provider."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT last_download, etag FROM downloads WHERE name=?",
                (provider.name,),
            ).fetchone()
            last_download = row[0] if row else 0
            etag = row[1] if row else None

        # Respect interval
        if datetime.now().timestamp() - last_download < provider.interval:
            return {"success": True, "skipped": True, "reason": "interval not elapsed"}

        # Difesa in profondità: provider.url viene riletto da SQLite (non
        # solo dai DEFAULT_PROVIDERS hardcoded), quindi va validato ad ogni
        # download — mai fidarsi implicitamente di uno schema diverso da
        # http/https (es. file:// leggerebbe file locali arbitrari).
        from urllib.parse import urlparse

        scheme = urlparse(provider.url).scheme
        if scheme not in ("http", "https"):
            raise ValueError(f"Schema URL non ammesso per {provider.name}: {scheme!r}")

        # Download to temp
        req = Request(provider.url, headers={"User-Agent": "ClamGuard/0.1.0"})
        if etag:
            req.add_header("If-None-Match", etag)

        try:
            # nosec B310 — raggiungibile solo dopo la validazione esplicita
            # dello schema (http/https) qui sopra; bandit segnala ogni
            # urlopen() a prescindere perché fa solo pattern-matching AST,
            # senza analisi del flusso dati che veda la guardia precedente.
            with urlopen(req, timeout=60) as response:  # nosec B310
                if response.status == 304:
                    return {"success": True, "skipped": True, "reason": "not modified"}

                data = response.read()
                if len(data) > provider.max_size:
                    return {"success": False, "error": "Max size exceeded"}

                new_etag = response.headers.get("ETag")
                local_hash = hashlib.sha256(data).hexdigest()

                # Write to temp file nella STESSA directory della destinazione,
                # così l'os.rename successivo (dentro shutil.move) è atomico:
                # se il tempfile finisse su un filesystem diverso (es. /tmp),
                # shutil.move degraderebbe a copy+delete, perdendo l'atomicità.
                os.makedirs(self.sig_dir, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=".sig", dir=self.sig_dir
                ) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name

                # Integrity test with clamscan
                test_result = self._test_signature(tmp_path)
                if not test_result["valid"]:
                    os.unlink(tmp_path)
                    return {
                        "success": False,
                        "error": f"Integrity test failed: {test_result['error']}",
                    }

                # Atomic move
                dest_path = os.path.join(self.sig_dir, provider.filename)
                shutil.move(tmp_path, dest_path)
                os.chmod(dest_path, 0o644)

                # Update DB
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "UPDATE downloads SET last_download=?, etag=?, local_hash=?, size=? WHERE name=?",
                        (
                            datetime.now().timestamp(),
                            new_etag,
                            local_hash,
                            len(data),
                            provider.name,
                        ),
                    )

                return {"success": True, "size": len(data), "hash": local_hash}

        except HTTPError as e:
            return {"success": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _test_signature(self, path: str) -> dict:
        """Test signature file with clamscan before activation."""
        import subprocess

        try:
            result = subprocess.run(
                ["clamscan", "--database", path, "--infected", "/dev/null"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Return code 0 or 1 is OK (0 = clean, 1 = found - but /dev/null is clean)
            if result.returncode in (0, 1):
                return {"valid": True}
            return {"valid": False, "error": result.stderr or "Unknown error"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_provider_status(self) -> List[dict]:
        """Return status of all providers."""
        status = []
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute("SELECT * FROM downloads"):
                status.append(
                    {
                        "name": row[0],
                        "filename": row[2],
                        "last_download": (
                            datetime.fromtimestamp(row[3]).isoformat()
                            if row[3]
                            else None
                        ),
                        "size": row[6],
                        "enabled": bool(row[7]),
                    }
                )
        return status

    def stage_for_system_install(self) -> List[tuple]:
        """Copia le firme scaricate/verificate in un'area di staging
        per-utente 0o700, pronta per l'helper privilegiato
        clamguard-apply-signatures.

        Ritorna una lista di coppie (path_staged, path_destinazione) da
        passare a PolkitHelper.run_elevated() come argomenti dopo
        "--protocol=1". Ogni firma viene ri-copiata ad ogni chiamata
        (mai riusata da una staging precedente), così l'helper autentica
        sempre lo stato più recente, non uno stantio.

        Solleva ValueError se sig_dir non contiene firme con
        un'estensione riconosciuta dall'allowlist dell'helper.
        """
        from .privileged_paths import (
            ALLOWED_SIGNATURE_EXTENSIONS,
            staging_root_for_uid,
        )

        staging_root = staging_root_for_uid(os.getuid())
        # 0o700: solo il proprietario può leggere/scrivere/attraversare —
        # è il presupposto di sicurezza che verify_staging_root() nell'helper
        # controlla via fstat prima di fidarsi di qualunque file al suo interno.
        os.makedirs(staging_root, mode=0o700, exist_ok=True)
        os.chmod(staging_root, 0o700)

        pairs = []
        sig_path = Path(self.sig_dir)
        if not sig_path.is_dir():
            return pairs

        for entry in sorted(sig_path.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in ALLOWED_SIGNATURE_EXTENSIONS:
                continue

            staged = staging_root / entry.name
            # Ricopia sempre da zero (mai un hardlink/mtime-preserving
            # copy): l'helper autentica per contenuto/proprietà al momento
            # dell'invocazione, non per storia del file.
            with open(entry, "rb") as src, open(staged, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.chmod(staged, 0o600)

            destination = f"/var/lib/clamav/{entry.name}"
            pairs.append((str(staged), destination))

        if not pairs:
            raise ValueError(
                f"Nessuna firma con estensione riconosciuta trovata in {self.sig_dir}"
            )
        return pairs

    def build_privileged_install_args(self) -> List[str]:
        """Argomenti pronti per PolkitHelper.run_elevated(), incluso il
        token di protocollo richiesto dall'helper."""
        from .privileged_paths import PROTOCOL_VERSION

        pairs = self.stage_for_system_install()
        args = [f"--protocol={PROTOCOL_VERSION}"]
        for staged, destination in pairs:
            args.extend([staged, destination])
        return args
