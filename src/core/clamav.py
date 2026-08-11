#!/usr/bin/env python3
"""
ClamAVScanner — Async wrapper for clamscan / clamdscan / clamd socket
High-performance parsing, I/O mitigation for large scans
"""

import asyncio
import hashlib
import logging
import os
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("clamguard.clamav")


def _compute_file_hash(file_path: str | Path) -> str:
    """Compute SHA-256 hash of a file in chunks to avoid high memory usage."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


class ScanResult:
    """Represents a single file scan result."""

    def __init__(
        self,
        path: str,
        infected: bool,
        virus_name: str | None = None,
        error: str | None = None,
    ):
        self.path = path
        self.infected = infected
        self.virus_name = virus_name
        self.error = error
        self.timestamp = datetime.now(timezone.utc)
        # L'hash NON viene più calcolato qui: leggere l'intero file in modo
        # sincrono per ogni risultato (anche quelli puliti) dentro un loop
        # asyncio blocca l'event loop e annulla il vantaggio dell'I/O async.
        # Va calcolato esplicitamente via compute_hash() solo quando serve
        # (es. prima della quarantena di un file infetto).
        self._hash = None

    def compute_hash(self) -> str | None:
        """Calcola (e mette in cache) lo sha256 del file, se ancora presente."""
        if self._hash is None:
            p = Path(self.path)
            if p.exists():
                self._hash = _compute_file_hash(p)
        return self._hash

    @property
    def hash(self) -> str | None:
        return self._hash

    def to_dict(self):
        return {
            "path": self.path,
            "infected": self.infected,
            "virus_name": self.virus_name,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "hash": self._hash,
        }


class ClamAVScanner:
    """High-level async scanner using clamscan or clamd."""

    CLAMD_SOCKET = "/run/clamav/clamd.ctl"
    CLAMD_ALT = "/var/run/clamav/clamd.ctl"

    def __init__(
        self,
        socket_path: str | None = None,
        extra_db_dirs: list[str] | None = None,
    ):
        self.socket_path = socket_path or self._find_socket()
        self._use_clamd = self._detect_clamd()
        # Directory con firme di terze parti (ThirdPartyDBManager). Usate
        # solo dal fallback clamscan: clamd carica database extra solo da
        # ExtraDatabase in clamd.conf, non selezionabili per-comando via
        # il protocollo SCAN — vedi nota in third_party_db.py.
        self.extra_db_dirs = extra_db_dirs or []

    def _find_socket(self) -> str:
        # SICUREZZA: niente /tmp/clamd.socket come fallback. /tmp è
        # scrivibile da qualunque utente locale, che potrebbe precreare lì
        # un socket fasullo e far credere all'app di parlare con clamd —
        # facendo segnalare "pulito" file realmente infetti, o intercettando
        # i file inviati in scansione. Solo path sotto directory scrivibili
        # esclusivamente da root/gruppo clamav sono considerati attendibili.
        for path in [self.CLAMD_SOCKET, self.CLAMD_ALT]:
            if os.path.exists(path):
                return path
        return self.CLAMD_SOCKET

    def _detect_clamd(self) -> bool:
        if not (
            os.path.exists(self.socket_path)
            and os.access(self.socket_path, os.R_OK | os.W_OK)
        ):
            return False
        try:
            owner_uid = os.stat(self.socket_path).st_uid
        except OSError:
            return False
        # Difesa in profondità: un socket posseduto da un utente normale
        # (uid >= 1000 sulla maggior parte delle distribuzioni) non è il
        # vero clamd di sistema, anche se il path coincide nominalmente.
        return owner_uid < 1000

    async def scan_paths(
        self,
        paths: list[str],
        progress_callback: Callable[[str, int, int], None] | None = None,
        chunk_size: int = 100,
    ) -> list[ScanResult]:
        """Scan multiple paths with async I/O and progress reporting."""
        if self._use_clamd:
            return await self._scan_clamd(paths, progress_callback)
        return await self._scan_clamscan(paths, progress_callback, chunk_size)

    async def _scan_clamd(
        self, paths: list[str], progress_callback: Callable | None = None
    ) -> list[ScanResult]:
        """Stream scan via clamd UNIX socket using asyncio."""

        results = []
        total = len(paths)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path), timeout=10
            )
            for idx, path in enumerate(paths):
                cmd = f"SCAN {path}\n".encode()
                writer.write(cmd)
                await writer.drain()

                response = await asyncio.wait_for(reader.readline(), timeout=300)
                decoded = response.decode().strip()
                result = self._parse_clamd_response(path, decoded)

                if result.error:
                    err_lower = result.error.lower()
                    if (
                        "denied" in err_lower
                        or "permission" in err_lower
                        or "access" in err_lower
                    ):
                        # Fallback to INSTREAM if permission denied
                        logger.warning(
                            f"Permission denied for clamd on {path}. Falling back to INSTREAM."
                        )
                        result = await self._scan_file_instream(path)

                results.append(result)

                if progress_callback:
                    progress_callback(path, idx + 1, total)

            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, TimeoutError) as e:
            logger.error(f"clamd scan timeout: {e}")
            return await self._scan_clamscan(paths, progress_callback)
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"clamd scan connection broken: {e}")
            return await self._scan_clamscan(paths, progress_callback)
        except (OSError, ValueError) as e:
            logger.error(f"clamd scan error: {e}")
            # Fallback to clamscan
            return await self._scan_clamscan(paths, progress_callback)

        return results

    async def _scan_file_instream(self, path: str) -> ScanResult:
        """Stream a file to clamd using the INSTREAM command."""
        import struct

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path), timeout=10
            )
        except (OSError, ConnectionError) as e:
            logger.error(f"Failed to open connection for INSTREAM: {e}")
            return ScanResult(path, False, error=str(e))

        try:
            writer.write(b"nINSTREAM\n")
            await writer.drain()

            with open(path, "rb") as f:
                while True:
                    chunk = await asyncio.to_thread(f.read, 65536)
                    if not chunk:
                        break
                    chunk_len = len(chunk)
                    writer.write(struct.pack(">I", chunk_len) + chunk)
                    await writer.drain()

            # End stream with a zero-length chunk
            writer.write(struct.pack(">I", 0))
            await writer.drain()

            response = await asyncio.wait_for(reader.readline(), timeout=300)
            decoded = response.decode().strip()
            # Parse the INSTREAM response (e.g., "stream: OK" or "stream: <virus> FOUND")
            # For the parse function, the format usually is "stream: <status>", so we map it back
            # replacing "stream:" with the path for correct path matching.
            if decoded.startswith("stream:"):
                decoded = decoded.replace("stream:", f"{path}:", 1)
            return self._parse_clamd_response(path, decoded)
        except (asyncio.TimeoutError, TimeoutError) as e:
            logger.error(f"Timeout during INSTREAM of {path}: {e}")
            return ScanResult(path, False, error="Timeout")
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"Broken connection during INSTREAM of {path}: {e}")
            return ScanResult(path, False, error="Connection lost")
        except (OSError, ValueError) as e:
            logger.error(f"INSTREAM error for {path}: {e}")
            return ScanResult(path, False, error=str(e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError) as e:
                logger.debug(f"Error closing writer for {path}: {e}")

    def _parse_clamd_response(self, path: str, response: str) -> ScanResult:
        """Parse clamd STREAM/SCAN output."""
        if "FOUND" in response:
            parts = response.split(":")
            virus = parts[-1].replace("FOUND", "").strip()
            return ScanResult(path, True, virus_name=virus)
        elif "OK" in response:
            return ScanResult(path, False)
        else:
            return ScanResult(path, False, error=response)

    async def _scan_clamscan(
        self,
        paths: list[str],
        progress_callback: Callable | None,
        chunk_size: int = 100,
    ) -> list[ScanResult]:
        """Fallback async clamscan with chunked execution."""
        results = []
        total = len(paths)

        for idx in range(0, total, chunk_size):
            chunk = paths[idx : idx + chunk_size]
            db_args = []
            for extra_dir in self.extra_db_dirs:
                if os.path.isdir(extra_dir):
                    db_args += ["--database", extra_dir]
            cmd = (
                ["clamscan", "--infected", "--no-summary", "--stdout"]
                + db_args
                + ["--"]
                + chunk
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await proc.communicate()

            chunk_results = self._parse_clamscan_output(stdout.decode())
            # Map results back to paths
            for path in chunk:
                matched = next((r for r in chunk_results if r.path == path), None)
                if matched:
                    results.append(matched)
                else:
                    results.append(ScanResult(path, False))

            if progress_callback:
                progress_callback(chunk[-1], min(idx + chunk_size, total), total)

        return results

    def _parse_clamscan_output(self, output: str) -> list[ScanResult]:
        """Parse clamscan --stdout output."""
        results = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            match = re.match(r"^(.*):\s*(.*?)\s*FOUND$", line)
            if match:
                path, virus = match.groups()
                results.append(ScanResult(path, True, virus_name=virus))
            elif ": OK" in line:
                path = line.replace(": OK", "").strip()
                results.append(ScanResult(path, False))
            elif "ERROR" in line:
                path = line.split(":")[0].strip()
                results.append(ScanResult(path, False, error=line))
        return results

    def get_database_age(self) -> float:
        """Return age of main.cvd in seconds."""
        db_paths = [
            "/var/lib/clamav/main.cvd",
            "/var/lib/clamav/main.cld",
            "/usr/share/clamav/main.cvd",
        ]
        for path in db_paths:
            if os.path.exists(path):
                mtime = os.path.getmtime(path)
                return datetime.now(timezone.utc).timestamp() - mtime
        return float("inf")

    def get_database_version(self) -> str | None:
        """Return ClamAV database version string."""
        try:
            result = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
