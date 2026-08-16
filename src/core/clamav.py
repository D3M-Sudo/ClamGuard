#!/usr/bin/env python3
"""
ClamAVScanner — Async wrapper for clamscan / clamdscan / clamd socket
High-performance parsing, I/O mitigation for large scans
"""

import asyncio
import logging
import os
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from . import paths
from .path_validator import validate_path
from .paths import compute_file_hash

logger = logging.getLogger("clamguard.clamav")


class ScanResult:
    """Represents a single file scan result."""

    def __init__(
        self,
        path: str,
        infected: bool,
        virus_name: str | None = None,
        error: str | None = None,
        skipped: bool = False,
    ):
        self.path = path
        self.infected = infected
        self.virus_name = virus_name
        self.error = error
        # True quando il file non è mai stato realmente ispezionato (es.
        # dimensione oltre il limite configurato). Va tenuto distinto da
        # un risultato "pulito" vero e proprio: clamscan stesso, in modalità
        # normale (non --debug), stampa "<path>: OK" identico sia per un
        # file davvero scansionato sia per uno scartato per dimensione —
        # da qui la necessità di intercettare i file troppo grandi PRIMA
        # di invocare clamscan, per poterli segnalare come tali.
        self.skipped = skipped
        self.timestamp = datetime.now(timezone.utc)
        # L'hash NON viene più calcolato qui: leggere l'intero file in modo
        # sincrono per ogni risultato (anche quelli puliti) dentro un loop
        # asyncio blocca l'event loop e annulla il vantaggio dell'I/O async.
        # Va calcolato esplicitamente via compute_hash() solo quando serve
        # (es. prima della quarantena di un file infetto).
        self._hash: str | None = None

    def compute_hash(self) -> str | None:
        """Calcola (e mette in cache) lo sha256 del file, se ancora presente."""
        if self._hash is None:
            p = Path(self.path)
            if p.exists():
                self._hash = compute_file_hash(self.path)
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
            "skipped": self.skipped,
            "timestamp": self.timestamp.isoformat(),
            "hash": self._hash,
        }


class ClamAVScanner:
    """High-level async scanner using clamscan or clamd."""

    CLAMD_SOCKET = "/run/clamav/clamd.ctl"
    CLAMD_ALT = "/var/run/clamav/clamd.ctl"

    # Limite dimensione file oltre il quale un file viene esplicitamente
    # saltato (mai passato a clamscan) e segnalato come tale all'utente,
    # invece di essere silenziosamente riportato "OK" senza mai essere
    # davvero ispezionato. 2 GiB: alto abbastanza da coprire la stragrande
    # maggioranza dei file reali di un utente desktop (inclusi video e la
    # maggior parte delle ISO), pur restando una soglia esplicita e finita.
    MAX_SCAN_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB

    def __init__(
        self,
        socket_path: str | None = None,
        extra_db_dirs: list[str] | None = None,
        prefer_clamd: bool = True,
        clamd_timeout: float = 300.0,
    ):
        self.socket_path = socket_path or self._find_socket()
        # CG-006: timeout per la risposta clamd, configurabile. Prima del
        # fix era fisso a 300s, senza possibilità di adattarlo a file
        # particolarmente lenti o a sistemi con clamd sotto carico.
        self.clamd_timeout = clamd_timeout
        # QA #4 (alto): lo switch "Use clamd daemon" in Settings era
        # collegato a GSettings ma il valore non veniva mai letto da
        # nessuna parte del codice — _use_clamd si autodeterminava sempre
        # via _detect_clamd(), rendendo lo switch puramente decorativo.
        #
        # prefer_clamd riflette la scelta esplicita dell'utente. Non
        # sostituisce però i controlli di sicurezza di _detect_clamd()
        # (socket realmente presente, permessi corretti, proprietario di
        # sistema): l'utente può solo DISATTIVARE clamd (forzare
        # clamscan) anche quando sarebbe disponibile, mai forzarlo ON se
        # i controlli di sicurezza falliscono — coerente con l'etichetta
        # in Settings ("Prefer clamd... when available").
        self.prefer_clamd = prefer_clamd
        self._clamd_available = self._detect_clamd()
        # Directory con firme di terze parti (ThirdPartyDBManager). Usate
        # solo dal fallback clamscan: clamd carica database extra solo da
        # ExtraDatabase in clamd.conf, non selezionabili per-comando via
        # il protocollo SCAN — vedi nota in third_party_db.py.
        self.extra_db_dirs = extra_db_dirs or []

    @property
    def _use_clamd(self) -> bool:
        # Calcolato ad ogni accesso (non cachato) così che un cambio dello
        # switch "Use clamd daemon" a runtime (window.py aggiorna
        # self.prefer_clamd su notify::active) abbia effetto immediato
        # sulla prossima scansione, senza richiedere un riavvio dell'app.
        return self.prefer_clamd and self._clamd_available

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
        # In Flatpak il socket di sistema non è visibile nel sandbox (e
        # anche se lo fosse, non sarebbe affidabile). Forziamo sempre il
        # fallback clamscan via flatpak-spawn --host.
        if paths.is_flatpak_sandbox():
            return False
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
        scan_paths: list[str],
        progress_callback: Callable[[str, int, int], None] | None = None,
        chunk_size: int = 2000,
    ) -> list[ScanResult]:
        """Scan multiple paths with async I/O and progress reporting."""
        if self._use_clamd:
            return await self._scan_clamd(scan_paths, progress_callback)
        return await self._scan_clamscan(scan_paths, progress_callback, chunk_size)

    @staticmethod
    def _expand_to_files(paths: list[str]) -> list[str]:
        """Espande una lista di file/cartelle nell'elenco reale dei file.

        Il protocollo clamd (comando SCAN) risponde con un numero di righe
        non prevedibile a priori quando il target è una directory (una
        riga per ogni file scansionato al suo interno). Per garantire che
        "un comando inviato" corrisponda sempre a "una riga di risposta
        letta" — ed evitare quindi un disallineamento del protocollo tra
        una directory e la successiva — camminiamo l'albero noi stessi e
        inviamo un comando SCAN per singolo file reale.
        """
        files = []
        for p in paths:
            # CG-005: validazione del path di input prima di qualsiasi
            # operazione. Prima del fix, _expand_to_files accettava
            # qualsiasi stringa, inclusi symlink a file sensibili (es.
            # /etc/shadow) o path con traversal. I path non validi vengono
            # saltati con un warning, non passati allo scanner.
            valid, reason = validate_path(p)
            if not valid:
                logger.warning(f"Skipping invalid scan path {p}: {reason}")
                continue
            if os.path.isdir(p):
                for root, _dirs, filenames in os.walk(p, followlinks=False):
                    for name in filenames:
                        files.append(os.path.join(root, name))
            elif os.path.isfile(p):
                files.append(p)
        return files

    async def _scan_clamd(
        self, scan_paths: list[str], progress_callback: Callable | None = None
    ) -> list[ScanResult]:
        """Stream scan via clamd UNIX socket using asyncio.

        Ogni path in ingresso (file o cartella) viene prima espanso
        nell'elenco reale dei file da scansionare (vedi _expand_to_files):
        così ogni comando SCAN inviato riguarda sempre un singolo file, la
        risposta è sempre esattamente una riga, e i risultati riportati
        (conteggio file, minacce trovate) corrispondono a ciò che è stato
        davvero scansionato — non al numero di cartelle scelte dall'utente.
        """
        files = await asyncio.to_thread(self._expand_to_files, scan_paths)
        results: list[ScanResult] = []
        total = len(files)

        if total == 0:
            return results

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path), timeout=10
            )
            for idx, path in enumerate(files):
                cmd = f"SCAN {path}\n".encode()
                writer.write(cmd)
                await writer.drain()

                response = await asyncio.wait_for(
                    reader.readline(), timeout=self.clamd_timeout
                )
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
            return await self._scan_clamscan(scan_paths, progress_callback)
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error(f"clamd scan connection broken: {e}")
            return await self._scan_clamscan(scan_paths, progress_callback)
        except (OSError, ValueError, TypeError) as e:
            logger.error(f"clamd scan error: {e}")
            # Fallback to clamscan
            return await self._scan_clamscan(scan_paths, progress_callback)

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

            # Real async chunk-by-chunk streaming to minimize memory usage and avoid blocking
            # the event loop with synchronous file reads. Only 1 chunk in memory at any time.
            f = await asyncio.to_thread(open, path, "rb")
            try:
                while True:
                    chunk = await asyncio.to_thread(f.read, 65536)
                    if not chunk:
                        break
                    chunk_len = len(chunk)
                    writer.write(struct.pack(">I", chunk_len) + chunk)
                    await writer.drain()
            finally:
                await asyncio.to_thread(f.close)

            # End stream with a zero-length chunk
            writer.write(struct.pack(">I", 0))
            await writer.drain()

            response = await asyncio.wait_for(
                reader.readline(), timeout=self.clamd_timeout
            )
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
            # CG-015: rsplit(":", 1) invece di split(":") — un path può
            # contenere ":" (es. C:\... o path con colonne), e split(":")
            # produrrebbe più di 2 parti, rompendo l'estrazione del virus.
            parts = response.rsplit(":", 1)
            virus = parts[-1].replace("FOUND", "").strip()
            return ScanResult(path, True, virus_name=virus)
        elif "OK" in response:
            return ScanResult(path, False)
        else:
            return ScanResult(path, False, error=response)

    def _build_clamscan_cmd(self, args: list[str]) -> list[str]:
        """Costruisce il comando clamscan, gestendo il sandbox Flatpak.

        In Flatpak, clamscan non esiste dentro il sandbox: va eseguito
        sull'host via flatpak-spawn --host. I path vanno convertiti dal
        namespace sandbox a quello host (vedi paths.to_host_path).
        """
        if paths.is_flatpak_sandbox():
            return ["flatpak-spawn", "--host", "clamscan"] + args
        return ["clamscan"] + args

    async def _scan_clamscan(
        self,
        scan_paths: list[str],
        progress_callback: Callable | None,
        chunk_size: int = 2000,
    ) -> list[ScanResult]:
        """Fallback async clamscan with chunked execution.

        clamscan scansiona già ricorsivamente ogni cartella passata e
        stampa (con --no-summary --stdout) una riga per ciascun file
        realmente scansionato al suo interno: _parse_clamscan_output
        produce quindi già un ScanResult per file reale, non per path
        di input. In precedenza questi risultati venivano scartati e
        rimpiazzati con un unico ScanResult fittizio per ogni cartella
        di input (facendo apparire "1 file scansionato" indipendentemente
        dal contenuto reale, e perdendo silenziosamente eventuali minacce
        trovate nei file interni). Ora i risultati parsati vengono usati
        direttamente.

        NOTA: il flag --infected è stato rimosso deliberatamente. Con
        --infected, clamscan stampa una riga SOLO per i file infetti o in
        errore: i file puliti non producono alcuna riga di output e quindi
        non vengono mai conteggiati. Senza --infected, clamscan stampa una
        riga "<path>: OK" anche per ogni file pulito, permettendo un
        conteggio "Files scanned" corretto.

        NOTA 2: aggiunto --recursive. Senza questo flag clamscan NON
        scende nelle sottocartelle (comportamento di default di clamscan
        stesso, non di questo codice) — scansionava quindi solo i file
        presenti direttamente nella cartella scelta dall'utente, ignorando
        silenziosamente tutto ciò che si trova più in profondità.

        NOTA 3: i file vengono espansi ed elencati esplicitamente PRIMA di
        invocare clamscan, ed ogni file oltre MAX_SCAN_FILE_SIZE viene
        escluso dall'invocazione e riportato come ScanResult(skipped=True)
        — clamscan, in modalità normale (non --debug), stampa "<path>: OK"
        in modo identico sia per un file davvero scansionato sia per uno
        scartato internamente per dimensione (default clamscan ~200MB):
        senza questo controllo lato client, un file enorme risulterebbe
        indistinguibile in UI da uno realmente pulito. Impostiamo comunque
        anche --max-filesize/--max-scansize espliciti, come difesa in
        profondità nel caso un archivio si espanda oltre il limite durante
        la scansione stessa (non intercettabile dal solo controllo sulla
        dimensione su disco).
        """
        all_files = await asyncio.to_thread(self._expand_to_files, scan_paths)
        results: list[ScanResult] = []
        total = len(all_files)

        if total == 0:
            return results

        scannable = []
        max_mb = self.MAX_SCAN_FILE_SIZE // (1024 * 1024)
        for f in all_files:
            try:
                size = os.path.getsize(f)
            except OSError:
                # Il file può essere sparito tra l'enumerazione e questo
                # controllo, o essere illeggibile: lasciamo che sia
                # clamscan stesso a riportare l'errore appropriato.
                scannable.append(f)
                continue
            if size > self.MAX_SCAN_FILE_SIZE:
                results.append(
                    ScanResult(
                        f,
                        False,
                        skipped=True,
                        error=(
                            f"Skipped: file exceeds the {max_mb}MB scan "
                            f"limit ({size} bytes)"
                        ),
                    )
                )
            else:
                scannable.append(f)

        # chunk_size alzato rispetto al default storico: ora che ogni
        # chunk è una lista di FILE espliciti (non più di cartelle top
        # level lasciate espandere a clamscan internamente), un chunk
        # troppo piccolo moltiplicherebbe inutilmente il numero di
        # invocazioni di clamscan — ognuna delle quali ricarica l'intero
        # database delle firme da disco, con un costo fisso non
        # trascurabile per scansioni con molti file (es. System Scan).
        for idx in range(0, len(scannable), chunk_size):
            chunk = scannable[idx : idx + chunk_size]
            db_args = []
            for extra_dir in self.extra_db_dirs:
                # clamscan fallisce l'INTERO comando (nessun file scansionato,
                # nessun risultato per nessuno dei path richiesti) se una
                # cartella passata a --database esiste ma non contiene
                # alcuna firma valida — condizione garantita su qualunque
                # installazione pulita, prima che l'utente scarichi le
                # prime firme di terze parti dalla vista Database. Va quindi
                # passata solo se contiene realmente almeno un file.
                # In Flatpak la directory firme è persistita nel sandbox e
                # va convertita al path host prima di passarla a clamscan
                # eseguito sull'host.
                host_extra = paths.to_host_path(extra_dir)
                if os.path.isdir(extra_dir) and any(os.scandir(extra_dir)):
                    db_args += ["--database", host_extra]
            # In Flatpak i path vanno convertiti al namespace host prima
            # di passarli a clamscan eseguito sull'host.
            host_chunk = [paths.to_host_path(p) for p in chunk]
            cmd = (
                self._build_clamscan_cmd(
                    [
                        "--recursive",
                        "--no-summary",
                        "--stdout",
                        f"--max-filesize={max_mb}M",
                        f"--max-scansize={max_mb}M",
                    ]
                    + db_args
                )
                + ["--"]
                + host_chunk
            )
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _stderr = await proc.communicate()
            except FileNotFoundError as e:
                # clamscan non è installato (né nel sandbox né sull'host)
                msg = (
                    "ClamAV non è installato. Installa clamav sul sistema "
                    "per abilitare le scansioni."
                )
                logger.error(f"clamscan not found: {e}")
                return [ScanResult(p, False, error=msg) for p in chunk]

            chunk_results = self._parse_clamscan_output(stdout.decode())
            # In Flatpak clamscan gira sull'host: i path nei risultati sono
            # in namespace host. Riconvertiamoli in namespace sandbox per
            # coerenza interna (quarantena, storico). In esecuzione nativa
            # to_sandbox_path è l'identità.
            for r in chunk_results:
                r.path = paths.to_sandbox_path(r.path)
            results.extend(chunk_results)

            if progress_callback:
                progress_callback(
                    chunk[-1], min(idx + chunk_size, len(scannable)), total
                )

        return results

    def _parse_clamscan_output(self, output: str) -> list[ScanResult]:
        """Parse clamscan --stdout output.

        Oltre a FOUND/OK/ERROR, riconosce esplicitamente "Access denied"
        (permessi insufficienti sul file) invece di scartare silenziosamente
        la riga: prima di questo fix, un file non leggibile spariva
        semplicemente dai risultati, senza alcuna indicazione per l'utente
        che quel file non era mai stato controllato.
        """
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
            elif "Access denied" in line:
                # CG-015: rsplit(":", 1) invece di split(":")[0] — un path
                # può contenere ":" e split(":")[0] troncherebbe il path.
                path = line.rsplit(":", 1)[0].strip()
                results.append(ScanResult(path, False, skipped=True, error=line))
            elif "ERROR" in line:
                path = line.rsplit(":", 1)[0].strip()
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
            if paths.is_flatpak_sandbox():
                # In Flatpak /var/lib/clamav non è montato nel sandbox:
                # chiediamo l'età del file all'host via flatpak-spawn.
                try:
                    result = subprocess.run(
                        ["flatpak-spawn", "--host", "stat", "-c", "%Y", path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode == 0:
                        mtime = float(result.stdout.strip())
                        return datetime.now(timezone.utc).timestamp() - mtime
                except (OSError, ValueError, subprocess.TimeoutExpired) as e:
                    logger.debug(f"Could not stat {path} on host: {e}")
            elif os.path.exists(path):
                mtime = os.path.getmtime(path)
                return datetime.now(timezone.utc).timestamp() - mtime
        return float("inf")

    def get_database_version(self) -> str | None:
        """Return ClamAV database version string."""
        try:
            if paths.is_flatpak_sandbox():
                result = subprocess.run(
                    ["flatpak-spawn", "--host", "clamscan", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            else:
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
