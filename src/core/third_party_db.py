#!/usr/bin/env python3
"""
ThirdPartyDBManager — Download, verify, and update unofficial signatures
Inspired by Fangfrisch and clamav-unofficial-sigs
"""

import hashlib
import logging
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from . import paths
from .paths import is_flatpak_sandbox

logger = logging.getLogger("clamguard.third_party_db")

# CG-013: percorso della chiave pubblica bundled di sanesecurity. La chiave
# vive nel pacchetto (build-time), così il canale di distribuzione della
# chiave è SEPARATO dal canale del feed: un attaccante che compromette il
# server di sanesecurity non può falsificare la chiave (servita con il
# pacchetto stesso), solo le firme — che a loro volta diventano
# verificabili e quindi inutili da falsificare.
#
# Fingerprint della chiave (da `gpg --show-keys --with-fingerprint`):
#   pub dsa1024 2009-01-09 [SC]
#       D691DED931EA4D9E
#   fpr 4E025A1CBA90A0653F38D2D8D691DED931EA4D9E
#   uid Sanesecurity (Sanesecurity Signatures) <steveb_clamav@sanesecurity.co.uk>
#
# NOTA: chiave storica DSA-1024 (creata 2009). gpgv la accetta senza
# problemi di compatibilità; la documentiamo perché l'utente possa
# verificare la catena di trust contro https://www.sanesecurity.com/publickey.gpg
SANESECURITY_KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resources", "sanesecurity.gpg"
)


class SignatureProvider:
    """Configuration for a single third-party signature source.

    ``signature_url`` e ``gpg_required`` (CG-013): se ``signature_url`` è
    impostato, dopo il download del database viene scaricata anche la firma
    detached (``.sig``) da quell'URL e verificata con GPG contro la chiave
    pubblica bundled. Con ``gpg_required=True`` una firma GPG INVALIDA
    blocca l'aggiornamento (fail-closed); con ``False`` (default) il GPG
    resta opzionale e il fallback degrada al test clamscan.
    """

    def __init__(
        self,
        name: str,
        url: str,
        filename: str,
        interval: int = 3600,
        max_size: int = 10 * 1024 * 1024,
        integrity_check: str = "sha256",
        enabled: bool = True,
        signature_url: str | None = None,
        gpg_required: bool = False,
    ):
        self.name = name
        self.url = url
        self.filename = filename
        self.interval = interval  # seconds
        self.max_size = max_size
        self.integrity_check = integrity_check
        self.enabled = enabled
        self.signature_url = signature_url
        self.gpg_required = gpg_required


class ThirdPartyDBManager:
    """Manages third-party signature databases with atomic updates.

    NOTA SICUREZZA (CG-013): verifica GPG delle firme di terze parti per
    i provider che le pubblicano. I feed sanesecurity (junk/phish)
    pubblicano firme detached ``.sig`` e vengono verificati con GPG
    (chiave pubblica bundled in SANESECURITY_KEY_PATH) PRIMA
    dell'attivazione: una firma invalida BLOCCA l'aggiornamento
    (fail-closed, gpg_required=True). Gli altri provider (urlhaus,
    twinclams, ditekshen, ...) non pubblicano firme: per loro resta
    attiva la mitigazione composita — (1) validazione dello schema URL
    (solo http/https), (2) limite dimensione, (3) hash SHA-256 nel DB,
    (4) test di integrità funzionale clamscan pre-attivazione
    (_test_signature). Se gpgv/gpg non sono installati, la verifica GPG
    degrada al test clamscan con un warning (mai negare il servizio per
    un tool mancante).
    """

    DEFAULT_PROVIDERS: ClassVar[list[SignatureProvider]] = [
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
            # CG-013: sanesecurity pubblica firme detached (.sig) sullo
            # stesso mirror (nome + ".sig"). La chiave bundled è in
            # SANESECURITY_KEY_PATH. gpg_required=True → una firma GPG
            # invalida BLOCCA l'aggiornamento (fail-closed).
            signature_url="https://ftp.swin.edu.au/sanesecurity/junk.ndb.sig",
            gpg_required=True,
        ),
        SignatureProvider(
            "sanesecurity_phish",
            "https://ftp.swin.edu.au/sanesecurity/phish.ndb",
            "sanesecurity_phish.ndb",
            interval=3600,
            signature_url="https://ftp.swin.edu.au/sanesecurity/phish.ndb.sig",
            gpg_required=True,
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
        db_path: str | None = None,
        sig_dir: str | None = None,
        state_dir: str | None = None,
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
        self.providers: list[SignatureProvider] = []
        self._init_db()
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
        except OSError as e:
            logger.warning(f"Could not set permissions on {self.db_path}: {e}")
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
        """Load providers from DB or initialize defaults.

        I provider vengono letti dal DB (stato runtime: ultimo download,
        etag, hash, abilitato). La config GPG (``signature_url``,
        ``gpg_required``) e il limite ``max_size`` NON sono persistiti nel
        DB: vengono riallineati dai ``DEFAULT_PROVIDERS`` per nome, così i
        provider ricaricati da un DB esistente (caso tipico) conservano la
        verifica GPG configurata nel codice. Se un provider nel DB non ha
        più un default corrispondente, resta con la config DB base.
        """
        defaults_by_name = {p.name: p for p in self.DEFAULT_PROVIDERS}
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
                default = defaults_by_name.get(row[0])
                self.providers.append(
                    SignatureProvider(
                        name=row[0],
                        url=row[1],
                        filename=row[2],
                        interval=3600,
                        enabled=bool(row[7]),
                        signature_url=(
                            default.signature_url if default else None
                        ),
                        gpg_required=(
                            default.gpg_required if default else False
                        ),
                    )
                )

    def refresh(self) -> dict[str, dict]:
        """Download and update all enabled providers. Returns results per provider."""
        results = {}
        for provider in self.providers:
            if not provider.enabled:
                continue
            try:
                result = self._update_provider(provider)
                results[provider.name] = result
            except (OSError, ValueError, sqlite3.Error) as e:
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
        if datetime.now(timezone.utc).timestamp() - last_download < provider.interval:
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
                    delete=False, suffix=".part", dir=self.sig_dir
                ) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name

                # CG-013: verifica GPG della firma detached, se configurata.
                # Logica fail-safe:
                #   esito True  → firma valida, procedi
                #   esito False → firma INVALIDA: se gpg_required blocca
                #                 (fail-closed); altrimenti warning + clamscan
                #   esito None  → gpgv/chiave non disponibile: degrada a
                #                 clamscan con warning (mai negare il
                #                 servizio per una tool mancante)
                sig_path = None
                if provider.signature_url:
                    from urllib.parse import urlparse as _urlparse

                    sig_scheme = _urlparse(provider.signature_url).scheme
                    if sig_scheme in ("http", "https"):
                        sig_req = Request(
                            provider.signature_url,
                            headers={"User-Agent": "ClamGuard/0.1.0"},
                        )
                        try:
                            with urlopen(sig_req, timeout=60) as sig_resp:  # nosec B310
                                sig_data = sig_resp.read()
                                if len(sig_data) > provider.max_size:
                                    raise ValueError(
                                        "Firma .sig oltre max_size"
                                    )
                                with tempfile.NamedTemporaryFile(
                                    delete=False,
                                    suffix=".sig",
                                    dir=self.sig_dir,
                                ) as sig_tmp:
                                    sig_tmp.write(sig_data)
                                    sig_path = sig_tmp.name
                        except (HTTPError, OSError, ValueError) as sig_e:
                            logger.error(
                                f"Download firma .sig fallito per "
                                f"{provider.name}: {sig_e}"
                            )
                            if provider.gpg_required:
                                if sig_path and os.path.exists(sig_path):
                                    os.unlink(sig_path)
                                os.unlink(tmp_path)
                                return {
                                    "success": False,
                                    "error": (
                                        "GPG signature download failed "
                                        f"for {provider.name}: {sig_e}"
                                    ),
                                }
                            logger.warning(
                                f"GPG non richiesto per {provider.name} — "
                                "proseguo senza verifica firma"
                            )

                    if sig_path and os.path.exists(sig_path):
                        gpg_ok = self._verify_gpg(sig_path, tmp_path)
                        if gpg_ok is False:
                            # Firma INVALIDA: possibile attacco o file corrotto.
                            if provider.gpg_required:
                                os.unlink(sig_path)
                                os.unlink(tmp_path)
                                return {
                                    "success": False,
                                    "error": (
                                        "GPG signature verification FAILED "
                                        f"for {provider.name} — update blocked"
                                    ),
                                }
                            logger.warning(
                                f"Firma GPG INVALIDA per {provider.name} ma "
                                "gpg_required=False — proseguo con clamscan"
                            )
                        elif gpg_ok is None:
                            logger.warning(
                                f"gpg/chiave non disponibili per {provider.name} "
                                f"— degrada a test clamscan"
                            )
                        else:
                            logger.info(
                                f"GPG verified OK per {provider.name}"
                            )
                        # Unlink unico di sig_path (nel ramo gpg_required=True
                        # è già stato rimosso prima del return).
                        if os.path.exists(sig_path):
                            os.unlink(sig_path)
                        sig_path = None

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
                            datetime.now(timezone.utc).timestamp(),
                            new_etag,
                            local_hash,
                            len(data),
                            provider.name,
                        ),
                    )

                return {"success": True, "size": len(data), "hash": local_hash}

        except HTTPError as e:
            return {"success": False, "error": f"HTTP {e.code}"}
        except (OSError, ValueError, sqlite3.Error) as e:
            return {"success": False, "error": str(e)}

    def _verify_gpg(self, signature_path: str, data_path: str) -> bool | None:
        """CG-013: verifica una firma detached GPG con `gpg --verify`.

        Usa `gpg --verify` (non gpgv) con un homedir temp isolato (0700)
        e un keyring custom con nome esplicito. Il pattern segue
        clamav-unofficial-sigs: `--no-default-keyring` va passato SIA
        all'import SIA alla verifica, altrimenti gpg ignora il nome custom
        e crea comunque pubring.kbx. `--trust-model always` è appropriato
        perché verifichiamo contro un'unica chiave bundled nota, non una
        web-of-trust. Il keyring dell'utente non viene mai toccato.

        Returns:
            True  → firma valida contro la chiave bundled
            False → firma INVALIDA (reattacco o file corrotto)
            None  → gpg non disponibile / errore tecnico (il chiamante
                    decide il fallback, es. degrada a clamscan)
        """
        import subprocess
        import tempfile as _tempfile

        try:
            # In Flatpak gpg non è garantito nel runtime del sandbox: va
            # eseguito sull'host via flatpak-spawn --host (stesso pattern
            # già usato per clamscan in _test_signature). I path dei file
            # temp vanno convertiti al namespace host.
            if is_flatpak_sandbox():
                gpg_bin = "flatpak-spawn"
                host_key_path = paths.to_host_path(SANESECURITY_KEY_PATH)
                host_sig_path = paths.to_host_path(signature_path)
                host_data_path = paths.to_host_path(data_path)
            else:
                gpg_bin = shutil.which("gpg")
                host_key_path = SANESECURITY_KEY_PATH
                host_sig_path = signature_path
                host_data_path = data_path

            if gpg_bin is None:
                logger.warning("gpg non disponibile — verifica GPG saltata")
                return None

            if not os.path.isfile(SANESECURITY_KEY_PATH):
                logger.error(
                    f"Chiave pubblica bundled mancante: {SANESECURITY_KEY_PATH}"
                )
                return None

            # Homedir temp isolato (0700) con keyring custom a nome noto.
            # In Flatpak la TemporaryDirectory del sandbox (/tmp) NON è
            # visibile all'host: usiamo una directory persistita
            # (~/.local/share/clamguard/gpg, in PERSIST_DIRS) che
            # to_host_path() mappa correttamente all'host.
            if is_flatpak_sandbox():
                gpg_workdir = paths.app_data_dir("gpg")
                os.makedirs(gpg_workdir, mode=0o700, exist_ok=True)
                home = os.path.join(gpg_workdir, "gnupg")
                os.makedirs(home, mode=0o700, exist_ok=True)
                host_home = paths.to_host_path(home)
                _cleanup_workdir = False
            else:
                gpg_workdir = _tempfile.mkdtemp(prefix="clamguard_gpg_")
                home = os.path.join(gpg_workdir, "gnupg")
                os.makedirs(home, mode=0o700, exist_ok=True)
                host_home = home
                _cleanup_workdir = True

            keyring = os.path.join(home, "sanesecurity-keyring.gpg")
            host_keyring = paths.to_host_path(keyring) if is_flatpak_sandbox() else keyring

            try:
                # 1. Import isolato della chiave bundled nel keyring custom.
                # --no-default-keyring è OBBLIGATORIO qui: senza, gpg ignora
                # il nome custom e crea comunque pubring.kbx.
                import_cmd = (
                    [gpg_bin, "--host", "gpg"]
                    if is_flatpak_sandbox()
                    else [gpg_bin]
                )
                import_result = subprocess.run(
                    import_cmd
                    + [
                        "-q",
                        "--no-options",
                        "--no-default-keyring",
                        "--homedir",
                        host_home,
                        "--keyring",
                        host_keyring,
                        "--import",
                        host_key_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if import_result.returncode != 0:
                    logger.error(
                        f"Import della chiave GPG bundled fallito: "
                        f"{import_result.stderr.strip()}"
                    )
                    return None

                # 2. Verifica della firma detached contro il keyring custom.
                verify_cmd = (
                    [gpg_bin, "--host", "gpg"]
                    if is_flatpak_sandbox()
                    else [gpg_bin]
                )
                verify_result = subprocess.run(
                    verify_cmd
                    + [
                        "-q",
                        "--no-options",
                        "--trust-model",
                        "always",
                        "--no-default-keyring",
                        "--homedir",
                        host_home,
                        "--keyring",
                        host_keyring,
                        "--verify",
                        host_sig_path,
                        host_data_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if verify_result.returncode == 0:
                    logger.info("Firma GPG verificata correttamente")
                    return True
                logger.error(
                    f"Firma GPG INVALIDA: {verify_result.stderr.strip() or 'unknown'}"
                )
                return False
            finally:
                if _cleanup_workdir:
                    shutil.rmtree(gpg_workdir, ignore_errors=True)
        except (OSError, subprocess.TimeoutExpired, ValueError) as e:
            logger.error(f"Verifica GPG non riuscita: {e}")
            return None

    def _test_signature(self, path: str) -> dict:
        """Test signature file with clamscan before activation."""
        import subprocess

        # In Flatpak clamscan non è installato nel sandbox: va eseguito
        # sull'host via flatpak-spawn --host. Il file temporaneo vive in
        # una directory persistita del sandbox, quindi va convertito al
        # path host prima di passarlo a clamscan.
        if is_flatpak_sandbox():
            cmd = ["flatpak-spawn", "--host", "clamscan"]
            host_path = paths.to_host_path(path)
        else:
            cmd = ["clamscan"]
            host_path = path

        try:
            result = subprocess.run(
                cmd + ["--database", host_path, "--infected", "/dev/null"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            # Return code 0 or 1 is OK (0 = clean, 1 = found - but /dev/null is clean)
            if result.returncode in (0, 1):
                return {"valid": True}
            return {"valid": False, "error": result.stderr or "Unknown error"}
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"valid": False, "error": str(e)}

    def get_provider_status(self) -> list[dict]:
        """Return status of all providers."""
        status = []
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute("SELECT * FROM downloads"):
                status.append(
                    {
                        "name": row[0],
                        "filename": row[2],
                        "last_download": (
                            datetime.fromtimestamp(row[3], tz=timezone.utc).isoformat()
                            if row[3]
                            else None
                        ),
                        "size": row[6],
                        "enabled": bool(row[7]),
                    }
                )
        return status

    def stage_for_system_install(self) -> list[tuple]:
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

    def build_privileged_install_args(self) -> list[str]:
        """Argomenti pronti per PolkitHelper.run_elevated(), incluso il
        token di protocollo richiesto dall'helper."""
        from .privileged_paths import PROTOCOL_VERSION

        pairs = self.stage_for_system_install()
        args = [f"--protocol={PROTOCOL_VERSION}"]
        for staged, destination in pairs:
            args.extend([staged, destination])
        return args
