"""
Validatori di sicurezza per l'helper privilegiato "applica firme".

Sul modello di ClamUI (src/core/privileged_paths.py): questo modulo è la
*singola fonte di verità* per cosa l'helper pkexec-elevato può scrivere, e
autentica ogni file staged prima che venga copiato in una destinazione di
sistema. È pure-Python, senza dipendenze GTK/D-Bus, per restare facile da
testare in isolamento — è il confine di sicurezza reale dell'helper.

Differenza rispetto a ClamUI: ClamUI scrive file di *configurazione*
(freshclam.conf, clamd.conf) sotto /etc. ClamGuard scrive *firme di
terze parti* già scaricate e verificate da ThirdPartyDBManager in un'area
utente, dentro la directory di sistema di ClamAV /var/lib/clamav, così
che un clamd di sistema possa vederle (vedi core/third_party_db.py).
"""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

# Destinazione ammessa: solo dentro /var/lib/clamav, niente sottodirectory
# annidate. Sia l'helper sia il chiamante importano questa costante — i
# test dovrebbero fare monkeypatch con un path sotto tmp_path piuttosto
# che ridefinire la policy altrove.
ALLOWED_DEST_DIRS: tuple[Path, ...] = (Path("/var/lib/clamav"),)

# Estensioni di database riconosciute da ClamAV (clamscan/clamd le caricano
# automaticamente da DatabaseDirectory). Qualunque altra estensione viene
# rifiutata: l'helper non è un file-copy generico.
ALLOWED_SIGNATURE_EXTENSIONS: tuple[str, ...] = (
    ".cvd", ".cld", ".cud",
    ".hdb", ".hdu", ".hsb", ".hsu",
    ".ndb", ".ndu",
    ".ldb", ".ldu",
    ".fp", ".pdb", ".gdb", ".wdb", ".mdb", ".mdu",
    ".crb", ".zmd", ".rmd", ".cbc", ".cdb", ".cat",
    ".yar", ".yara",
)

# Bump se il protocollo cambia forma: l'helper rifiuta ogni invocazione che
# non parte con --protocol=<PROTOCOL_VERSION>, così una versione disallineata
# fallisce in modo esplicito invece di essere interpretata a caso.
PROTOCOL_VERSION = 1


def is_running_as_root() -> bool:
    """True se il processo corrente ha già EUID 0 (elevazione superflua)."""
    return os.geteuid() == 0


def staging_root_for_uid(uid: int) -> Path:
    """Directory di staging per-utente: <home-passwd>/.cache/clamguard/privileged-staging.

    L'helper (che gira sull'host, via flatpak-spawn --host in Flatpak) e il
    chiamante non privilegiato calcolano indipendentemente questo path a
    partire dal database passwd (mai da $HOME, che dentro Flatpak punta a
    ~/.var/app/<id> e non coinciderebbe con quanto vede l'helper sull'host).
    """
    return Path(pwd.getpwuid(uid).pw_dir) / ".cache" / "clamguard" / "privileged-staging"


def validate_destination(destination: Path) -> None:
    """Verifica che ``destination`` sia dentro /var/lib/clamav con
    un'estensione di database ClamAV riconosciuta, senza sottodirectory
    annidate né componenti '..'.

    Solleva ValueError se la destinazione non è ammessa.
    """
    try:
        resolved_parent = destination.parent.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Impossibile risolvere la directory padre: {destination}") from exc

    candidate = resolved_parent / destination.name

    if candidate.suffix.lower() not in ALLOWED_SIGNATURE_EXTENSIONS:
        raise ValueError(
            f"Estensione non ammessa per una firma ClamAV: {destination} "
            f"(ammesse: {', '.join(ALLOWED_SIGNATURE_EXTENSIONS)})"
        )

    if candidate.stem == "":
        raise ValueError(f"Nome file vuoto: {destination}")

    if resolved_parent not in ALLOWED_DEST_DIRS:
        raise ValueError(f"Destinazione fuori dall'allowlist: {destination}")


def _fstat_strict(fd: int) -> os.stat_result:
    """os.fstat(fd) — indirezione per facilitare i test."""
    return os.fstat(fd)


def validate_source_for_uid(
    source_fd: int,
    source_path: Path,
    expected_uid: int,
    staging_root: Path,
) -> None:
    """Autentica un file staged rispetto all'utente che ha richiesto l'elevazione.

    Il chiamante DEVE aver già aperto ``source_fd`` con
    ``os.O_RDONLY | os.O_NOFOLLOW`` (e tipicamente ``O_NONBLOCK``, contro
    le FIFO). Si fa fstat sul *descrittore* (mai sul path — reintrodurrebbe
    una finestra TOCTOU) e si verifica:

    - è un file regolare;
    - l'UID proprietario coincide con ``expected_uid``;
    - non è scrivibile da gruppo/altri;
    - il path risolto vive dentro ``staging_root`` (per impedire che un
      bind-mount malevolo reindirizzi l'helper altrove).
    """
    st = _fstat_strict(source_fd)

    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Il file staged non è un file regolare: {source_path}")

    if st.st_uid != expected_uid:
        raise ValueError(
            f"Il file staged ha uid={st.st_uid}, atteso uid={expected_uid}: {source_path}"
        )

    if st.st_mode & 0o022:
        raise ValueError(f"Il file staged ha permessi non sicuri {oct(st.st_mode & 0o777)}: {source_path}")

    try:
        resolved_source = source_path.resolve(strict=True)
        resolved_staging = staging_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Impossibile risolvere il path staged: {source_path}") from exc

    try:
        resolved_source.relative_to(resolved_staging)
    except ValueError as exc:
        raise ValueError(
            f"Il file staged {resolved_source} è fuori dallo staging root {resolved_staging}"
        ) from exc


def verify_staging_root(staging_root: Path, expected_uid: int) -> None:
    """Verifica che la directory di staging per-utente sia sicura da leggere.

    Apertura con ``O_NOFOLLOW`` (niente staging root simlinkata) e
    ``O_DIRECTORY`` (niente file regolare spacciato per directory), poi
    fstat conferma: è una directory, è di proprietà di ``expected_uid``,
    non ha bit group/other (mode 0o700 o più stretto).
    """
    fd = os.open(str(staging_root), os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        st = _fstat_strict(fd)
    finally:
        os.close(fd)

    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"Lo staging root non è una directory: {staging_root}")

    if st.st_uid != expected_uid:
        raise ValueError(
            f"Lo staging root ha uid={st.st_uid}, atteso uid={expected_uid}: {staging_root}"
        )

    if st.st_mode & 0o077:
        raise ValueError(f"Lo staging root ha permessi non sicuri {oct(st.st_mode & 0o777)}: {staging_root}")
