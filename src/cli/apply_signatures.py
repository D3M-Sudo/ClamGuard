#!/usr/bin/env python3
"""
Helper privilegiato "applica firme" — installa firme di terze parti
staged e validate in /var/lib/clamav.

Pensato per essere invocato via pkexec dal layer GUI/CLI non privilegiato
di ClamGuard. Deliberatamente piccolo, senza dipendenza GTK, e tratta ogni
input come ostile — la vera superficie di sicurezza sono i validatori in
core/privileged_paths.py; questo modulo è il collegamento attorno ad essi.

Adattamento di ClamUI (src/cli/apply_preferences.py) al caso d'uso
ClamGuard: invece di scrivere file di configurazione sotto /etc, installa
firme di database ClamAV sotto /var/lib/clamav.

Protocollo (versione 1):

    PKEXEC_UID=<uid>  pkexec  clamguard-apply-signatures  --protocol=1 \\
        <staged-src-1> <dest-1>  [<staged-src-2> <dest-2> ...]

L'helper:

1. Legge ``PKEXEC_UID`` dall'ambiente; rifiuta se assente, ``0`` o non
   numerico (exit 3). Questo lega l'autenticazione del file staged
   all'utente che ha realmente autorizzato l'elevazione, non al processo
   root in esecuzione.
2. Richiede ``--protocol=1`` come primo argomento posizionale, così un
   chiamante disallineato fallisce esplicitamente (exit 4) invece di
   essere interpretato a caso.
3. Risolve lo staging root per-utente, lo apre con ``O_NOFOLLOW`` /
   ``O_DIRECTORY``, verifica che sia di proprietà dell'UID chiamante con
   mode ``0o700`` (o più stretto).
4. Per ogni coppia ``(src, dst)``:

   - apre ``src`` con ``O_RDONLY | O_NOFOLLOW | O_NONBLOCK`` (rifiuta
     simlink atomicamente, non blocca su FIFO);
   - fa fstat sul descrittore e conferma: file regolare, UID proprietario,
     niente scrittura di gruppo/altri, path risolto dentro lo staging root;
   - valida la destinazione contro l'allowlist (dentro /var/lib/clamav,
     estensione di database ClamAV riconosciuta);
   - installa atomicamente via ``mkstemp`` nella directory di destinazione,
     ``copyfileobj`` dal descrittore validato, ``fsync``, ``chmod 0o644``,
     ``os.replace`` sulla destinazione. In caso di errore il file
     temporaneo viene rimosso.

5. Segnala a clamd (via ``systemctl reload``/``restart``, se attivo) di
   ricaricare le firme aggiornate.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core.privileged_paths import (
    PROTOCOL_VERSION,
    staging_root_for_uid,
    validate_destination,
    validate_source_for_uid,
    verify_staging_root,
)

_CLAMD_UNITS: tuple[str, ...] = (
    "clamav-daemon.service",
    "clamd.service",
    "clamd@scan.service",
)

# --- Exit codes -------------------------------------------------------
EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_BAD_ARGS = 2
EXIT_BAD_PKEXEC_UID = 3
EXIT_BAD_PROTOCOL = 4


def _parse_path_pairs(args):
    if not args:
        raise ValueError("Nessun file di firma staged fornito.")
    if len(args) % 2 != 0:
        raise ValueError("Argomenti non validi: attese coppie sorgente/destinazione.")
    pairs = []
    for idx in range(0, len(args), 2):
        src, dst = args[idx], args[idx + 1]
        if "\0" in src or "\0" in dst:
            raise ValueError("I percorsi non possono contenere byte nulli.")
        if "\\" in src or "\\" in dst:
            raise ValueError("I percorsi non possono contenere backslash.")
        pairs.append((Path(src), Path(dst)))
    return pairs


def _parse_pkexec_uid():
    raw = os.environ.get("PKEXEC_UID")
    if raw is None:
        return None
    try:
        uid = int(raw)
    except ValueError:
        return None
    if uid <= 0:
        return None
    return uid


def _atomic_install(source_fd: int, destination: Path) -> None:
    """Installa atomicamente il contenuto di source_fd in destination (0o644).

    Il file temporaneo è creato nella stessa directory della destinazione
    così os.replace è atomico. Questa funzione possiede source_fd e lo
    chiude sempre, anche se l'installazione fallisce.
    """
    with os.fdopen(source_fd, "rb", closefd=True) as source_file:
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        tmp_file = None
        try:
            tmp_file = os.fdopen(tmp_fd, "wb", closefd=True)
            with tmp_file:
                shutil.copyfileobj(source_file, tmp_file)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, destination)
        except BaseException:
            if tmp_file is None:
                os.close(tmp_fd)
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise


def _open_and_validate_source(
    source: Path, expected_uid: int, staging_root: Path
) -> int:
    source_fd = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        validate_source_for_uid(source_fd, source, expected_uid, staging_root)
    except BaseException:
        os.close(source_fd)
        raise
    return source_fd


def _reload_clamd() -> None:
    """Segnala a clamd di ricaricare le firme, se un unit attivo esiste.

    Solo gli unit attivi vengono ricaricati: un fallimento qui non deve
    bloccare l'installazione delle firme già scritte con successo.
    """
    if shutil.which("systemctl") is None:
        return
    for unit in _CLAMD_UNITS:
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        if active.returncode != 0:
            continue
        result = subprocess.run(
            ["systemctl", "reload-or-restart", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            error = (
                result.stderr.strip() or result.stdout.strip() or "errore sconosciuto"
            )
            print(f"Attenzione: reload di {unit} fallito: {error}", file=sys.stderr)
        return  # un solo unit clamd attivo alla volta, tipicamente


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    uid = _parse_pkexec_uid()
    if uid is None:
        print(
            "Errore: PKEXEC_UID assente o non valido; rifiuto di procedere.",
            file=sys.stderr,
        )
        return EXIT_BAD_PKEXEC_UID

    expected_protocol = f"--protocol={PROTOCOL_VERSION}"
    if not args or args[0] != expected_protocol:
        print(
            f"Errore: token di protocollo mancante o errato; atteso {expected_protocol} "
            "come primo argomento.",
            file=sys.stderr,
        )
        return EXIT_BAD_PROTOCOL
    args = args[1:]

    try:
        pairs = _parse_path_pairs(args)
    except ValueError as error:
        print(f"Errore: {error}", file=sys.stderr)
        return EXIT_BAD_ARGS

    staging_root = staging_root_for_uid(uid)
    try:
        verify_staging_root(staging_root, uid)
    except (ValueError, OSError) as error:
        print(f"Errore: staging root non valido: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    # Preflight 1: valida ogni sorgente e destinazione PRIMA di aprire qualunque file.
    try:
        for source, destination in pairs:
            # Enforce that source is a direct file within staging_root (no nested directories or path traversal allowed)
            if source.parent.resolve(strict=False) != staging_root.resolve(strict=False):
                raise ValueError(f"Sorgente fuori dal percorso di staging ammesso: {source}")
            validate_destination(destination)
    except ValueError as error:
        print(f"Errore: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    # Preflight 2: apri e autentica ogni sorgente staged, tenendo aperti i
    # descrittori validati. Nessuna destinazione viene scritta finché OGNI
    # sorgente non ha superato i controlli uid/mode/staging-root.
    validated = []  # (source_fd, destination)
    try:
        for source, destination in pairs:
            src_fd = _open_and_validate_source(source, uid, staging_root)
            validated.append((src_fd, destination))
    except (ValueError, OSError) as error:
        for src_fd, _destination in validated:
            try:
                os.close(src_fd)
            except OSError:
                pass
        print(f"Errore: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    # Installazione: copia ogni descrittore preflighted nella sua destinazione.
    installed = 0
    try:
        for src_fd, destination in validated:
            _atomic_install(src_fd, destination)
            installed += 1
        _reload_clamd()
    except (OSError, shutil.Error) as error:
        for src_fd, _destination in validated[installed + 1 :]:
            try:
                os.close(src_fd)
            except OSError:
                pass
        print(f"Errore: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
