"""
``clamguard install-privileged-helper`` — installa l'helper privilegiato
per le firme e la sua policy polkit sull'host.

ClamGuard installa le firme di terze parti scaricate in /var/lib/clamav
tramite un helper elevato via pkexec. Perché pkexec autorizzi l'azione,
l'helper deve vivere esattamente in /usr/bin/clamguard-apply-signatures
(il path nominato nella policy polkit) e la policy deve essere installata
sotto /usr/share/polkit-1/actions. Solo un'installazione root-level può
scrivere lì — cosa che un pacchetto .deb farebbe automaticamente, ma
un'installazione da sorgente o pip no. Questo comando permette di
configurarlo una volta con `sudo`, indipendentemente da come ClamGuard è
stato installato (sul modello di ClamUI, issue #143 upstream).

Dentro un sandbox Flatpak questo comando non può scrivere sui path
dell'host in nessun caso: serve un pacchetto separato
`clamguard-privileged-helper` installato sull'host (vedi run()).

Sicurezza: l'helper installato è **autocontenuto e root-owned**. Si copiano
apply_signatures.py e la sua unica dipendenza (privileged_paths.py —
entrambi pure standard-library) in una directory root-owned
/usr/lib/clamguard, e si genera un wrapper che gira sotto il python3 di
sistema. pkexec non esegue quindi mai codice da una posizione
scrivibile dall'utente (che reintrodurrebbe la classe di vulnerabilità
"VULN-001" descritta da ClamUI).
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

from ..core.paths import is_flatpak_sandbox

# Posizioni canoniche a runtime. Sono fisse perché l'annotazione
# exec.path della policy polkit nomina esattamente
# /usr/bin/clamguard-apply-signatures, e il wrapper generato ha la
# directory libreria hard-coded.
RUNTIME_BIN = "/usr/bin/clamguard-apply-signatures"
RUNTIME_LIB_DIR = "/usr/lib/clamguard"
POLKIT_ACTIONS_DIR = "/usr/share/polkit-1/actions"
POLICY_NAME = "io.github.d3msudo.clamguard.policy"

# Import relativo originale dentro apply_signatures.py, e la sua
# sostituzione a namespace piatto per l'helper copiato e autocontenuto.
_ORIGINAL_IMPORT = "from ..core.privileged_paths import"
_REWRITTEN_IMPORT = "from clamguard_privileged_paths import"

_WRAPPER_TEMPLATE = """\
#!/usr/bin/python3
# Helper privilegiato "applica firme" di ClamGuard.
# Installato da `clamguard install-privileged-helper`. Invocato come root
# via pkexec; carica i moduli helper autocontenuti e root-owned sotto {lib_dir}.
import sys

sys.path.insert(0, "{lib_dir}")
from clamguard_apply_signatures import main

sys.exit(main())
"""


def _source_paths() -> tuple[Path, Path, Traversable]:
    """Risolve i file sorgente da installare (helper, dipendenza, policy).

    I moduli Python dell'helper (apply_signatures e privileged_paths) sono
    risolti relativamente a questo pacchetto installato — vivono sempre sul
    filesystem, quindi bastano Path normali. La policy polkit, invece, è
    distribuita come risorsa importlib.resources dentro src.cli.resources
    e ritornata come Traversable: un handle path-like che funziona sia per
    pacchetti su disco sia per wheel zippate.
    """
    cli_dir = Path(__file__).resolve().parent  # .../src/cli
    apply_src = cli_dir / "apply_signatures.py"
    priv_src = cli_dir.parent / "core" / "privileged_paths.py"
    policy_src = files(f"{__name__.rsplit('.', 1)[0]}.resources") / POLICY_NAME
    return apply_src, priv_src, policy_src


def _create_install_directories(root: Path, dest_dirs: tuple[Path, ...]) -> None:
    """Crea le directory di destinazione mancanti con mode deterministico 0o755.

    nosec B103 su entrambi i chmod sotto: operano esclusivamente su
    directory create da .mkdir() in questa stessa funzione (mai su file),
    e 0o755 (rwxr-xr-x) è il permesso standard per directory sotto
    /usr/{bin,lib,share} — servono attraversabili da chiunque. Bandit
    segnala ogni chmod con bit world-readable/executable a prescindere,
    senza distinguere file da directory.
    """
    try:
        root.mkdir(mode=0o755, parents=True)
    except FileExistsError:
        pass
    else:
        os.chmod(root, 0o755)  # nosec B103 — directory, non file
    for dest_dir in dest_dirs:
        current = root
        for component in dest_dir.relative_to(root).parts:
            current /= component
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                continue
            os.chmod(current, 0o755)  # nosec B103 — directory, non file


def _atomic_install_file(destination: Path, content: bytes, mode: int) -> None:
    """Installa atomicamente content come file regolare in destination.

    I byte sono scritti in un file temporaneo regolare creato nella
    directory di destination, poi flush/fsync, mode assegnato (e
    ownership root quando l'installer gira come root), e scambiato al
    posto giusto con os.replace. Poiché os.replace opera sulla entry di
    directory invece di seguire un simlink nel componente finale, un
    simlink preesistente in destination viene SOSTITUITO dal nuovo file
    regolare — mai scritto attraverso — così un attaccante non può
    reindirizzare la scrittura root-owned verso il target del simlink
    (classe VULN-001, come in ClamUI issue #143).
    """
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(destination.parent),
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    tmp_file = None
    try:
        tmp_file = os.fdopen(tmp_fd, "wb", closefd=True)
        with tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.chmod(tmp_name, mode)
        if os.geteuid() == 0:
            os.chown(tmp_name, 0, 0)
        os.replace(tmp_name, str(destination))
    except BaseException:
        if tmp_file is None:
            os.close(tmp_fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def install_privileged_helper(prefix: str = "/") -> tuple[bool, str]:
    """Installa l'helper privilegiato, la sua libreria, e la policy polkit.

    Args:
        prefix: radice di installazione. Default "/" (installazione reale
            di sistema); i test passano una directory temporanea. Il
            wrapper generato referenzia sempre la RUNTIME_LIB_DIR
            canonica, dato che a runtime i file vivono lì davvero.

    Returns:
        (successo, messaggio).
    """
    apply_src, priv_src, policy_src = _source_paths()
    for src in (apply_src, priv_src):
        if not src.is_file():
            return (False, f"File sorgente richiesto non trovato: {src}")
    if not policy_src.is_file():
        return (False, f"Risorsa policy non trovata: {POLICY_NAME}")

    # Riscrive l'unico import relativo di apply_signatures.py così il
    # modulo copiato può essere importato da una directory piatta e
    # root-owned sotto il python di sistema.
    apply_content = apply_src.read_text(encoding="utf-8").replace(
        _ORIGINAL_IMPORT, _REWRITTEN_IMPORT
    )
    if "from ..core" in apply_content or "\nfrom .core" in apply_content:
        return (
            False,
            "Import relativo inatteso rimasto nel sorgente dell'helper; interrotto.",
        )

    root = Path(prefix)
    lib_dir = root / RUNTIME_LIB_DIR.lstrip("/")
    bin_path = root / RUNTIME_BIN.lstrip("/")
    policy_dst = root / POLKIT_ACTIONS_DIR.lstrip("/") / POLICY_NAME
    install_dirs = (lib_dir, bin_path.parent, policy_dst.parent)

    try:
        _create_install_directories(root, install_dirs)

        priv_dst = lib_dir / "clamguard_privileged_paths.py"
        apply_dst = lib_dir / "clamguard_apply_signatures.py"
        wrapper_content = _WRAPPER_TEMPLATE.format(lib_dir=RUNTIME_LIB_DIR)

        _atomic_install_file(priv_dst, priv_src.read_bytes(), 0o644)
        _atomic_install_file(apply_dst, apply_content.encode("utf-8"), 0o644)
        _atomic_install_file(bin_path, wrapper_content.encode("utf-8"), 0o755)
        _atomic_install_file(policy_dst, policy_src.read_bytes(), 0o644)
    except OSError as e:
        return (False, f"Installazione dell'helper privilegiato fallita: {e}")

    return (
        True,
        (
            f"Helper installato in {bin_path} e policy polkit in {policy_dst}. "
            "ClamGuard può ora installare le firme di terze parti nel database di sistema."
        ),
    )


def run(args: argparse.Namespace) -> int:
    """Entry point del sottocomando install-privileged-helper."""
    prefix = getattr(args, "prefix", "/")

    # Un sandbox Flatpak non può raggiungere i path dell'host: un'installazione
    # di sistema reale da lì dentro è impossibile a prescindere dai privilegi.
    # Va delegata a un pacchetto separato clamguard-privileged-helper installato
    # sull'host (sia con che senza root).
    if prefix == "/" and is_flatpak_sandbox():
        print(
            "ClamGuard gira dentro un sandbox Flatpak, che non può installare "
            "file sull'host. Installa il pacchetto clamguard-privileged-helper "
            "corrispondente sul sistema host.",
            file=sys.stderr,
        )
        return 1

    if prefix == "/" and os.geteuid() != 0:
        print(
            "Questo comando installa file sotto /usr e /usr/share e deve "
            "girare come root. Prova: sudo clamguard-daemon install-privileged-helper",
            file=sys.stderr,
        )
        return 1

    success, message = install_privileged_helper(prefix)
    if success:
        print(message)
        return 0

    print(f"Errore: {message}", file=sys.stderr)
    return 1


def register(subparsers: argparse._SubParsersAction) -> None:
    """Registra il sottocomando install-privileged-helper nel router CLI."""
    parser = subparsers.add_parser(
        "install-privileged-helper",
        help="Installa l'helper privilegiato per le firme e la policy polkit (esegui con sudo)",
        description=(
            "Installa /usr/bin/clamguard-apply-signatures e la sua policy polkit "
            "così ClamGuard può installare le firme di terze parti nel database "
            "ClamAV di sistema. Esegui come root (sudo). Sotto Flatpak, va "
            "installato invece il pacchetto clamguard-privileged-helper "
            "corrispondente sull'host."
        ),
    )
    parser.add_argument("--prefix", default="/", help=argparse.SUPPRESS)
    parser.set_defaults(func=run)
