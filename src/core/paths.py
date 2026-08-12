#!/usr/bin/env python3
"""
paths — XDG Base Directory helpers.

I moduli core (quarantine, history, third_party_db) devono persistere dati
in una posizione scrivibile dal processo utente, sia in esecuzione nativa
sia dentro il sandbox Flatpak. Path hardcoded come /var/lib/clamguard o
/var/lib/clamav richiedono permessi di root e, in Flatpak, non sono
nemmeno montati nel sandbox (o lo sono in sola lettura), quindi rompono
la persistenza dei dati.

Questo modulo centralizza la risoluzione dei path seguendo la XDG Base
Directory Specification, senza dipendere da GLib/PyGObject (i moduli core
restano testabili anche fuori da un ambiente GTK).
"""

import os
import subprocess
from functools import lru_cache

APP_DIRNAME = "clamguard"
APP_ID = "io.github.d3msudo.clamguard"

# Directory persistite dal sandbox Flatpak (flag --persist nel manifest).
# Queste directory vivono sull'host in:
#   $HOME_HOST/.var/app/<app-id>/<rel-path>
# e NON in $HOME_HOST/<rel-path> come i file utente condivisi.
PERSIST_DIRS: tuple[str, ...] = (
    ".local/share/clamguard",
    ".config/clamguard",
)


def get_data_home() -> str:
    """Ritorna $XDG_DATA_HOME, o ~/.local/share come da specifica XDG.

    Sotto Flatpak, $HOME è rimappato su ~/.var/app/<app-id>, quindi
    ~/.local/share risolve automaticamente in una posizione persistita
    tramite il permesso --persist=.local/share/clamguard già presente nel
    manifest.
    """
    return os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )


def get_state_home() -> str:
    """Ritorna $XDG_STATE_HOME, o ~/.local/state come da specifica XDG."""
    return os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )


def get_config_home() -> str:
    """Ritorna $XDG_CONFIG_HOME, o ~/.config come da specifica XDG."""
    return os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )


def app_data_dir(*parts: str) -> str:
    """Percorso dati dell'app: $XDG_DATA_HOME/clamguard/<parts...>."""
    return os.path.join(get_data_home(), APP_DIRNAME, *parts)


def is_flatpak_sandbox() -> bool:
    """True se il processo corrente gira dentro un sandbox Flatpak."""
    return os.path.exists("/.flatpak-info") or bool(os.environ.get("FLATPAK_ID"))


def compute_file_hash(filepath: str | os.PathLike) -> str:
    """Calcola lo sha256 di un file a blocchi di 64KB per evitare memory spikes."""
    import hashlib

    sha256 = hashlib.sha256()
    with open(str(filepath), "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


@lru_cache(maxsize=1)
def get_host_home() -> str:
    """Ritorna la home directory reale dell'host.

    Dentro il sandbox Flatpak, $HOME è rimappato su
    ~/.var/app/<app-id>. Per eseguire comandi sull'host (es. clamscan via
    flatpak-spawn --host) serve la home reale dell'utente, che si ottiene
    chiedendola all'host stesso. Il risultato è cachato perché non cambia
    durante la vita del processo.
    """
    if not is_flatpak_sandbox():
        return os.path.expanduser("~")
    try:
        result = subprocess.run(
            ["flatpak-spawn", "--host", "sh", "-c", "echo $HOME"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            home = result.stdout.strip()
            if home:
                return home
    except (OSError, subprocess.TimeoutExpired):
        pass
    # Fallback: se non riusciamo a chiedere all'host, proviamo a derivare
    # la home reale dal path sandbox (rimuovendo il prefisso .var/app).
    sandbox_home = os.path.expanduser("~")
    marker = f"/.var/app/{APP_ID}"
    if marker in sandbox_home:
        return sandbox_home.split(marker)[0]
    return sandbox_home


def to_host_path(path: str) -> str:
    """Converte un path dal namespace sandbox Flatpak al path host reale.

    Dentro il sandbox, $HOME è ~/.var/app/<app-id>. Due casi distinti:

    1. **File utente condivisi** (es. xdg-documents, xdg-download): il path
       sandbox ~/.var/app/<app-id>/Documenti/foo corrisponde all'host
       ~/Documenti/foo — Flatpak monta la directory dell'utente alla stessa
       posizione relativa dentro la home sandbox.

    2. **Directory persistite** (--persist=.local/share/clamguard,
       --persist=.config/clamguard): il path sandbox
       ~/.local/share/clamguard/... corrisponde all'host
       ~/.var/app/<app-id>/.local/share/clamguard/... — i dati persistiti
       vivono nella directory .var/app sull'host, NON nella home diretta.

    Prima di passare il path a un comando eseguito sull'host
    (flatpak-spawn --host clamscan ...) va riconvertito nella forma host.

    In esecuzione nativa (non Flatpak) il path è già nella forma host e
    viene restituito invariato.
    """
    if not is_flatpak_sandbox():
        return path

    sandbox_home = os.path.expanduser("~")
    host_home = get_host_home()

    # Path dentro la home del sandbox.
    if path.startswith(sandbox_home):
        rel = path[len(sandbox_home):].lstrip("/")
        for persist_dir in PERSIST_DIRS:
            if rel == persist_dir or rel.startswith(persist_dir + "/"):
                # Directory persistita: sull'host vive in
                # $HOME_HOST/.var/app/<app-id>/<rel-path>
                return os.path.join(
                    host_home, ".var", "app", APP_ID, rel
                )
        # File utente condiviso: stesso path relativo nella home host.
        return host_home + path[len(sandbox_home):]

    # Fallback: se il path contiene il marker .var/app/<app-id>, rimuovilo.
    marker = f"/.var/app/{APP_ID}"
    if marker in path:
        return path.replace(marker, "")

    return path


def to_sandbox_path(path: str) -> str:
    """Converte un path dal namespace host al namespace sandbox Flatpak.

    È l'inverso di ``to_host_path``: i risultati di clamscan eseguito
    sull'host (via flatpak-spawn --host) sono in namespace host; per
    coerenza interna dell'app (es. quarantena, storico) vanno riconvertiti
    nel namespace sandbox in cui l'app stessa vive.

    In esecuzione nativa (non Flatpak) il path è già nel namespace corretto
    e viene restituito invariato.
    """
    if not is_flatpak_sandbox():
        return path

    sandbox_home = os.path.expanduser("~")
    host_home = get_host_home()

    # Directory persistite: sull'host vivono in
    # $HOME_HOST/.var/app/<app-id>/<rel-path> e nel sandbox in
    # $HOME_SANDBOX/<rel-path>.
    persist_prefix = os.path.join(host_home, ".var", "app", APP_ID)
    if path.startswith(persist_prefix):
        rel = path[len(persist_prefix):].lstrip("/")
        for persist_dir in PERSIST_DIRS:
            if rel == persist_dir or rel.startswith(persist_dir + "/"):
                return os.path.join(sandbox_home, rel)

    # File utente condivisi: host $HOME_HOST/<rel> → sandbox $HOME_SANDBOX/<rel>.
    if path.startswith(host_home):
        return sandbox_home + path[len(host_home):]

    return path
