#!/usr/bin/env python3
"""
paths — XDG Base Directory helpers.

I moduli core (quarantine, history, third_party_db) devono persistere dati
in una posizione scrivibile dal processo utente, sia in esecuzione nativa
sia dentro il sandbox Flatpak. Path hardcoded come /var/lib/alpha o
/var/lib/clamav richiedono permessi di root e, in Flatpak, non sono
nemmeno montati nel sandbox (o lo sono in sola lettura), quindi rompono
la persistenza dei dati.

Questo modulo centralizza la risoluzione dei path seguendo la XDG Base
Directory Specification, senza dipendere da GLib/PyGObject (i moduli core
restano testabili anche fuori da un ambiente GTK).
"""

import os

APP_DIRNAME = "clamguard"


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
    """Percorso dati dell'app: $XDG_DATA_HOME/alpha/<parts...>."""
    return os.path.join(get_data_home(), APP_DIRNAME, *parts)


def is_flatpak_sandbox() -> bool:
    """True se il processo corrente gira dentro un sandbox Flatpak."""
    return os.path.exists("/.flatpak-info") or bool(os.environ.get("FLATPAK_ID"))
