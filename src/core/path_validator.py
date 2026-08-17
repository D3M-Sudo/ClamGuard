"""
path_validator — Validazione dei path di input per le scansioni.

CG-005: prima del fix, ClamAVScanner._expand_to_files accettava qualsiasi
stringa senza controlli, inclusi symlink a file sensibili (es. /etc/shadow)
o path con componenti di traversal. Questo modulo centralizza la
validazione dei path prima che vengano passati allo scanner.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger("clamguard.path_validator")

# File/directory sensibili di sistema che non dovrebbero mai essere
# scansionati come target diretto (difesa in profondità). La lista non è
# esaustiva: è un ulteriore strato oltre al rifiuto dei symlink.
SENSITIVE_PATHS = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
}


def is_absolute(path: str) -> bool:
    """Il path deve essere assoluto."""
    return os.path.isabs(path)


def exists_and_readable(path: str) -> bool:
    """Il path deve esistere ed essere leggibile."""
    return os.path.exists(path) and os.access(path, os.R_OK)


def not_path_traversal(path: str) -> bool:
    """Il path non deve contenere componenti di traversal (..)."""
    return ".." not in Path(path).parts


def not_sensitive_path(path: str) -> bool:
    """Il path non deve essere un path sensibile né un symlink a un path sensibile."""
    try:
        resolved = os.path.realpath(path)
    except OSError:
        resolved = path

    for sensitive in SENSITIVE_PATHS:
        if (
            path == sensitive
            or path.startswith(sensitive + os.sep)
            or resolved == sensitive
            or resolved.startswith(sensitive + os.sep)
        ):
            return False
    return True


def not_symlink_to_sensitive(path: str) -> bool:
    """Funzione di compatibilità: verifica che il path non sia sensibile."""
    return not_sensitive_path(path)


def validate_path(path: str) -> tuple[bool, str | None]:
    """Valida un path di input per la scansione.

    Ritorna (True, None) se valido, (False, motivo) altrimenti.
    """
    if not is_absolute(path):
        return False, f"Path non assoluto: {path}"
    if not exists_and_readable(path):
        return False, f"Path inesistente o non leggibile: {path}"
    if not not_path_traversal(path):
        return False, f"Path traversal non ammesso: {path}"
    if not not_sensitive_path(path):
        return False, f"Path sensibile non ammesso: {path}"
    return True, None
