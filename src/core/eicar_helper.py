#!/usr/bin/env python3
"""
EICAR test file helper — GTK-free helpers for the EICAR self-test.

Il bottone "EICAR Test" scrive il pattern antivirus standard su un file
temporaneo, lo scansiona e lo pulisce al completamento. Su force-quit /
crash / cancel il cleanup può essere saltato, lasciando il file EICAR in
~/.cache/clamguard/ o /tmp/ — la prossima scansione normale di quella
directory lo segnalerebbe come minaccia reale.

Questo modulo estrae la logica di creazione/pulizia fuori dal codice GTK
(così è unit-testabile senza display) e aggiunge una safety net ``atexit``
così un file stantio non sopravvive mai all'uscita del processo.
"""

from __future__ import annotations

import atexit
import logging
import tempfile
from contextlib import suppress
from pathlib import Path

logger = logging.getLogger("clamguard.eicar_helper")

# Stringa di test EICAR — pattern antivirus standard di settore.
# NON è malware: è una stringa sicura e non funzionale riconosciuta da
# ogni motore AV per scopi di auto-test.
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def create_eicar_temp(parent_dir: str | None = None) -> str:
    """Scrive la stringa EICAR su un file temp e ne ritorna il path.

    Args:
        parent_dir: Directory in cui creare il file temp. ``None`` usa la
            posizione tempfile di sistema.

    Returns:
        Path assoluto del file temp creato. Il chiamante è responsabile
        della pulizia (via :func:`cleanup_eicar_path` e/o
        :func:`register_eicar_atexit_cleanup`).
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".txt",
        prefix="eicar_test_",
        delete=False,
        dir=parent_dir,
    ) as f:
        f.write(EICAR_TEST_STRING)
        return f.name


def cleanup_eicar_path(path: str | None) -> None:
    """Rimozione best-effort di un file temp EICAR.

    Sicura da chiamare ripetutamente, con stringhe vuote, ``None`` o path
    che non esistono più. Gli errori sono loggati a livello debug e
    inghiottiti — il cleanup non deve mai sollevare.
    """
    if not path:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as e:
        # Permessi, file occupato, ecc. — mai propagare dal cleanup.
        logger.debug("Failed to clean up EICAR file %r: %s", path, e)


def register_eicar_atexit_cleanup(path: str | None):
    """Registra un handler ``atexit`` per rimuovere il file EICAR all'uscita.

    Ritorna una callable zero-arg che deregistra l'handler — chiamala dopo
    un cleanup riuscito in-process per evitare un doppio unlink allo
    shutdown dell'interprete. Ritorna una no-op callable quando ``path``
    è falsy.
    """
    if not path:
        return lambda: None

    atexit.register(cleanup_eicar_path, path)

    def _unregister() -> None:
        with suppress(Exception):
            atexit.unregister(cleanup_eicar_path)

    return _unregister