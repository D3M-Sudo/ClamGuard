#!/usr/bin/env python3
"""CG-018: test EICAR — verifica che il motore di scansione rilevi
correttamente il pattern antivirus standard e che il modulo helper
eicar_helper gestisca creazione/pulizia del file temp senza lasciare
file stanti.

Il test end-to-end è opzionale: viene saltato se clamscan/clamd non è
disponibile nel sistema, così la CI non fallisce su macchine senza ClamAV.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clamav import ClamAVScanner  # noqa: E402
from src.core.eicar_helper import (  # noqa: E402
    EICAR_TEST_STRING,
    cleanup_eicar_path,
    create_eicar_temp,
    register_eicar_atexit_cleanup,
)


def _clamav_available() -> bool:
    """True se clamscan o clamd è disponibile sul sistema."""
    if shutil.which("clamscan"):
        return True
    # In esecuzione sandbox Flatpak, clamscan può essere richiamato
    # sull'host via flatpak-spawn.
    try:
        result = subprocess.run(
            ["flatpak-spawn", "--host", "clamscan", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class TestEicarHelper(unittest.TestCase):
    """Test unitari del modulo eicar_helper (GTK-free)."""

    def test_create_eicar_temp_writes_standard_string(self):
        path = create_eicar_temp()
        try:
            self.assertTrue(os.path.exists(path))
            with open(path, "r") as f:
                content = f.read()
            self.assertEqual(content.strip(), EICAR_TEST_STRING)
        finally:
            cleanup_eicar_path(path)

    def test_create_eicar_temp_in_parent_dir(self):
        with tempfile.TemporaryDirectory() as d:
            path = create_eicar_temp(parent_dir=d)
            try:
                self.assertTrue(path.startswith(d))
                self.assertTrue(os.path.exists(path))
            finally:
                cleanup_eicar_path(path)

    def test_cleanup_removes_file(self):
        path = create_eicar_temp()
        self.assertTrue(os.path.exists(path))
        cleanup_eicar_path(path)
        self.assertFalse(os.path.exists(path))

    def test_cleanup_safe_on_missing_or_none(self):
        # Non deve sollevare: percorso inesistente, None, stringa vuota.
        cleanup_eicar_path(os.path.join(tempfile.gettempdir(), "does_not_exist_eicar"))
        cleanup_eicar_path(None)
        cleanup_eicar_path("")

    def test_atexit_registration_and_unregister(self):
        path = create_eicar_temp()
        unregister = register_eicar_atexit_cleanup(path)
        try:
            # La registrazione non deve fallire.
            self.assertTrue(True)
        finally:
            unregister()
            cleanup_eicar_path(path)

    def test_atexit_unregister_returns_noop_for_falsy(self):
        noop = register_eicar_atexit_cleanup(None)
        # Non deve sollevare nessuna eccezione.
        noop()
        noop2 = register_eicar_atexit_cleanup("")
        noop2()


@unittest.skipUnless(_clamav_available(), "clamscan/clamd not available")
class TestEicarEndToEnd(unittest.TestCase):
    """Test di integrazione end-to-end: scan del file EICAR con lo
    scanner reale, verifica che venga rilevato come minaccia."""

    def test_eicar_file_is_detected(self):
        path = create_eicar_temp()
        try:
            scanner = ClamAVScanner()
            results = asyncio.run(scanner.scan_paths([path]))
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].infected)
            self.assertIn("EICAR", results[0].virus_name.upper())
        finally:
            cleanup_eicar_path(path)

    def test_eicar_detected_via_clamscan_fallback(self):
        """Verifica il rilevamento con clamscan forzato (fallback usato
        quando clamd non è disponibile o in Flatpak)."""
        path = create_eicar_temp()
        try:
            scanner = ClamAVScanner(prefer_clamd=False)
            results = asyncio.run(scanner.scan_paths([path]))
            infected = [r for r in results if r.infected]
            self.assertGreater(len(infected), 0)
            self.assertIn("EICAR", infected[0].virus_name.upper())
        finally:
            cleanup_eicar_path(path)


if __name__ == "__main__":
    unittest.main()