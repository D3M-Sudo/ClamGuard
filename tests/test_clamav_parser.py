#!/usr/bin/env python3
import unittest
from src.core.clamav import ClamAVScanner


class TestClamAVParser(unittest.TestCase):
    def test_parse_clamd_response_found(self):
        scanner = ClamAVScanner()
        r = scanner._parse_clamd_response(
            "/tmp/eicar", "stream: Eicar-Test-Signature FOUND"
        )
        self.assertTrue(r.infected)
        self.assertEqual(r.virus_name, "Eicar-Test-Signature")

    def test_parse_clamd_response_ok(self):
        scanner = ClamAVScanner()
        r = scanner._parse_clamd_response("/tmp/clean", "/tmp/clean: OK")
        self.assertFalse(r.infected)

    def test_clamscan_fallback_has_chunk_size_default(self):
        """Regressione: _scan_clamd() richiama _scan_clamscan(paths,
        progress_callback) SENZA chunk_size quando clamd fallisce a metà
        scansione. Prima del fix, chunk_size non aveva un valore di
        default: quel fallback avrebbe sollevato TypeError esattamente
        nel momento in cui serve di più (clamd già fallito). Verifichiamo
        che la chiamata usata realmente dal fallback sia vincolabile.
        """
        import inspect

        sig = inspect.signature(ClamAVScanner._scan_clamscan)
        # Chiamata esatta usata dal fallback in _scan_clamd (self, paths, progress_callback)
        sig.bind(
            None, ["/tmp/x"], None
        )  # solleva TypeError se chunk_size non ha default


if __name__ == "__main__":
    unittest.main()
