#!/usr/bin/env python3
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.core.virustotal import REQUESTS_AVAILABLE, VirusTotalClient


class TestVirusTotal(unittest.TestCase):
    def test_cache_init(self):
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(cache_db=os.path.join(tmpdir, "vt.db"))
        self.assertIsNotNone(client)

    def test_default_cache_db_path(self):
        """Verify default cache_db points to user-specific app data directory."""
        client = VirusTotalClient()
        self.assertTrue(client.cache_db.endswith("clamguard/virustotal_cache.db"))

    def test_cache_db_permissions(self):
        """Verify that cache_db file has secure 0o600 permissions."""
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "vt_secure.db")
        client = VirusTotalClient(cache_db=db_path)
        self.assertIsNotNone(client)
        self.assertTrue(os.path.exists(db_path))
        mode = os.stat(db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests not installed")
    def test_tls_hardening(self):
        """CG-017: la sessione deve usare certifi per la verifica TLS e
        ignorare le variabili d'ambiente (trust_env=False), così che una
        variabile d'ambiente non possa disabilitare la verifica dei
        certificati."""
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(
            api_key="test-key", cache_db=os.path.join(tmpdir, "vt_tls.db")
        )
        self.assertIsNotNone(client._session)
        self.assertFalse(client._session.trust_env)
        # verify deve essere impostato a un bundle CA (certifi o di sistema).
        self.assertTrue(client._session.verify)

    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests not installed")
    @patch("src.core.virustotal.time.sleep")
    def test_retry_on_503(self, mock_sleep):
        """CG-008: _make_request deve ritentare su HTTP 503 con backoff
        esponenziale (2→4→8s), fino a 3 retry, prima di arrendersi."""
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(
            api_key="test-key", cache_db=os.path.join(tmpdir, "vt_retry.db")
        )
        mock_session = MagicMock()
        mock_session.request.side_effect = [
            MagicMock(status_code=503),
            MagicMock(status_code=503),
            MagicMock(status_code=200),
        ]
        client._session = mock_session

        resp = client._make_request("GET", "https://example.com")

        self.assertEqual(mock_session.request.call_count, 3)
        self.assertEqual(resp.status_code, 200)
        # Backoff: 2s poi 4s.
        self.assertEqual(mock_sleep.call_args_list[0][0][0], 2.0)
        self.assertEqual(mock_sleep.call_args_list[1][0][0], 4.0)

    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests not installed")
    @patch("src.core.virustotal.time.sleep")
    def test_retry_gives_up_after_max_attempts(self, mock_sleep):
        """CG-008: dopo 3 retry falliti su 503, _make_request deve
        restituire l'ultima risposta (non sollevare)."""
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(
            api_key="test-key", cache_db=os.path.join(tmpdir, "vt_retry2.db")
        )
        mock_session = MagicMock()
        mock_session.request.side_effect = [
            MagicMock(status_code=503),
            MagicMock(status_code=503),
            MagicMock(status_code=503),
            MagicMock(status_code=503),
        ]
        client._session = mock_session

        resp = client._make_request("GET", "https://example.com")

        self.assertEqual(mock_session.request.call_count, 4)  # 1 + 3 retry
        self.assertEqual(resp.status_code, 503)

    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests not installed")
    def test_upload_refuses_oversized_file(self):
        """CG-009: l'upload deve essere rifiutato PRIMA di leggere il file
        se supera VT_MAX_FILE_SIZE, evitando di caricare in RAM file
        enormi (OOM)."""
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(
            api_key="test-key", cache_db=os.path.join(tmpdir, "vt_size.db")
        )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"x" * 100)
            f.flush()
            with patch("src.core.virustotal.VT_MAX_FILE_SIZE", 10):
                result = client.upload_file(f.name)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
