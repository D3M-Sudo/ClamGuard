#!/usr/bin/env python3
import os
import tempfile
import unittest

from src.core.virustotal import VirusTotalClient


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


if __name__ == "__main__":
    unittest.main()
