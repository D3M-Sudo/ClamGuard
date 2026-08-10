#!/usr/bin/env python3
import unittest
import tempfile
import os
from src.core.third_party_db import ThirdPartyDBManager


class TestThirdPartyUpdater(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = ThirdPartyDBManager(sig_dir=self.tmpdir, state_dir=self.tmpdir)

    def test_provider_status(self):
        status = self.mgr.get_provider_status()
        self.assertGreater(len(status), 0)

    def test_db_permissions(self):
        """Verify that the third party database file has secure 0o600 permissions."""
        db_path = os.path.join(self.tmpdir, "test_perm.db")
        mgr = ThirdPartyDBManager(sig_dir=self.tmpdir, state_dir=self.tmpdir, db_path=db_path)
        self.assertIsNotNone(mgr)
        self.assertTrue(os.path.exists(db_path))
        mode = os.stat(db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
