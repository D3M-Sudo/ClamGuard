#!/usr/bin/env python3
import os
import tempfile
import unittest
from src.core.history import HistoryManager


class TestHistory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_history_db_permissions(self):
        """Verify that the history database file has secure 0o600 permissions."""
        db_path = os.path.join(self.tmpdir, "history_test.db")
        manager = HistoryManager(db_path=db_path)
        self.assertIsNotNone(manager)
        self.assertTrue(os.path.exists(db_path))
        mode = os.stat(db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
