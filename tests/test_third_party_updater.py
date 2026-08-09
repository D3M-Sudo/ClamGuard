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


if __name__ == "__main__":
    unittest.main()
