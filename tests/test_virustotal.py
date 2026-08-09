#!/usr/bin/env python3
import unittest
import tempfile
import os
from src.core.virustotal import VirusTotalClient


class TestVirusTotal(unittest.TestCase):
    def test_cache_init(self):
        tmpdir = tempfile.mkdtemp()
        client = VirusTotalClient(cache_db=os.path.join(tmpdir, "vt.db"))
        self.assertIsNotNone(client)


if __name__ == "__main__":
    unittest.main()
