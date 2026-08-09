#!/usr/bin/env python3
"""
ClamdService — Monitor stato clamd e controllo socket
"""

import os
import logging
import subprocess

logger = logging.getLogger("alpha.clamd")


class ClamdService:
    def __init__(self, socket_path="/run/clamav/clamd.ctl"):
        self.socket_path = socket_path

    def is_running(self):
        if not os.path.exists(self.socket_path):
            return False
        try:
            result = subprocess.run(
                ["clamdscan", "--ping", "1", "-c", self.socket_path],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def reload(self):
        try:
            subprocess.run(
                ["clamdscan", "--reload", "-c", self.socket_path],
                capture_output=True,
                timeout=10,
            )
            return True
        except Exception as e:
            logger.error(f"clamd reload failed: {e}")
            return False
