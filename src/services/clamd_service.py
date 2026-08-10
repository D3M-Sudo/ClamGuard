#!/usr/bin/env python3
"""
ClamdService — Monitor stato clamd e controllo socket
"""

import logging
import os
import subprocess

logger = logging.getLogger("clamguard.clamd")


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
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def reload(self):
        try:
            subprocess.run(
                ["clamdscan", "--reload", "-c", self.socket_path],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return True
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error(f"clamd reload failed: {e}")
            return False
