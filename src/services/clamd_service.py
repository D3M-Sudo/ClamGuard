#!/usr/bin/env python3
"""
ClamdService — Monitor stato clamd e controllo socket
"""

import logging
import os
import subprocess

from ..core import paths

logger = logging.getLogger("clamguard.clamd")


class ClamdService:
    def __init__(self, socket_path="/run/clamav/clamd.ctl"):
        self.socket_path = socket_path

    def _build_cmd(self, args: list[str]) -> list[str]:
        """Costruisce il comando clamdscan, gestendo il sandbox Flatpak.

        In Flatpak il socket di sistema non è visibile nel sandbox e
        clamdscan non è installato nel sandbox: va eseguito sull'host via
        flatpak-spawn --host.
        """
        if paths.is_flatpak_sandbox():
            return ["flatpak-spawn", "--host", "clamdscan"] + args
        return ["clamdscan"] + args

    def is_running(self):
        if not paths.is_flatpak_sandbox() and not os.path.exists(self.socket_path):
            return False
        try:
            result = subprocess.run(
                self._build_cmd(["--ping", "1", "-c", self.socket_path]),
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
                self._build_cmd(["--reload", "-c", self.socket_path]),
                capture_output=True,
                timeout=10,
                check=False,
            )
            return True
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error(f"clamd reload failed: {e}")
            return False