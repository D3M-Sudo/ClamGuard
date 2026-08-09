#!/usr/bin/env python3
"""
PolkitHelper — Elevation via pkexec for privileged operations
"""

import logging
import subprocess
from typing import List, Optional, Callable

from ..core import paths

logger = logging.getLogger("alpha.polkit")


class PolkitHelper:
    def run_elevated(
        self,
        command: str,
        args: List[str],
        callback: Optional[Callable[[bool, str], None]] = None,
    ):
        if paths.is_flatpak_sandbox():
            # pkexec dentro il sandbox non raggiunge il polkit agent
            # dell'host: va eseguito sull'host via flatpak-spawn (richiede
            # --talk-name=org.freedesktop.Flatpak, già nel manifest).
            cmd = ["flatpak-spawn", "--host", "pkexec", command] + args
        else:
            cmd = ["pkexec", command] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if callback:
                callback(success, output)
            return success, output
        except Exception as e:
            logger.error(f"pkexec failed: {e}")
            if callback:
                callback(False, str(e))
            return False, str(e)
