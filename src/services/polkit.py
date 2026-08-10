#!/usr/bin/env python3
"""
PolkitHelper — Elevation via pkexec for privileged operations
"""

import logging
import subprocess
from collections.abc import Callable

from ..core import paths

logger = logging.getLogger("clamguard.polkit")


class PolkitHelper:
    def run_elevated(
        self,
        command: str,
        args: list[str],
        callback: Callable[[bool, str], None] | None = None,
    ):
        if paths.is_flatpak_sandbox():
            # pkexec dentro il sandbox non raggiunge il polkit agent
            # dell'host: va eseguito sull'host via flatpak-spawn (richiede
            # --talk-name=org.freedesktop.Flatpak, già nel manifest).
            cmd = ["flatpak-spawn", "--host", "pkexec", command] + args
        else:
            cmd = ["pkexec", command] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=False
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if callback:
                callback(success, output)
            return success, output
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error(f"pkexec failed: {e}")
            if callback:
                callback(False, str(e))
            return False, str(e)
