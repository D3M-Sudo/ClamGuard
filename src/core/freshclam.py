#!/usr/bin/env python3
"""
FreshclamManager — Wrapper for official ClamAV definition updates
"""

import logging
import os
import subprocess

logger = logging.getLogger("alpha.freshclam")


class FreshclamManager:
    """Manages official ClamAV database updates via freshclam."""

    def __init__(self, config_path: str | None = None):
        self.config_path = config_path or "/etc/clamav/freshclam.conf"
        self._binary = self._find_binary()

    def _find_binary(self) -> str:
        for path in ["/usr/bin/freshclam", "/usr/local/bin/freshclam"]:
            if os.path.exists(path):
                return path
        return "freshclam"

    def update(self, foreground: bool = False) -> tuple[bool, str]:
        """Run freshclam update. Returns (success, output)."""
        cmd = [self._binary]
        if self.config_path and os.path.exists(self.config_path):
            cmd += ["--config-file", self.config_path]
        if foreground:
            cmd.append("--foreground")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            success = result.returncode == 0
            output = result.stdout + result.stderr
            if success:
                logger.info("freshclam updated successfully")
            else:
                logger.warning(f"freshclam failed: {output}")
            return success, output
        except subprocess.TimeoutExpired:
            logger.error("freshclam timed out")
            return False, "Update timed out after 10 minutes"
        except OSError as e:
            logger.error(f"freshclam error: {e}")
            return False, str(e)

    def get_status(self) -> dict:
        """Return freshclam configuration status."""
        status = {
            "binary": self._binary,
            "config_exists": os.path.exists(self.config_path),
            "config_path": self.config_path,
        }
        if status["config_exists"]:
            try:
                with open(self.config_path) as f:
                    for line in f:
                        if line.startswith("DatabaseMirror"):
                            status.setdefault("mirrors", []).append(line.split()[1])
                        elif line.startswith("Checks"):
                            status["checks_per_day"] = int(line.split()[1])
            except (OSError, ValueError) as e:
                logger.error(f"Error reading freshclam.conf: {e}")
        return status
