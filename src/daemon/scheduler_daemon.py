#!/usr/bin/env python3
"""
SchedulerDaemon — Gestore scansioni pianificate via systemd timer
"""

import logging

from ..core.clamav import ClamAVScanner
from ..core.history import HistoryManager

logger = logging.getLogger("alpha.daemon.scheduler")


class SchedulerDaemon:
    def __init__(self):
        self.scanner = ClamAVScanner()
        self.history = HistoryManager()

    def run(self, target="/home"):
        logger.info(f"Starting scheduled scan of {target}")
        scan_id = self.history.start_scan("scheduled", target)
        import asyncio

        try:
            results = asyncio.run(self.scanner.scan_paths([target]))
            threats = sum(1 for r in results if r.infected)
            self.history.finish_scan(
                scan_id, len(results), threats, [r.to_dict() for r in results]
            )
            logger.info(f"Scheduled scan complete: {threats} threats found")
        except (OSError, ValueError) as e:
            logger.error(f"Scheduled scan failed: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    daemon = SchedulerDaemon()
    daemon.run()
