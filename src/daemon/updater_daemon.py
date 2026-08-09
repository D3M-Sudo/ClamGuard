#!/usr/bin/env python3
"""
UpdaterDaemon — Background daemon for third-party signature updates
"""
import logging
from ..core.third_party_db import ThirdPartyDBManager
from ..core.freshclam import FreshclamManager

logger = logging.getLogger("alpha.daemon.updater")


class UpdaterDaemon:
    def __init__(self):
        self.third_party = ThirdPartyDBManager()
        self.freshclam = FreshclamManager()

    def run(self):
        logger.info("Starting ClamGuard signature updater daemon")
        success, output = self.freshclam.update()
        logger.info(f"freshclam: success={success}")
        results = self.third_party.refresh()
        for name, result in results.items():
            logger.info(f"{name}: {result}")
        logger.info("Updater daemon finished")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    daemon = UpdaterDaemon()
    daemon.run()
