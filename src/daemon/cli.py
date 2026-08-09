#!/usr/bin/env python3
"""
CLI per il binario clamguard-daemon.

Gli unit systemd (data/systemd/clamguard-updater.service e
clamguard-scheduled-scan.service) invocano:

    clamguard-daemon update-signatures
    clamguard-daemon scheduled-scan [TARGET]

Prima del fix strutturale questi non erano definiti da nessuna parte
(il binario clamguard-daemon stesso non veniva nemmeno generato dal
build) e gli unit systemd fallivano sempre con "command not found".

Espone anche `install-privileged-helper` (vedi cli/install_helper.py):
un'operazione root-only, deliberatamente separata dal binario GUI
(clamguard), così un `sudo clamguard-daemon install-privileged-helper`
non richiede GTK/Adw importabili né un display.
"""

import argparse
import logging
import sys

logger = logging.getLogger("clamguard.daemon.cli")


def _run_update_signatures(args) -> int:
    from .updater_daemon import UpdaterDaemon
    UpdaterDaemon().run()
    return 0


def _run_scheduled_scan(args) -> int:
    from .scheduler_daemon import SchedulerDaemon
    SchedulerDaemon().run(target=args.target)
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(
        prog="clamguard-daemon",
        description="Demone in background ClamGuard (aggiornamento firme / scansioni pianificate / setup privilegiato)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    p_update = subparsers.add_parser(
        "update-signatures",
        help="Aggiorna freshclam e le firme di terze parti, poi esce",
    )
    p_update.set_defaults(func=_run_update_signatures)

    p_scan = subparsers.add_parser(
        "scheduled-scan",
        help="Esegue una scansione pianificata, poi esce",
    )
    p_scan.add_argument(
        "target", nargs="?", default="/home",
        help="Percorso da scansionare (default: /home)",
    )
    p_scan.set_defaults(func=_run_scheduled_scan)

    from ..cli.install_helper import register as register_install_helper
    register_install_helper(subparsers)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
