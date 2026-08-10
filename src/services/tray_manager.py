#!/usr/bin/env python3
"""
tray_manager — Gestisce il subprocesso tray_service.py dal processo GTK4.

Sul modello di ClamUI (src/ui/tray_manager.py): spawna il subprocesso,
scrive comandi JSON su stdin, legge eventi JSON da stdout su un thread in
background, e marshalla ogni callback verso il main loop GTK4 via
GLib.idle_add (il main loop GTK non è thread-safe: nessuna chiamata a
widget/segnali va fatta direttamente dal thread reader).
"""

import json
import logging
import os
import subprocess
import sys
import threading
import time

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib

logger = logging.getLogger("clamguard.tray_manager")

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB — limite di sicurezza sui messaggi IPC
MAX_RESPAWNS = 3
RESPAWN_WINDOW_SEC = 60


class TrayManager:
    """Spawna e gestisce il subprocesso tray_service.py."""

    def __init__(self):
        self._process = None
        self._running = False
        self._ready = False
        self._state_lock = threading.Lock()
        self._respawn_times = []
        self._tray_down = False

        # Callback verso il processo principale (impostate da chi usa TrayManager)
        self.on_ready = None
        self.on_quick_scan = None
        self.on_update = None
        self.on_toggle_window = None
        self.on_quit = None

    def _get_service_path(self) -> str:
        """Risolve il percorso di tray_service.py, sia in albero sorgente
        (sviluppo) sia da pacchetto installato."""
        return os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "tray_service.py"
        )

    def start(self):
        if self._running:
            return
        try:
            self._process = subprocess.Popen(
                [sys.executable, self._get_service_path()],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # line-buffered
            )
        except (OSError, ValueError) as e:
            logger.error(f"Impossibile avviare il subprocesso tray: {e}")
            self._tray_down = True
            return

        with self._state_lock:
            self._running = True
            self._ready = False

        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        logger.info("Subprocesso tray avviato")

    def stop(self):
        with self._state_lock:
            self._running = False
        if self._process:
            try:
                self._send_command({"action": "quit"})
                self._process.wait(timeout=2)
            except (OSError, ValueError):
                try:
                    self._process.terminate()
                    self._process.wait(timeout=2)
                except (OSError, ValueError):
                    self._process.kill()
            self._process = None

    def _send_command(self, command: dict):
        if (
            not self._process
            or self._process.stdin is None
            or self._process.stdin.closed
        ):
            return
        try:
            self._process.stdin.write(json.dumps(command) + "\n")
            self._process.stdin.flush()
        except (OSError, ValueError) as e:
            logger.debug(f"Invio comando fallito: {e}")

    def update_status(self, status: str):
        self._send_command({"action": "update_status", "status": status})

    def update_window_visible(self, visible: bool):
        self._send_command({"action": "update_window_visible", "visible": visible})

    def _read_stdout(self):
        try:
            for line in self._process.stdout:
                if len(line) > MAX_MESSAGE_SIZE:
                    logger.error("Messaggio IPC dal tray troppo grande, scartato")
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    logger.error(f"JSON non valido dal tray: {line[:200]}")
                    continue
                if not isinstance(message, dict) or "event" not in message:
                    continue
                GLib.idle_add(self._handle_event, message)
        except (OSError, ValueError) as e:
            logger.error(f"Errore lettura stdout tray: {e}")
        finally:
            with self._state_lock:
                was_running = self._running
                self._running = False
            if was_running:
                GLib.idle_add(self._maybe_respawn)

    def _read_stderr(self):
        if not self._process or not self._process.stderr:
            return
        for line in self._process.stderr:
            line = line.rstrip()
            if line:
                logger.debug(f"[tray] {line}")

    def _maybe_respawn(self):
        now = time.time()
        self._respawn_times = [
            t for t in self._respawn_times if now - t < RESPAWN_WINDOW_SEC
        ]
        if len(self._respawn_times) >= MAX_RESPAWNS:
            logger.error(
                f"Tray crashato {MAX_RESPAWNS} volte in {RESPAWN_WINDOW_SEC}s: "
                "disabilitato per questa sessione"
            )
            self._tray_down = True
            return False
        self._respawn_times.append(now)
        logger.warning("Subprocesso tray terminato inaspettatamente, riavvio...")
        self.start()
        return False

    def _handle_event(self, message: dict):
        event = message.get("event")
        if event == "ready":
            with self._state_lock:
                self._ready = True
            if self.on_ready:
                self.on_ready()
        elif event == "menu_action":
            action = message.get("action")
            if action == "quick_scan" and self.on_quick_scan:
                self.on_quick_scan()
            elif action == "update" and self.on_update:
                self.on_update()
            elif action == "toggle_window" and self.on_toggle_window:
                self.on_toggle_window()
            elif action == "quit" and self.on_quit:
                self.on_quit()
        elif event == "error":
            logger.error(f"Errore dal tray: {message.get('message')}")
        return False

    def is_available(self) -> bool:
        return self._running and not self._tray_down
