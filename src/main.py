#!/usr/bin/env python3
"""
ClamGuard — Modern ClamAV Security Suite for Linux
Entry point: Gio.Application, CLI args, single-instance, system tray
"""

import logging
import signal
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Secret", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from .services.credentials import CredentialsService
from .services.notifier import Notifier
from .services.tray_manager import TrayManager
from .window import ClamGuardWindow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("clamguard")


class ClamGuardApplication(Adw.Application):
    """Main application class with single-instance enforcement."""

    def __init__(self, version: str = "0.1.0"):
        super().__init__(
            application_id="io.github.d3msudo.clamguard",
            flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE
            | Gio.ApplicationFlags.HANDLES_OPEN,
        )
        self._version = version
        self._window = None
        self._tray = None
        self._notifier = None
        self._credentials = None
        self._css_provider = None

        self.add_main_option(
            "scan",
            ord("s"),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.FILENAME_ARRAY,
            "Scan specified files or directories",
            None,
        )
        self.add_main_option(
            "quarantine",
            ord("q"),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Open quarantine view",
            None,
        )
        self.add_main_option(
            "version",
            ord("v"),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Show version",
            None,
        )
        self.add_main_option(
            "daemon",
            ord("d"),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Run background daemon (updater/scheduler)",
            None,
        )

        # Graceful shutdown on SIGINT/SIGTERM
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

    def _on_signal(self, signum, frame):
        logger.info(f"Received signal {signum}, quitting...")
        self.quit()

    def do_startup(self):
        Adw.Application.do_startup(self)
        self._setup_css()
        self._setup_actions()
        self._credentials = CredentialsService()
        self._notifier = Notifier(self)

    def _setup_css(self):
        """Load custom CSS for Bitdefender-style dashboard accents."""
        css = """
        .status-badge-protected {
            background: linear-gradient(135deg, @green_4, @green_5);
            color: white;
            border-radius: 9999px;
            padding: 8px 20px;
            font-weight: 800;
            font-size: 0.95rem;
        }
        .status-badge-warning {
            background: linear-gradient(135deg, @yellow_4, @yellow_5);
            color: black;
            border-radius: 9999px;
            padding: 8px 20px;
            font-weight: 800;
            font-size: 0.95rem;
        }
        .status-badge-critical {
            background: linear-gradient(135deg, @red_4, @red_5);
            color: white;
            border-radius: 9999px;
            padding: 8px 20px;
            font-weight: 800;
            font-size: 0.95rem;
        }
        .dashboard-card {
            background-color: @card_bg_color;
            border-radius: 18px;
            padding: 18px;
            margin: 6px;
        }
        .dashboard-card-title {
            font-weight: 700;
            font-size: 1.1rem;
        }
        .dashboard-card-desc {
            font-size: 0.85rem;
            opacity: 0.7;
        }
        .dashboard-icon {
            -gtk-icon-size: 32px;
        }
        .threat-row {
            background: alpha(@red_3, 0.08);
            border-radius: 12px;
            margin: 4px 0;
            padding: 10px;
        }
        """
        self._css_provider = Gtk.CssProvider()
        self._css_provider.load_from_string(css)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            self._css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def _setup_actions(self):
        actions = [
            ("quit", self._on_quit_action, None),
            ("preferences", self._on_preferences_action, None),
            ("about", self._on_about_action, None),
            ("scan-file", self._on_scan_file_action, GLib.VariantType.new("as")),
        ]
        for name, callback, param_type in actions:
            action = Gio.SimpleAction.new(name, param_type)
            action.connect("activate", callback)
            self.add_action(action)

        self.set_accels_for_action("app.quit", ["<Primary>q"])
        self.set_accels_for_action("app.preferences", ["<Primary>comma"])

    def do_activate(self):
        if not self._window:
            self._window = ClamGuardWindow(application=self)
            self._window.connect("close-request", self._on_window_close)
            self._setup_tray()
        self._window.present()

    def do_shutdown(self):
        if self._tray:
            self._tray.stop()
        Adw.Application.do_shutdown(self)

    def _setup_tray(self):
        settings = Gio.Settings.new("io.github.d3msudo.clamguard")
        if settings.get_boolean("show-tray-icon"):
            self._tray = TrayManager()
            self._tray.on_toggle_window = self._on_tray_toggle_window
            self._tray.on_quick_scan = self._on_tray_quick_scan
            self._tray.on_update = self._on_tray_update
            self._tray.on_quit = lambda: self.quit()
            self._tray.start()

    def _on_tray_toggle_window(self):
        if self._window.get_visible():
            self._window.set_visible(False)
            self._tray.update_window_visible(False)
        else:
            self._window.present()
            self._tray.update_window_visible(True)

    def _on_tray_quick_scan(self):
        self._window.present()
        self._window.start_scan([GLib.get_home_dir()])

    def _on_tray_update(self):
        self._window.present()
        self._window._on_update_db(None)

    def _on_window_close(self, window):
        """Minimize to tray instead of quitting."""
        if self._tray and self._tray.is_available():
            window.set_visible(False)
            self._tray.update_window_visible(False)
            return True  # Block default close
        return False  # Allow close

    def do_command_line(self, command_line):
        options = command_line.get_options_dict()
        options = options.end().unpack()

        if "version" in options:
            print(f"ClamGuard {self._version}")
            return 0

        if "daemon" in options:
            # Scorciatoia manuale (es. `clamguard --daemon` da terminale) per
            # forzare un aggiornamento firme senza aprire la GUI. Il
            # percorso primario per updater/scheduled-scan in background è
            # il binario dedicato clamguard-daemon (src/daemon/cli.py),
            # invocato dagli unit systemd in data/systemd/*.service.
            from .daemon.updater_daemon import UpdaterDaemon

            UpdaterDaemon().run()
            return 0

        if "scan" in options:
            paths = options["scan"]
            self.activate()
            if self._window:
                GLib.idle_add(self._window.start_scan, paths)
            return 0

        if "quarantine" in options:
            self.activate()
            if self._window:
                GLib.idle_add(self._window.show_quarantine)
            return 0

        self.activate()
        return 0

    def do_open(self, files, n_files, hint):
        """Handle file open / DnD / file manager integration."""
        paths = [f.get_path() for f in files if f.get_path()]
        if paths:
            self.activate()
            if self._window:
                GLib.idle_add(self._window.start_scan, paths)

    def _on_quit_action(self, action, param):
        self.quit()

    def _on_preferences_action(self, action, param):
        if self._window:
            self._window.show_settings()

    def _on_about_action(self, action, param):
        dialog = Adw.AboutWindow(
            transient_for=self._window,
            application_name="ClamGuard",
            application_icon="io.github.d3msudo.clamguard",
            developer_name="D3M-Sudo",
            version=self._version,
            developers=["D3M-Sudo"],
            copyright="© 2026 D3M-Sudo",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/D3M-Sudo/ClamGuard",
            issue_url="https://github.com/D3M-Sudo/ClamGuard/issues",
        )
        dialog.present()

    def _on_scan_file_action(self, action, param):
        paths = param.unpack()
        if self._window:
            self._window.start_scan(paths)

    def show_notification(self, title, body, icon="security-high"):
        if self._notifier:
            self._notifier.send(title, body, icon)

    @property
    def credentials(self):
        return self._credentials


def main(version: str = "0.1.0"):
    app = ClamGuardApplication(version=version)
    return app.run(sys.argv)


if __name__ == "__main__":
    main()
