#!/usr/bin/env python3
"""
ClamGuardWindow — Main window with Bitdefender-style dashboard
GTK4 / Libadwaita native implementation
"""

import asyncio
import logging
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import GLib, Gio, Gtk, Adw

from .core.clamav import ClamAVScanner
from .core.quarantine import QuarantineManager
from .core.history import HistoryManager
from .core.third_party_db import ThirdPartyDBManager
from .services.clamd_service import ClamdService
from .services.polkit import PolkitHelper

logger = logging.getLogger("alpha.window")


class ClamGuardWindow(Adw.ApplicationWindow):
    """Main application window with dashboard and view stack."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("ClamGuard")
        self.set_default_size(1100, 780)

        self._settings = Gio.Settings.new("io.github.d3msudo.clamguard")
        self._quarantine = QuarantineManager()
        self._history = HistoryManager()
        self._third_party = ThirdPartyDBManager()
        self._clamav = ClamAVScanner(extra_db_dirs=[self._third_party.sig_dir])
        self._clamd = ClamdService()
        self._polkit = PolkitHelper()
        self._scan_in_progress = False

        self._build_ui()
        self._load_state()
        self._start_status_monitor()

    def _build_ui(self):
        """Construct the main UI hierarchy."""
        # Root: Overlay for toasts
        self._overlay = Adw.ToastOverlay()
        self.set_content(self._overlay)

        # Main box: header + content
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._overlay.set_child(main_box)

        # Header bar with status badge
        header = self._build_header()
        main_box.append(header)

        # View stack with switcher
        self._view_stack = Adw.ViewStack()
        self._view_stack.set_hexpand(True)
        self._view_stack.set_vexpand(True)

        # Add views
        self._scanner_view = self._build_scanner_view()
        self._quarantine_view = self._build_quarantine_view()
        self._history_view = self._build_history_view()
        self._virustotal_view = self._build_placeholder_view("VirusTotal", "globe")
        self._database_view = self._build_database_view()
        self._settings_view = self._build_placeholder_view(
            "Settings", "preferences-system"
        )

        self._view_stack.add_titled_with_icon(
            self._scanner_view, "scanner", "Dashboard", "security-high"
        )
        self._view_stack.add_titled_with_icon(
            self._quarantine_view, "quarantine", "Quarantine", "folder-quarantine"
        )
        self._view_stack.add_titled_with_icon(
            self._history_view, "history", "History", "document-open-recent"
        )
        self._view_stack.add_titled_with_icon(
            self._virustotal_view, "virustotal", "VirusTotal", "globe"
        )
        self._view_stack.add_titled_with_icon(
            self._database_view, "database", "Database", "database"
        )
        self._view_stack.add_titled_with_icon(
            self._settings_view, "settings", "Settings", "preferences-system"
        )

        # View switcher bar (bottom) + title (header)
        switcher_bar = Adw.ViewSwitcherBar()
        switcher_bar.set_stack(self._view_stack)
        switcher_bar.set_reveal(True)

        main_box.append(self._view_stack)
        main_box.append(switcher_bar)

    def _build_header(self):
        """Build the header bar with prominent protection status badge."""
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)
        header.set_show_start_title_buttons(True)

        # Left: Menu button
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu = Gio.Menu()
        menu.append("Preferences", "app.preferences")
        menu.append("About ClamGuard", "app.about")
        menu.append("Quit", "app.quit")
        menu_button.set_menu_model(menu)
        header.pack_end(menu_button)

        # Center/Right: Status badge (Bitdefender style)
        self._status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._status_box.set_valign(Gtk.Align.CENTER)

        self._status_icon = Gtk.Image.new_from_icon_name("security-high")
        self._status_icon.add_css_class("dashboard-icon")
        self._status_box.append(self._status_icon)

        self._status_label = Gtk.Label(label="Protected")
        self._status_label.add_css_class("status-badge-protected")
        self._status_box.append(self._status_label)

        # Last update label
        self._update_label = Gtk.Label(label="Updated: Today")
        self._update_label.add_css_class("dashboard-card-desc")
        self._status_box.append(self._update_label)

        header.set_title_widget(self._status_box)

        # Quick scan button in header
        quick_scan_btn = Gtk.Button(label="Quick Scan")
        quick_scan_btn.add_css_class("suggested-action")
        quick_scan_btn.connect("clicked", self._on_quick_scan)
        header.pack_start(quick_scan_btn)

        return header

    def _build_scanner_view(self):
        """Build the main dashboard / scanner view."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)
        scroll.set_child(content)

        # Protection status card (large, prominent)
        status_card = self._build_status_card()
        content.append(status_card)

        # Quick action cards grid
        actions_grid = self._build_actions_grid()
        content.append(actions_grid)

        # Recent activity / threats area
        activity_box = self._build_activity_box()
        content.append(activity_box)

        return scroll

    def _build_status_card(self):
        """Large status card showing protection overview."""
        card = Adw.Bin()
        card.add_css_class("dashboard-card")
        card.set_margin_bottom(12)

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        card.set_child(box)

        # Left: Big icon + status text
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        left.set_valign(Gtk.Align.CENTER)
        left.set_halign(Gtk.Align.START)
        left.set_hexpand(True)

        self._big_status_icon = Gtk.Image.new_from_icon_name("security-high")
        self._big_status_icon.set_pixel_size(64)
        left.append(self._big_status_icon)

        self._big_status_title = Gtk.Label(label="Your device is protected")
        self._big_status_title.add_css_class("title-1")
        left.append(self._big_status_title)

        self._big_status_desc = Gtk.Label(
            label="Real-time scanning is active and virus definitions are up to date."
        )
        self._big_status_desc.add_css_class("body")
        self._big_status_desc.set_wrap(True)
        self._big_status_desc.set_xalign(0)
        left.append(self._big_status_desc)

        box.append(left)

        # Right: Stats column
        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        right.set_valign(Gtk.Align.CENTER)
        right.set_halign(Gtk.Align.END)

        stats = [
            ("Threats blocked", "0", "dialog-error"),
            ("Files scanned", "0", "folder-open"),
            ("Last scan", "Never", "appointment-soon"),
        ]
        for label, value, icon in stats:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_halign(Gtk.Align.END)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(16)
            row.append(ic)
            lbl = Gtk.Label(label=f"{label}: {value}")
            lbl.add_css_class("dashboard-card-desc")
            row.append(lbl)
            right.append(row)

        self._stats_rows = right
        box.append(right)

        return card

    def _build_actions_grid(self):
        """Grid of quick action cards (Bitdefender-style)."""
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(12)
        grid.set_column_homogeneous(True)

        actions = [
            (
                "System Scan",
                "Deep scan of your entire system",
                "drive-harddisk",
                self._on_system_scan,
            ),
            (
                "Custom Scan",
                "Scan specific files or folders",
                "folder-open",
                self._on_custom_scan,
            ),
            (
                "Quarantine",
                "Manage isolated threats",
                "folder-quarantine",
                self._on_quarantine_click,
            ),
            (
                "VirusTotal",
                "Check files with 70+ engines",
                "globe",
                self._on_virustotal_click,
            ),
            (
                "Update DB",
                "Update virus definitions",
                "software-update-available",
                self._on_update_db,
            ),
            (
                "Settings",
                "Configure protection options",
                "preferences-system",
                self._on_settings_click,
            ),
        ]

        for i, (title, desc, icon, callback) in enumerate(actions):
            card = self._build_action_card(title, desc, icon, callback)
            grid.attach(card, i % 3, i // 3, 1, 1)

        return grid

    def _build_action_card(self, title, description, icon_name, callback):
        """Single action card with icon, title, description."""
        card = Gtk.Button()
        card.add_css_class("dashboard-card")
        card.set_hexpand(True)
        card.connect("clicked", callback)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        card.set_child(box)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(32)
        icon.add_css_class("dashboard-icon")
        box.append(icon)

        lbl_title = Gtk.Label(label=title)
        lbl_title.add_css_class("dashboard-card-title")
        box.append(lbl_title)

        lbl_desc = Gtk.Label(label=description)
        lbl_desc.add_css_class("dashboard-card-desc")
        lbl_desc.set_wrap(True)
        lbl_desc.set_xalign(0)
        box.append(lbl_desc)

        return card

    def _build_activity_box(self):
        """Recent threats / scan activity list."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_top(12)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        title = Gtk.Label(label="Recent Activity")
        title.add_css_class("title-2")
        header.append(title)
        box.append(header)

        self._activity_list = Gtk.ListBox()
        self._activity_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._activity_list.add_css_class("boxed-list")
        box.append(self._activity_list)

        # Placeholder row
        placeholder = Adw.ActionRow()
        placeholder.set_title("No recent threats detected")
        placeholder.set_subtitle(
            "Your system is clean. Run a scan to check for threats."
        )
        placeholder.set_icon_name("emblem-ok-symbolic")
        self._activity_list.append(placeholder)

        return box

    def _build_placeholder_view(self, title, icon_name):
        """Placeholder view for unimplemented pages."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(64)
        icon.set_opacity(0.5)
        box.append(icon)

        lbl = Gtk.Label(label=title)
        lbl.add_css_class("title-2")
        box.append(lbl)

        sub = Gtk.Label(label="View implementation pending")
        sub.add_css_class("body")
        sub.set_opacity(0.6)
        box.append(sub)

        return box

    def _build_quarantine_view(self):
        """View reale della quarantena, collegata a QuarantineManager."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        title = Gtk.Label(label="Quarantined Files")
        title.add_css_class("title-2")
        title.set_xalign(0)
        box.append(title)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self._quarantine_list = Gtk.ListBox()
        self._quarantine_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._quarantine_list.add_css_class("boxed-list")
        scroll.set_child(self._quarantine_list)
        box.append(scroll)

        self._refresh_quarantine_view()
        return box

    def _refresh_quarantine_view(self):
        """Ricarica la lista quarantena dal database reale."""
        child = self._quarantine_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._quarantine_list.remove(child)
            child = nxt

        entries = self._quarantine.list_entries()
        if not entries:
            row = Adw.ActionRow()
            row.set_title("No quarantined files")
            row.set_subtitle("Threats found during a scan will appear here.")
            row.set_icon_name("emblem-ok-symbolic")
            self._quarantine_list.append(row)
            return

        for entry in entries:
            row = Adw.ActionRow()
            row.set_title(GLib.markup_escape_text(entry.original_path))
            row.set_subtitle(entry.virus_name or "Unknown threat")
            row.add_css_class("threat-row")
            row.set_icon_name("dialog-warning")

            restore_btn = Gtk.Button(icon_name="edit-undo-symbolic")
            restore_btn.set_tooltip_text("Restore")
            restore_btn.set_valign(Gtk.Align.CENTER)
            restore_btn.connect("clicked", self._on_restore_clicked, entry.id)
            row.add_suffix(restore_btn)

            delete_btn = Gtk.Button(icon_name="user-trash-symbolic")
            delete_btn.set_tooltip_text("Delete permanently")
            delete_btn.set_valign(Gtk.Align.CENTER)
            delete_btn.connect("clicked", self._on_delete_clicked, entry.id)
            row.add_suffix(delete_btn)

            self._quarantine_list.append(row)

    def _on_restore_clicked(self, button, entry_id):
        success = self._quarantine.restore(entry_id)
        self._show_toast(
            "File restored" if success else "Restore failed — check logs",
            Adw.ToastPriority.NORMAL if success else Adw.ToastPriority.HIGH,
        )
        self._refresh_quarantine_view()

    def _on_delete_clicked(self, button, entry_id):
        success = self._quarantine.delete(entry_id)
        self._show_toast(
            "File deleted" if success else "Deletion failed",
            Adw.ToastPriority.NORMAL if success else Adw.ToastPriority.HIGH,
        )
        self._refresh_quarantine_view()

    def _build_history_view(self):
        """View reale dello storico scansioni, collegata a HistoryManager."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        title = Gtk.Label(label="Scan History")
        title.add_css_class("title-2")
        title.set_xalign(0)
        box.append(title)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self._history_list = Gtk.ListBox()
        self._history_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._history_list.add_css_class("boxed-list")
        scroll.set_child(self._history_list)
        box.append(scroll)

        self._refresh_history_view()
        return box

    def _refresh_history_view(self):
        """Ricarica lo storico scansioni dal database reale."""
        child = self._history_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._history_list.remove(child)
            child = nxt

        records = self._history.get_recent_scans(limit=50)
        if not records:
            row = Adw.ActionRow()
            row.set_title("No scans yet")
            row.set_subtitle("Run a scan to see it here.")
            row.set_icon_name("document-open-recent")
            self._history_list.append(row)
            return

        for record in records:
            row = Adw.ActionRow()
            row.set_title(f"{record.scan_type.capitalize()} scan — {record.target}")
            if record.end_time:
                status = f"{record.files_scanned} files, {record.threats_found} threats"
            else:
                status = "In progress…"
            row.set_subtitle(
                f"{record.start_time.strftime('%Y-%m-%d %H:%M')} · {status}"
            )
            row.set_icon_name(
                "dialog-warning" if record.threats_found else "emblem-ok-symbolic"
            )
            self._history_list.append(row)

    def _build_database_view(self):
        """View reale dello stato firme di terze parti, con installazione
        privilegiata in /var/lib/clamav via helper pkexec."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        title = Gtk.Label(label="Third-Party Signature Databases")
        title.add_css_class("title-2")
        title.set_xalign(0)
        box.append(title)

        info = Gtk.Label(
            label="Downloaded signatures are used automatically by local scans. "
            "Installing them into the system database also makes them "
            "available to a running clamd daemon (requires admin rights)."
        )
        info.set_wrap(True)
        info.set_xalign(0)
        info.add_css_class("body")
        info.set_opacity(0.7)
        box.append(info)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        self._database_list = Gtk.ListBox()
        self._database_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._database_list.add_css_class("boxed-list")
        scroll.set_child(self._database_list)
        box.append(scroll)

        install_btn = Gtk.Button(label="Install into system database…")
        install_btn.add_css_class("suggested-action")
        install_btn.set_halign(Gtk.Align.START)
        install_btn.connect("clicked", self._on_install_signatures_clicked)
        box.append(install_btn)
        self._install_signatures_btn = install_btn

        self._refresh_database_view()
        return box

    def _refresh_database_view(self):
        child = self._database_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._database_list.remove(child)
            child = nxt

        providers = self._third_party.get_provider_status()
        if not providers:
            row = Adw.ActionRow()
            row.set_title("No third-party signatures downloaded yet")
            row.set_subtitle("Use “Update DB” to fetch them.")
            self._database_list.append(row)
            return

        for p in providers:
            row = Adw.ActionRow()
            row.set_title(p["name"])
            last = p["last_download"] or "never"
            row.set_subtitle(f"{p['filename']} · last updated: {last}")
            row.set_icon_name(
                "emblem-ok-symbolic" if p["enabled"] else "dialog-warning"
            )
            self._database_list.append(row)

    def _on_install_signatures_clicked(self, button):
        button.set_sensitive(False)
        self._show_toast("Preparing signatures for system install…")
        thread = threading.Thread(
            target=self._run_install_signatures_thread, daemon=True
        )
        thread.start()

    def _run_install_signatures_thread(self):
        try:
            args = self._third_party.build_privileged_install_args()
        except ValueError as e:
            GLib.idle_add(self._on_install_signatures_done, False, str(e))
            return

        def _callback(success, output):
            GLib.idle_add(self._on_install_signatures_done, success, output)

        # PolkitHelper instrada automaticamente via flatpak-spawn --host se
        # dentro un sandbox Flatpak (vedi services/polkit.py).
        self._polkit.run_elevated(
            "/usr/bin/clamguard-apply-signatures", args, _callback
        )

    def _on_install_signatures_done(self, success, output):
        self._install_signatures_btn.set_sensitive(True)

        if success:
            self._show_toast("Signatures installed into the system database")
        else:
            logger.error(f"Installazione firme fallita: {output}")
            self._show_toast(
                "Installation failed — see logs (helper may not be installed: "
                "run `sudo clamguard-daemon install-privileged-helper`)",
                Adw.ToastPriority.HIGH,
            )
        return False  # non ripetere (GLib.idle_add one-shot)

    # --- Callbacks ---

    def _on_quick_scan(self, btn):
        self.start_scan(["/home"])

    def _on_system_scan(self, btn):
        self.start_scan(["/"])

    def _on_custom_scan(self, btn):
        dialog = Gtk.FileDialog()
        dialog.set_title("Select files or folders to scan")
        dialog.select_multiple_folders(self, None, self._on_custom_scan_result)

    def _on_custom_scan_result(self, dialog, result):
        try:
            files = dialog.select_multiple_folders_finish(result)
            paths = [f.get_path() for f in files]
            if paths:
                self.start_scan(paths)
        except Exception as e:
            logger.error(f"File dialog error: {e}")

    def _on_quarantine_click(self, btn):
        self._refresh_quarantine_view()
        self._view_stack.set_visible_child_name("quarantine")

    def _on_virustotal_click(self, btn):
        self._view_stack.set_visible_child_name("virustotal")

    def _on_update_db(self, btn):
        self._show_toast("Updating virus definitions...")
        # Trigger via polkit if needed
        self._polkit.run_elevated("/usr/bin/freshclam", [], self._on_update_done)

    def _on_update_done(self, success, output):
        if success:
            self._show_toast("Virus definitions updated successfully")
            self._update_status()
        else:
            self._show_toast("Update failed. Check logs.", Adw.ToastPriority.HIGH)

    def _on_settings_click(self, btn):
        self._view_stack.set_visible_child_name("settings")

    # --- Public API ---

    def start_scan(self, paths):
        """Initiate a scan on the given paths (esegue realmente ClamAVScanner)."""
        if not paths:
            return
        if self._scan_in_progress:
            self._show_toast("A scan is already in progress")
            return

        self._scan_in_progress = True
        self._show_toast(f"Scanning {len(paths)} location(s)...")
        scan_id = self._history.start_scan("manual", ", ".join(paths))

        # clamscan/clamd sono operazioni I/O-bound potenzialmente lunghe:
        # vanno eseguite fuori dal thread del main loop GTK, altrimenti la
        # UI si blocca per l'intera durata della scansione. asyncio.run()
        # gira in un thread dedicato; i risultati tornano al main loop via
        # GLib.idle_add, l'unico modo sicuro di toccare i widget GTK da
        # un altro thread.
        thread = threading.Thread(
            target=self._run_scan_thread, args=(paths, scan_id), daemon=True
        )
        thread.start()

    def _run_scan_thread(self, paths, scan_id):
        try:
            results = asyncio.run(self._clamav.scan_paths(paths))
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            GLib.idle_add(self._on_scan_error, str(e))
            return
        GLib.idle_add(self._on_scan_complete, results, scan_id)

    def _on_scan_error(self, message):
        self._scan_in_progress = False
        self._show_toast(f"Scan failed: {message}", Adw.ToastPriority.HIGH)
        return False  # non ripetere (GLib.idle_add one-shot)

    def _on_scan_complete(self, results, scan_id):
        self._scan_in_progress = False
        infected = [r for r in results if r.infected]

        for r in infected:
            r.compute_hash()
            self._history.add_threat(scan_id, r.path, r.virus_name, r.hash)

        self._history.finish_scan(
            scan_id, len(results), len(infected), [r.to_dict() for r in results]
        )
        self._refresh_history_view()

        if infected:
            self._show_toast(
                f"Scan complete: {len(infected)} threat(s) found in {len(results)} file(s)",
                Adw.ToastPriority.HIGH,
            )
            self._prompt_quarantine(infected)
        else:
            self._show_toast(f"Scan complete: {len(results)} file(s), no threats found")

        return False  # non ripetere (GLib.idle_add one-shot)

    def _prompt_quarantine(self, infected):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Threats detected",
            body=f"{len(infected)} infected file(s) were found. Move them to quarantine now?",
        )
        dialog.add_response("later", "Later")
        dialog.add_response("quarantine", "Quarantine now")
        dialog.set_response_appearance("quarantine", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self._on_quarantine_prompt_response, infected)
        dialog.present()

    def _on_quarantine_prompt_response(self, dialog, response, infected):
        if response == "quarantine":
            count = sum(
                1
                for r in infected
                if self._quarantine.quarantine(r.path, virus_name=r.virus_name)
            )
            self._show_toast(f"{count} file(s) quarantined")
            self._refresh_quarantine_view()

    def show_quarantine(self):
        self._refresh_quarantine_view()
        self._view_stack.set_visible_child_name("quarantine")
        self.present()

    def show_settings(self):
        self._view_stack.set_visible_child_name("settings")
        self.present()

    def _show_toast(self, message, priority=Adw.ToastPriority.NORMAL):
        toast = Adw.Toast.new(message)
        toast.set_priority(priority)
        self._overlay.add_toast(toast)

    # --- State & Monitoring ---

    def _load_state(self):
        width = self._settings.get_int("window-width")
        height = self._settings.get_int("window-height")
        maximized = self._settings.get_boolean("window-maximized")
        self.set_default_size(width, height)
        if maximized:
            self.maximize()

    def _start_status_monitor(self):
        self._update_status()
        GLib.timeout_add_seconds(30, self._update_status)

    def _update_status(self):
        """Update protection status badge and dashboard."""
        try:
            clamd_ok = self._clamd.is_running()
            db_age = self._clamav.get_database_age()
            protected = clamd_ok and db_age < 86400 * 3  # 3 days

            if protected:
                self._set_status(
                    "protected",
                    "Protected",
                    "security-high",
                    "Your device is protected",
                    "Real-time scanning is active and virus definitions are up to date.",
                )
            elif clamd_ok:
                self._set_status(
                    "warning",
                    "Outdated",
                    "software-update-available",
                    "Definitions are outdated",
                    "Your virus definitions are older than 3 days. Please update.",
                )
            else:
                self._set_status(
                    "critical",
                    "At Risk",
                    "dialog-warning",
                    "Your device is at risk",
                    "ClamAV daemon is not running. Real-time protection is disabled.",
                )

            # Update last update label
            if db_age < 3600:
                update_text = "Updated: Just now"
            elif db_age < 86400:
                update_text = f"Updated: {int(db_age // 3600)}h ago"
            else:
                update_text = f"Updated: {int(db_age // 86400)}d ago"
            self._update_label.set_text(update_text)

        except Exception as e:
            logger.error(f"Status update error: {e}")

        return True  # Continue timeout

    def _set_status(self, level, badge_text, icon_name, title, desc):
        """Update status widgets with given level."""
        # Remove old classes
        for cls in [
            "status-badge-protected",
            "status-badge-warning",
            "status-badge-critical",
        ]:
            self._status_label.remove_css_class(cls)
            self._big_status_title.remove_css_class(cls)

        # Add new class
        css_class = f"status-badge-{level}"
        self._status_label.add_css_class(css_class)
        self._status_label.set_text(badge_text)
        self._status_icon.set_from_icon_name(icon_name)

        self._big_status_icon.set_from_icon_name(icon_name)
        self._big_status_title.set_text(title)
        self._big_status_desc.set_text(desc)

    def do_close_request(self):
        """Save window state before close."""
        size = self.get_default_size()
        self._settings.set_int("window-width", size.width)
        self._settings.set_int("window-height", size.height)
        self._settings.set_boolean("window-maximized", self.is_maximized())
        return False
