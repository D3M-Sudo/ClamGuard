#!/usr/bin/env python3
"""
ClamGuardWindow — Main window with Bitdefender-style dashboard
GTK4 / Libadwaita native implementation
"""

import asyncio
import base64
import logging
import os
import threading
from datetime import datetime, timezone

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

from .core.clamav import ClamAVScanner
from .core.history import HistoryManager
from .core.quarantine import QuarantineManager
from .core.third_party_db import ThirdPartyDBManager
from .services.clamd_service import ClamdService
from .services.polkit import PolkitHelper

logger = logging.getLogger("clamguard.window")


class ClamGuardWindow(Adw.ApplicationWindow):
    """Main application window with dashboard and view stack."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("ClamGuard")
        self.set_default_size(1100, 780)

        self._settings = Gio.Settings.new("io.github.d3msudo.clamguard")
        self._quarantine = QuarantineManager()
        # QA #3 (alto): lo switch "Encrypt quarantined files" (esposto sia
        # in Preferences sia nella card "Safe Files" della Dashboard,
        # entrambe collegate alla stessa chiave GSettings) non chiamava
        # mai QuarantineManager.set_encryption(), nonostante il codice
        # AES-256-GCM fosse già pronto e testato: il toggle non cifrava
        # nulla. "changed::" (non notify::active su un singolo widget)
        # copre entrambe le superfici UI con un solo punto di applicazione.
        self._settings.connect(
            "changed::quarantine-encrypt", self._apply_quarantine_encryption_setting
        )
        self._apply_quarantine_encryption_setting()
        self._history = HistoryManager()
        self._third_party = ThirdPartyDBManager()
        self._clamav = ClamAVScanner(
            extra_db_dirs=[self._third_party.sig_dir],
            prefer_clamd=self._settings.get_boolean("use-clamd"),
        )
        self._clamd = ClamdService()
        self._polkit = PolkitHelper()
        self._scan_in_progress = False
        self._active_tab = "dashboard"

        # Initialize Recommendations List
        self._recommendations = [
            {
                "title": "SYSTEM SCAN RECOMMENDATION",
                "desc": "Let's run a one-time scan of your entire device to make sure it's threat-free to begin with. All connected mounts will be scanned as well.",
                "action_label": "Scan",
                "action_callback": lambda: self.start_scan(["/"]),
            },
            {
                "title": "VIRUSTOTAL RECOMMENDATION",
                "desc": "Enable VirusTotal integration to check individual files against 70+ antivirus engines in the cloud.",
                "action_label": "Configure",
                "action_callback": lambda: self._on_settings_click(None),
            },
            {
                "title": "SIGNATURE DATABASE RECOMMENDATION",
                "desc": "Check for and download the latest virus signature databases from freshclam and third-party feeds.",
                "action_label": "Update",
                "action_callback": lambda: self._on_update_db(None),
            },
        ]
        self._current_rec_index = 0

        self._build_ui()
        self._load_state()
        self._start_status_monitor()

    def _build_ui(self):
        """Construct the main UI hierarchy."""
        # Root: Overlay for toasts
        self._overlay = Adw.ToastOverlay()
        self.set_content(self._overlay)

        # Main horizontal box split into Sidebar (left) and Content area (right)
        main_layout = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self._overlay.set_child(main_layout)

        # 1. Left column: SLEEK DARK SIDEBAR
        self.sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.sidebar.add_css_class("sidebar-dark")
        self.sidebar.set_size_request(240, -1)

        # Shield container at the top
        shield_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        shield_container.add_css_class("sidebar-shield-container")
        shield_container.set_halign(Gtk.Align.CENTER)
        shield_container.set_margin_top(28)
        shield_container.set_margin_bottom(20)

        self._sidebar_shield_image = Gtk.Image.new_from_icon_name(
            "security-high-symbolic"
        )
        self._sidebar_shield_image.set_pixel_size(96)
        self._sidebar_shield_image.add_css_class("sidebar-shield")
        shield_container.append(self._sidebar_shield_image)

        self._sidebar_shield_label = Gtk.Label(label="Protected")
        self._sidebar_shield_label.add_css_class("sidebar-shield-label")
        shield_container.append(self._sidebar_shield_label)

        self.sidebar.append(shield_container)

        # Sidebar navigation ListBox
        self._nav_list = Gtk.ListBox()
        self._nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._nav_list.add_css_class("sidebar-nav")
        self._nav_list.set_vexpand(True)
        self._nav_list.connect("row-selected", self._on_sidebar_row_selected)

        # Add Main Navigation Rows
        self._add_sidebar_row(
            self._nav_list, "dashboard", "Dashboard", "security-high-symbolic"
        )
        self._add_sidebar_row(
            self._nav_list, "protection", "Protection", "security-high-symbolic"
        )
        self._add_sidebar_row(
            self._nav_list, "privacy", "Privacy", "view-conceal-symbolic"
        )
        self._add_sidebar_row(
            self._nav_list,
            "notifications",
            "Notifications",
            "preferences-system-notifications-symbolic",
        )

        self.sidebar.append(self._nav_list)

        # Sidebar bottom ListBox
        self._bottom_nav_list = Gtk.ListBox()
        self._bottom_nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._bottom_nav_list.add_css_class("sidebar-nav")
        self._bottom_nav_list.set_margin_bottom(16)
        self._bottom_nav_list.connect("row-selected", self._on_sidebar_row_selected)

        # QA #8: "My Account" è stata rimossa. Era una voce della sidebar
        # visivamente identica alle pagine reali (Dashboard/Protection/
        # Privacy/Preferences), ma al click mostrava solo un toast
        # ("feature is coming soon!") senza cambiare la vista visibile —
        # un utente che ci clicca si aspetta una pagina, non un messaggio
        # fugace con la pagina precedente ancora in primo piano. Nessuna
        # funzionalità reale era ancora definita per questa voce: meglio
        # non promettere una destinazione che non esiste che reintrodurla
        # quando ci sarà un vero account da gestire.
        self._add_sidebar_row(
            self._bottom_nav_list,
            "settings",
            "Preferences",
            "preferences-system-symbolic",
        )
        self._add_sidebar_row(
            self._bottom_nav_list, "help", "Help", "help-about-symbolic"
        )

        self.sidebar.append(self._bottom_nav_list)
        main_layout.append(self.sidebar)

        # 2. Right column: LIGHT CONTENT CONTAINER
        content_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_container.add_css_class("content-area-light")
        content_container.set_hexpand(True)

        # Header bar with standard options
        header = self._build_header()
        content_container.append(header)

        # View stack with switcher
        self._view_stack = Adw.ViewStack()
        self._view_stack.set_hexpand(True)
        self._view_stack.set_vexpand(True)

        # Add reorganized views
        self._scanner_view = self._build_scanner_view()
        self._protection_view = self._build_protection_view()
        self._privacy_view = self._build_privacy_view()
        self._notifications_view = self._build_notifications_view()
        self._settings_view = self._build_settings_view()

        self._view_stack.add_named(self._scanner_view, "dashboard")
        self._view_stack.add_named(self._protection_view, "protection")
        self._view_stack.add_named(self._privacy_view, "privacy")
        self._view_stack.add_named(self._notifications_view, "notifications")
        self._view_stack.add_named(self._settings_view, "settings")

        content_container.append(self._view_stack)
        main_layout.append(content_container)

        # Initialize recommendation label values
        self._update_recommendation_ui()

        # Select Dashboard row initially
        GLib.idle_add(lambda: self._select_sidebar_row_by_id("dashboard"))

    def _add_sidebar_row(self, listbox, row_id, label, icon_name):
        row = Gtk.ListBoxRow()
        row.row_id = row_id
        row.add_css_class("sidebar-nav-row")

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(10)
        box.set_margin_bottom(10)

        img = Gtk.Image.new_from_icon_name(icon_name)
        img.set_pixel_size(18)
        img.add_css_class("sidebar-row-icon")

        lbl = Gtk.Label(label=label)
        lbl.add_css_class("sidebar-row-label")
        lbl.set_xalign(0)

        box.append(img)
        box.append(lbl)
        row.set_child(box)
        listbox.append(row)
        return row

    def _select_sidebar_row_by_id(self, row_id):
        """Helper to programmatically select sidebar row."""
        for listbox in [self._nav_list, self._bottom_nav_list]:
            child = listbox.get_first_child()
            while child:
                if getattr(child, "row_id", None) == row_id:
                    listbox.select_row(child)
                    return
                child = child.get_next_sibling()

    def _restore_sidebar_selection(self):
        """Restore previous selected tab for transient sidebar actions."""
        self._select_sidebar_row_by_id(self._active_tab)

    def _on_sidebar_row_selected(self, listbox, row):
        if not row:
            return

        # Clear selection of the other listbox to ensure only one item is active globally
        if listbox == self._nav_list:
            self._bottom_nav_list.select_row(None)
        else:
            self._nav_list.select_row(None)

        row_id = getattr(row, "row_id", None)
        if row_id in [
            "dashboard",
            "protection",
            "privacy",
            "notifications",
            "settings",
        ]:
            self._active_tab = row_id
            self._view_stack.set_visible_child_name(row_id)
        elif row_id == "help":
            self._on_help_clicked()
            GLib.idle_add(self._restore_sidebar_selection)

    def _on_help_clicked(self):
        app = self.get_application()
        if app:
            app.activate_action("about", None)

    def _build_header(self):
        """Build the header bar with transparent/integrated style."""
        header = Adw.HeaderBar()
        header.add_css_class("content-header")
        header.set_show_end_title_buttons(True)
        header.set_show_start_title_buttons(True)

        # Right: Menu button
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_tooltip_text("Main Menu")
        menu_button.update_property([Gtk.AccessibleProperty.LABEL], ["Main Menu"])
        menu = Gio.Menu()
        menu.append("Preferences", "app.preferences")
        menu.append("About ClamGuard", "app.about")
        menu.append("Quit", "app.quit")
        menu_button.set_menu_model(menu)
        header.pack_end(menu_button)

        # Center: Minimal status label
        self._status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._status_box.set_valign(Gtk.Align.CENTER)

        self._status_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
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

        # Big high-contrast Title & Subtitle (Bitdefender style)
        top_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        top_section.set_margin_start(6)
        top_section.set_margin_bottom(6)

        self._dashboard_main_title = Gtk.Label(label="You are safe")
        self._dashboard_main_title.add_css_class("dashboard-large-title")
        self._dashboard_main_title.set_xalign(0)

        self._dashboard_main_desc = Gtk.Label(
            label="We're looking out for your device and data."
        )
        self._dashboard_main_desc.add_css_class("dashboard-subtitle")
        self._dashboard_main_desc.set_xalign(0)

        top_section.append(self._dashboard_main_title)
        top_section.append(self._dashboard_main_desc)
        content.append(top_section)

        # Recommendations paginated banner
        self._dashboard_scan_buttons = {}
        rec_banner = self._build_recommendation_banner()
        content.append(rec_banner)

        # Quick and System scanning cards grid
        # QA #6: Gtk.Grid con set_column_homogeneous(True) forza OGNI
        # colonna alla larghezza della più larga tra le due — se una
        # card richiede più spazio del previsto, la finestra si apre più
        # larga del set_default_size(1100, 780) configurato, tagliando i
        # contenuti su schermi più piccoli (verificato: 1324px reali
        # invece di 1100px). Gtk.FlowBox supporta il wrap nativo: le card
        # vanno a capo (una sotto l'altra) quando lo spazio disponibile
        # non basta per affiancarle, invece di forzare la finestra ad
        # allargarsi oltre le dimensioni configurate.
        scan_grid = Gtk.FlowBox()
        scan_grid.set_selection_mode(Gtk.SelectionMode.NONE)
        scan_grid.set_homogeneous(True)
        scan_grid.set_column_spacing(12)
        scan_grid.set_row_spacing(12)
        scan_grid.set_max_children_per_line(2)
        scan_grid.set_min_children_per_line(1)

        quick_card = self._build_dashboard_scan_card(
            "Quick Scan", "Protection", "media-record-symbolic", self._on_quick_scan
        )
        system_card = self._build_dashboard_scan_card(
            "System Scan",
            "Protection",
            "drive-harddisk-symbolic",
            self._on_system_scan,
        )

        scan_grid.append(quick_card)
        scan_grid.append(system_card)
        content.append(scan_grid)

        # Bottom row grid (Stats, Safe Files, Web Protection) — stesso
        # ragionamento del blocco sopra: FlowBox invece di Grid omogeneo,
        # per permettere alle 3 card di andare a capo (2+1 o 1+1+1) su
        # finestre strette invece di forzare un overflow orizzontale.
        bottom_grid = Gtk.FlowBox()
        bottom_grid.set_selection_mode(Gtk.SelectionMode.NONE)
        bottom_grid.set_homogeneous(True)
        bottom_grid.set_column_spacing(12)
        bottom_grid.set_row_spacing(12)
        bottom_grid.set_max_children_per_line(3)
        bottom_grid.set_min_children_per_line(1)

        stats_card = self._build_stats_card()
        safe_files_card = self._build_safe_files_card()
        web_protection_card = self._build_web_protection_card()

        bottom_grid.append(stats_card)
        bottom_grid.append(safe_files_card)
        bottom_grid.append(web_protection_card)
        content.append(bottom_grid)

        # Recent activity / threats area
        activity_box = self._build_activity_box()
        content.append(activity_box)

        return scroll

    def _build_recommendation_banner(self):
        banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        banner.add_css_class("recommendation-banner")

        # Header Row: Title on left, pagination on right
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        header_row.add_css_class("recommendation-header")
        header_row.set_margin_start(16)
        header_row.set_margin_end(16)
        header_row.set_margin_top(12)
        header_row.set_margin_bottom(8)

        # Icon + Title
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        rec_icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
        self._rec_title_label = Gtk.Label(label="SYSTEM SCAN RECOMMENDATION")
        self._rec_title_label.add_css_class("recommendation-title")
        title_box.append(rec_icon)
        title_box.append(self._rec_title_label)
        header_row.append(title_box)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header_row.append(spacer)

        # Pagination controls
        pag_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        pag_box.set_valign(Gtk.Align.CENTER)

        prev_btn = Gtk.Button(icon_name="go-previous-symbolic")
        prev_btn.add_css_class("flat")
        prev_btn.connect("clicked", self._on_prev_recommendation)

        self._pag_label = Gtk.Label(label="1/3")
        self._pag_label.add_css_class("recommendation-pag-label")

        next_btn = Gtk.Button(icon_name="go-next-symbolic")
        next_btn.add_css_class("flat")
        next_btn.connect("clicked", self._on_next_recommendation)

        pag_box.append(prev_btn)
        pag_box.append(self._pag_label)
        pag_box.append(next_btn)
        header_row.append(pag_box)

        banner.append(header_row)

        # Separator line
        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        banner.append(sep)

        # Body Row: Text description on left, action buttons on right
        body_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        body_row.set_margin_start(16)
        body_row.set_margin_end(16)
        body_row.set_margin_top(16)
        body_row.set_margin_bottom(16)

        self._rec_desc_label = Gtk.Label(
            label="Let's run a one-time scan of your entire device to make sure it's threat-free to begin with."
        )
        self._rec_desc_label.set_wrap(True)
        self._rec_desc_label.set_xalign(0)
        self._rec_desc_label.set_hexpand(True)
        self._rec_desc_label.add_css_class("recommendation-desc")
        body_row.append(self._rec_desc_label)

        action_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        action_box.set_valign(Gtk.Align.CENTER)

        self._rec_action_btn = Gtk.Button(label="Scan")
        self._rec_action_btn.add_css_class("blue-button")
        self._rec_action_btn.connect("clicked", self._on_recommendation_action)
        action_box.append(self._rec_action_btn)

        not_now_btn = Gtk.Button(label="Not now")
        not_now_btn.add_css_class("flat")
        not_now_btn.add_css_class("not-now-button")
        not_now_btn.connect("clicked", self._on_not_now_clicked)
        action_box.append(not_now_btn)

        body_row.append(action_box)
        banner.append(body_row)

        return banner

    def _update_recommendation_ui(self):
        rec = self._recommendations[self._current_rec_index]
        self._rec_title_label.set_text(rec["title"])
        self._rec_desc_label.set_text(rec["desc"])
        self._rec_action_btn.set_label(rec["action_label"])
        self._pag_label.set_text(
            f"{self._current_rec_index + 1}/{len(self._recommendations)}"
        )

    def _on_prev_recommendation(self, btn):
        self._current_rec_index = (self._current_rec_index - 1) % len(
            self._recommendations
        )
        self._update_recommendation_ui()

    def _on_next_recommendation(self, btn):
        self._current_rec_index = (self._current_rec_index + 1) % len(
            self._recommendations
        )
        self._update_recommendation_ui()

    def _on_recommendation_action(self, btn):
        rec = self._recommendations[self._current_rec_index]
        rec["action_callback"]()

    def _on_not_now_clicked(self, btn):
        self._on_next_recommendation(None)

    def _build_dashboard_scan_card(self, title, subtitle, icon_name, callback):
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        card.add_css_class("scan-card")
        card.set_hexpand(True)
        card.set_margin_start(6)
        card.set_margin_end(6)

        # Icon box
        icon_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        icon_box.set_valign(Gtk.Align.CENTER)
        icon_box.add_css_class("scan-card-icon-box")
        img = Gtk.Image.new_from_icon_name(icon_name)
        img.set_pixel_size(48)
        img.add_css_class("scan-card-icon")
        icon_box.append(img)
        card.append(icon_box)

        # Details and outline Button
        details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        details_box.set_hexpand(True)
        details_box.set_valign(Gtk.Align.CENTER)

        t_lbl = Gtk.Label(label=title)
        t_lbl.add_css_class("scan-card-title")
        t_lbl.set_xalign(0)

        sub_lbl = Gtk.Label(label=subtitle)
        sub_lbl.add_css_class("scan-card-subtitle")
        sub_lbl.set_xalign(0)

        btn = Gtk.Button(label="Start Scan")
        btn.add_css_class("outline-button")
        btn.set_halign(Gtk.Align.START)
        btn.connect("clicked", callback)
        self._dashboard_scan_buttons[title] = btn

        details_box.append(t_lbl)
        details_box.append(sub_lbl)
        details_box.append(btn)

        card.append(details_box)
        return card

    def _build_stats_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("scan-card")
        card.set_hexpand(True)
        card.set_margin_start(6)
        card.set_margin_end(6)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        img = Gtk.Image.new_from_icon_name("security-high-symbolic")
        img.set_pixel_size(24)
        img.add_css_class("stats-card-icon")

        lbl = Gtk.Label(label="Scan Statistics")
        lbl.add_css_class("scan-card-title")

        header.append(img)
        header.append(lbl)
        card.append(header)

        # Dynamic stats labels
        self._stats_detail_label = Gtk.Label(label="0 threats · 0 files")
        self._stats_detail_label.add_css_class("scan-card-subtitle")
        self._stats_detail_label.set_xalign(0)
        card.append(self._stats_detail_label)

        btn = Gtk.Button(label="Scan Details")
        btn.add_css_class("outline-button")
        btn.set_halign(Gtk.Align.START)
        btn.connect(
            "clicked",
            lambda *_: (
                self._view_stack.set_visible_child_name("protection"),
                self._select_sidebar_row_by_id("protection"),
            ),
        )
        card.append(btn)

        return card

    def _build_safe_files_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("scan-card")
        card.set_hexpand(True)
        card.set_margin_start(6)
        card.set_margin_end(6)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        img = Gtk.Image.new_from_icon_name("folder-open-symbolic")
        img.set_pixel_size(24)
        img.add_css_class("safe-files-icon")

        lbl = Gtk.Label(label="Safe Files")
        lbl.add_css_class("scan-card-title")

        header.append(img)
        header.append(lbl)

        # Spacer & Switch
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header.append(spacer)

        sw = Gtk.Switch()
        sw.set_valign(Gtk.Align.CENTER)
        self._settings.bind(
            "quarantine-encrypt", sw, "active", Gio.SettingsBindFlags.DEFAULT
        )
        header.append(sw)

        card.append(header)

        desc = Gtk.Label(label="Encrypted protection for quarantined items.")
        desc.add_css_class("scan-card-subtitle")
        desc.set_xalign(0)
        card.append(desc)

        btn = Gtk.Button(label="Quarantined Files")
        btn.add_css_class("outline-button")
        btn.set_halign(Gtk.Align.START)
        btn.connect(
            "clicked",
            lambda *_: (
                self._view_stack.set_visible_child_name("privacy"),
                self._select_sidebar_row_by_id("privacy"),
            ),
        )
        card.append(btn)

        return card

    def _build_web_protection_card(self):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("scan-card")
        card.set_hexpand(True)
        card.set_margin_start(6)
        card.set_margin_end(6)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        img = Gtk.Image.new_from_icon_name("network-wired-symbolic")
        img.set_pixel_size(24)
        img.add_css_class("web-protection-icon")

        lbl = Gtk.Label(label="Web Protection")
        lbl.add_css_class("scan-card-title")

        header.append(img)
        header.append(lbl)
        card.append(header)

        # Browser active shields simulated indicators
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        for browser in ["Chrome", "Firefox", "Local"]:
            b_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            dot = Gtk.Label(label="●")
            dot.add_css_class("green-dot")
            b_lbl = Gtk.Label(label=browser)
            b_lbl.add_css_class("browser-label")
            b_box.append(dot)
            b_box.append(b_lbl)
            status_box.append(b_box)

        card.append(status_box)

        btn = Gtk.Button(label="Configure")
        btn.add_css_class("outline-button")
        btn.set_halign(Gtk.Align.START)
        btn.connect(
            "clicked",
            lambda *_: (
                self._view_stack.set_visible_child_name("settings"),
                self._select_sidebar_row_by_id("settings"),
            ),
        )
        card.append(btn)

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

    def _build_notifications_view(self):
        """QA #8: prima, "Notifications" nella sidebar era una voce che
        sembrava una pagina (stesso stile di Dashboard/Protection/Privacy)
        ma al click mostrava solo un toast fugace senza mai cambiare la
        vista visibile. Qui diventa una vera pagina nel view stack, con
        lo stesso schema (titolo + descrizione + lista) già usato dalle
        altre viste per coerenza visiva."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        scroll.set_child(box)

        title = Gtk.Label(label="Notifications")
        title.add_css_class("view-main-title")
        title.set_xalign(0)
        box.append(title)

        desc = Gtk.Label(
            label="Alerts about threats found, completed scans, and database updates."
        )
        desc.add_css_class("view-subtitle")
        desc.set_xalign(0)
        desc.set_wrap(True)
        box.append(desc)

        self._notifications_list = Gtk.ListBox()
        self._notifications_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._notifications_list.add_css_class("boxed-list")
        box.append(self._notifications_list)

        empty_row = Adw.ActionRow()
        empty_row.set_title("No new notifications")
        empty_row.set_subtitle("You're all caught up.")
        empty_row.set_icon_name("emblem-ok-symbolic")
        self._notifications_list.append(empty_row)

        return scroll

    def _build_protection_view(self):
        """Unified view containing Custom Scans, databases, and history list."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        scroll.set_child(box)

        title = Gtk.Label(label="Protection & Custom Scans")
        title.add_css_class("view-main-title")
        title.set_xalign(0)
        box.append(title)

        desc = Gtk.Label(
            label="Run direct custom scans, manage downloaded third-party signature databases, and review recent history."
        )
        desc.add_css_class("view-subtitle")
        desc.set_xalign(0)
        desc.set_wrap(True)
        box.append(desc)

        # Section 1: Custom Scan Action Card
        custom_scan_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        custom_scan_box.add_css_class("dashboard-card")
        custom_scan_box.set_margin_bottom(12)

        cs_details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        cs_details.set_hexpand(True)
        cs_title = Gtk.Label(label="Custom Scan")
        cs_title.add_css_class("scan-card-title")
        cs_title.set_xalign(0)
        cs_desc = Gtk.Label(
            label="Select specific files or folders to check for malware."
        )
        cs_desc.add_css_class("scan-card-subtitle")
        cs_desc.set_xalign(0)
        cs_details.append(cs_title)
        cs_details.append(cs_desc)
        custom_scan_box.append(cs_details)

        self._custom_scan_btn = Gtk.Button(label="Choose Location...")
        self._custom_scan_btn.add_css_class("blue-button")
        self._custom_scan_btn.set_valign(Gtk.Align.CENTER)
        self._custom_scan_btn.connect("clicked", self._on_custom_scan)
        custom_scan_box.append(self._custom_scan_btn)
        box.append(custom_scan_box)

        # Section 2: Databases
        db_title = Gtk.Label(label="Signature Databases")
        db_title.add_css_class("title-2")
        db_title.set_xalign(0)
        box.append(db_title)

        db_info = Gtk.Label(
            label="Downloaded signatures are used automatically by local scans. "
            "Installing them into the system database also makes them "
            "available to a running clamd daemon (requires admin rights)."
        )
        db_info.set_wrap(True)
        db_info.set_xalign(0)
        db_info.add_css_class("body")
        db_info.set_opacity(0.7)
        box.append(db_info)

        self._database_list = Gtk.ListBox()
        self._database_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._database_list.add_css_class("boxed-list")
        box.append(self._database_list)

        install_btn = Gtk.Button(label="Install into system database…")
        install_btn.add_css_class("suggested-action")
        install_btn.set_halign(Gtk.Align.START)
        install_btn.connect("clicked", self._on_install_signatures_clicked)
        box.append(install_btn)
        self._install_signatures_btn = install_btn

        # Section 3: History
        hist_title = Gtk.Label(label="Recent Scan History")
        hist_title.add_css_class("title-2")
        hist_title.set_xalign(0)
        box.append(hist_title)

        self._history_list = Gtk.ListBox()
        self._history_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._history_list.add_css_class("boxed-list")
        box.append(self._history_list)

        self._refresh_database_view()
        self._refresh_history_view()

        return scroll

    def _build_privacy_view(self):
        """Unified view containing Quarantine and VirusTotal lookup interfaces."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)
        scroll.set_child(box)

        title = Gtk.Label(label="Privacy & Threat Isolation")
        title.add_css_class("view-main-title")
        title.set_xalign(0)
        box.append(title)

        desc = Gtk.Label(
            label="Manage quarantined threats or analyze suspicious files with the power of VirusTotal."
        )
        desc.add_css_class("view-subtitle")
        desc.set_xalign(0)
        desc.set_wrap(True)
        box.append(desc)

        # Section 1: Quarantined Files
        q_title = Gtk.Label(label="Quarantined Files")
        q_title.add_css_class("title-2")
        q_title.set_xalign(0)
        box.append(q_title)

        self._quarantine_list = Gtk.ListBox()
        self._quarantine_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self._quarantine_list.add_css_class("boxed-list")
        box.append(self._quarantine_list)

        # Section 2: VirusTotal Integration
        vt_title = Gtk.Label(label="VirusTotal Integration")
        vt_title.add_css_class("title-2")
        vt_title.set_xalign(0)
        box.append(vt_title)

        vt_desc = Gtk.Label(
            label="Check a single file against 70+ antivirus engines via VirusTotal."
        )
        vt_desc.set_xalign(0)
        vt_desc.set_wrap(True)
        vt_desc.add_css_class("dashboard-card-desc")
        box.append(vt_desc)

        choose_btn = Gtk.Button(label="Choose File to Check")
        choose_btn.add_css_class("suggested-action")
        choose_btn.set_halign(Gtk.Align.START)
        choose_btn.connect("clicked", self._on_virustotal_choose_file)
        box.append(choose_btn)

        self._vt_status_group = Adw.PreferencesGroup()
        self._vt_status_rows = []
        box.append(self._vt_status_group)

        self._vt_result_group = Adw.PreferencesGroup()
        self._vt_result_rows = []
        self._vt_result_group.set_visible(False)
        box.append(self._vt_result_group)

        self._refresh_quarantine_view()
        self._refresh_virustotal_view()

        return scroll

    def _refresh_virustotal_view(self):
        """Display status for VirusTotal."""
        if not hasattr(self, "_vt_status_group") or not self._vt_status_group:
            return
        for row in self._vt_status_rows:
            self._vt_status_group.remove(row)
        self._vt_status_rows = []

        if not self._settings.get_boolean("virustotal-enabled"):
            info = Adw.ActionRow()
            info.set_title("VirusTotal integration is disabled")
            info.set_subtitle("Enable it from Settings to check files here.")
            info.set_icon_name("dialog-information-symbolic")
            self._vt_status_group.add(info)
            self._vt_status_rows.append(info)
            return

        from .core.virustotal import VirusTotalClient

        if not VirusTotalClient().api_key:
            info = Adw.ActionRow()
            info.set_title("No VirusTotal API key configured")
            info.set_subtitle("Add your API key from Settings to enable lookups.")
            info.set_icon_name("dialog-information-symbolic")
            self._vt_status_group.add(info)
            self._vt_status_rows.append(info)

    def _on_virustotal_choose_file(self, btn):
        dialog = Gtk.FileDialog()
        dialog.set_title("Select a file to check")
        dialog.open(self, None, self._on_virustotal_file_chosen)

    def _on_virustotal_file_chosen(self, dialog, result):
        try:
            f = dialog.open_finish(result)
            path = f.get_path()
        except (GLib.Error, ValueError) as e:
            logger.error(f"VirusTotal file dialog error: {e}")
            return
        if not path:
            return

        if not self._settings.get_boolean("virustotal-enabled"):
            self._show_toast(
                "Enable VirusTotal in Settings first", Adw.ToastPriority.HIGH
            )
            return

        self._show_toast(f"Checking {os.path.basename(path)} on VirusTotal...")
        thread = threading.Thread(
            target=self._run_virustotal_lookup, args=(path,), daemon=True
        )
        thread.start()

    def _run_virustotal_lookup(self, path):
        from .core.virustotal import VirusTotalClient

        client = VirusTotalClient()
        if not client.api_key:
            GLib.idle_add(self._on_virustotal_result, path, None, "no_key")
            return
        result = client.lookup_file(path)
        GLib.idle_add(self._on_virustotal_result, path, result, None)

    def _on_virustotal_result(self, path, result, error):
        filename = os.path.basename(path)

        for row in self._vt_result_rows:
            self._vt_result_group.remove(row)
        self._vt_result_rows = []

        if error == "no_key":
            self._show_toast(
                "No VirusTotal API key configured — add one in Settings",
                Adw.ToastPriority.HIGH,
            )
            return False

        if result is None:
            self._show_toast(
                f"VirusTotal check failed for {filename} — check logs",
                Adw.ToastPriority.HIGH,
            )
            return False

        self._vt_result_group.set_visible(True)
        self._vt_result_group.set_title(f"Results for {filename}")

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        harmless = result.get("harmless", 0)
        total = result.get("total", 0)

        summary = Adw.ActionRow()
        if malicious or suspicious:
            summary.set_title(
                f"{malicious + suspicious} / {total} engines flagged this file"
            )
            summary.set_icon_name("dialog-warning")
        else:
            summary.set_title(f"0 / {total} engines flagged this file")
            summary.set_icon_name("emblem-ok-symbolic")
        summary.set_subtitle(
            f"{harmless} clean · {malicious} malicious · {suspicious} suspicious"
        )
        self._vt_result_group.add(summary)
        self._vt_result_rows.append(summary)

        type_row = Adw.ActionRow()
        type_row.set_title("File type")
        type_row.set_subtitle(result.get("type", "unknown"))
        self._vt_result_group.add(type_row)
        self._vt_result_rows.append(type_row)

        names = result.get("names") or []
        if names:
            names_row = Adw.ActionRow()
            names_row.set_title("Known as")
            names_row.set_subtitle(", ".join(names[:5]))
            self._vt_result_group.add(names_row)
            self._vt_result_rows.append(names_row)

        self._show_toast(f"VirusTotal check complete for {filename}")
        return False

    def _refresh_quarantine_view(self):
        """Reload quarantined files list."""
        if not hasattr(self, "_quarantine_list") or not self._quarantine_list:
            return
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

            filename = os.path.basename(entry.original_path)

            restore_btn = Gtk.Button(icon_name="edit-undo-symbolic")
            restore_btn.set_tooltip_text(f"Restore {filename}")
            restore_btn.update_property(
                [Gtk.AccessibleProperty.LABEL], [f"Restore {filename}"]
            )
            restore_btn.set_valign(Gtk.Align.CENTER)
            restore_btn.connect("clicked", self._on_restore_clicked, entry.id)
            row.add_suffix(restore_btn)

            delete_btn = Gtk.Button(icon_name="user-trash-symbolic")
            delete_btn.set_tooltip_text(f"Delete {filename} permanently")
            delete_btn.update_property(
                [Gtk.AccessibleProperty.LABEL], [f"Delete {filename} permanently"]
            )
            delete_btn.set_valign(Gtk.Align.CENTER)
            delete_btn.connect("clicked", self._on_delete_clicked, entry.id)
            row.add_suffix(delete_btn)

            self._quarantine_list.append(row)

    def _on_restore_clicked(self, button, entry_id):
        button.set_sensitive(False)
        self._show_toast("Restoring file in background...")
        thread = threading.Thread(
            target=self._run_restore_thread, args=(button, entry_id), daemon=True
        )
        thread.start()

    def _run_restore_thread(self, button, entry_id):
        success = self._quarantine.restore(entry_id)
        GLib.idle_add(self._on_restore_done, button, success)

    def _on_restore_done(self, button, success):
        button.set_sensitive(True)
        self._show_toast(
            "File restored" if success else "Restore failed — check logs",
            Adw.ToastPriority.NORMAL if success else Adw.ToastPriority.HIGH,
        )
        self._refresh_quarantine_view()
        return False

    def _on_delete_clicked(self, button, entry_id):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Delete file permanently?",
            body="This action cannot be undone. The quarantined file will be permanently deleted.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_delete_confirm_response, entry_id)
        dialog.present()

    def _on_delete_confirm_response(self, dialog, response, entry_id):
        if response == "delete":
            success = self._quarantine.delete(entry_id)
            self._show_toast(
                "File deleted" if success else "Deletion failed",
                Adw.ToastPriority.NORMAL if success else Adw.ToastPriority.HIGH,
            )
            self._refresh_quarantine_view()

    def _refresh_history_view(self):
        """Reload scan history."""
        if not hasattr(self, "_history_list") or not self._history_list:
            return
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
            row.set_icon_name("document-open-recent-symbolic")
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

    def _refresh_database_view(self):
        """Reload signature database feeds."""
        if not hasattr(self, "_database_list") or not self._database_list:
            return
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

    def _build_settings_view(self):
        """Settings page connected to GSettings schema."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)

        page = Adw.PreferencesPage()
        scroll.set_child(page)

        scanning_group = Adw.PreferencesGroup()
        scanning_group.set_title("Scanning")

        use_clamd_row = Adw.SwitchRow()
        use_clamd_row.set_title("Use clamd daemon")
        use_clamd_row.set_subtitle(
            "Prefer the clamd background service over clamscan when available"
        )
        self._settings.bind(
            "use-clamd", use_clamd_row, "active", Gio.SettingsBindFlags.DEFAULT
        )
        use_clamd_row.connect("notify::active", self._on_use_clamd_changed)
        scanning_group.add(use_clamd_row)

        socket_row = Adw.EntryRow()
        socket_row.set_title("clamd socket path")
        self._settings.bind(
            "clamav-socket-path", socket_row, "text", Gio.SettingsBindFlags.DEFAULT
        )
        scanning_group.add(socket_row)

        auto_scan_row = Adw.SwitchRow()
        auto_scan_row.set_title("Auto-scan downloads")
        auto_scan_row.set_subtitle("Automatically scan files as they are downloaded")
        self._settings.bind(
            "auto-scan-downloads",
            auto_scan_row,
            "active",
            Gio.SettingsBindFlags.DEFAULT,
        )
        scanning_group.add(auto_scan_row)

        page.add(scanning_group)

        protection_group = Adw.PreferencesGroup()
        protection_group.set_title("Protection")

        encrypt_row = Adw.SwitchRow()
        encrypt_row.set_title("Encrypt quarantined files")
        encrypt_row.set_subtitle("Store isolated threats in an encrypted form")
        self._settings.bind(
            "quarantine-encrypt",
            encrypt_row,
            "active",
            Gio.SettingsBindFlags.DEFAULT,
        )
        protection_group.add(encrypt_row)

        third_party_row = Adw.SwitchRow()
        third_party_row.set_title("Third-party signature databases")
        third_party_row.set_subtitle(
            "Use community signature feeds (urlhaus, sanesecurity, …) in local scans"
        )
        self._settings.bind(
            "third-party-enabled",
            third_party_row,
            "active",
            Gio.SettingsBindFlags.DEFAULT,
        )
        protection_group.add(third_party_row)

        tray_row = Adw.SwitchRow()
        tray_row.set_title("Show system tray icon")
        self._settings.bind(
            "show-tray-icon", tray_row, "active", Gio.SettingsBindFlags.DEFAULT
        )
        protection_group.add(tray_row)

        page.add(protection_group)

        vt_group = Adw.PreferencesGroup()
        vt_group.set_title("VirusTotal")
        vt_group.set_description("Check individual files against 70+ antivirus engines")

        vt_enabled_row = Adw.SwitchRow()
        vt_enabled_row.set_title("Enable VirusTotal integration")
        self._settings.bind(
            "virustotal-enabled",
            vt_enabled_row,
            "active",
            Gio.SettingsBindFlags.DEFAULT,
        )
        vt_enabled_row.connect(
            "notify::active", lambda *_: self._refresh_virustotal_view()
        )
        vt_group.add(vt_enabled_row)

        self._vt_key_row = Adw.PasswordEntryRow()
        self._vt_key_row.set_title("API key")
        self._vt_key_row.set_tooltip_text("Leave blank to keep the currently saved key")
        vt_group.add(self._vt_key_row)

        save_key_btn = Gtk.Button(label="Save API key")
        save_key_btn.add_css_class("suggested-action")
        save_key_btn.set_margin_top(6)
        save_key_btn.set_halign(Gtk.Align.START)
        save_key_btn.connect("clicked", self._on_save_vt_key)
        vt_group.add(save_key_btn)

        page.add(vt_group)

        return scroll

    def _apply_quarantine_encryption_setting(self, *_args):
        enabled = self._settings.get_boolean("quarantine-encrypt")
        thread = threading.Thread(
            target=self._run_apply_quarantine_encryption,
            args=(enabled,),
            daemon=True,
        )
        thread.start()

    def _run_apply_quarantine_encryption(self, enabled):
        if not enabled:
            self._quarantine.set_encryption()
            return

        from .services.credentials import CredentialsService

        creds = CredentialsService()
        key_b64 = creds.get_quarantine_key()
        if key_b64:
            try:
                key_bytes = base64.b64decode(key_b64)
            except (ValueError, TypeError) as e:
                logger.error(f"Chiave quarantena salvata non valida: {e}")
                key_b64 = ""
        if not key_b64:
            # Prima attivazione: genera una chiave AES-256 casuale e la
            # persiste via libsecret, così sopravvive a riavvii dell'app
            # e resta utilizzabile per ripristinare file già in
            # quarantena. Nessuna password richiesta all'utente: lo
            # switch in UI è un semplice on/off, coerente con l'interfaccia
            # esistente.
            key_bytes = os.urandom(32)
            key_b64 = base64.b64encode(key_bytes).decode("ascii")
            if not creds.store_quarantine_key(key_b64):
                logger.error(
                    "Impossibile salvare la chiave di cifratura quarantena "
                    "(secret service non disponibile?) — cifratura non attivata"
                )
                GLib.idle_add(self._notify_quarantine_encryption_failed)
                return

        self._quarantine.set_encryption(key=key_bytes)

    def _notify_quarantine_encryption_failed(self):
        self._show_toast(
            "Couldn't enable quarantine encryption — no secret service "
            "available on this system",
            Adw.ToastPriority.HIGH,
        )
        return False

    def _on_use_clamd_changed(self, switch_row, _pspec):
        # QA #4: aggiorna la preferenza a runtime, così ha effetto sulla
        # prossima scansione senza richiedere un riavvio dell'app.
        self._clamav.prefer_clamd = switch_row.get_active()

    def _on_save_vt_key(self, btn):
        key = self._vt_key_row.get_text().strip()
        if not key:
            self._show_toast("Enter an API key first", Adw.ToastPriority.HIGH)
            return

        btn.set_sensitive(False)
        thread = threading.Thread(
            target=self._run_save_vt_key, args=(key, btn), daemon=True
        )
        thread.start()

    def _run_save_vt_key(self, key, btn):
        from .services.credentials import CredentialsService

        success = CredentialsService().store_vt_key(key)
        GLib.idle_add(self._on_save_vt_key_done, success, btn)

    def _on_save_vt_key_done(self, success, btn):
        btn.set_sensitive(True)
        self._vt_key_row.set_text("")
        self._show_toast(
            "VirusTotal API key saved" if success else "Failed to save API key",
            Adw.ToastPriority.NORMAL if success else Adw.ToastPriority.HIGH,
        )
        self._refresh_virustotal_view()
        return False

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

        self._polkit.run_elevated(
            "/usr/bin/clamguard-apply-signatures", args, _callback
        )

    def _on_install_signatures_done(self, success, output):
        if hasattr(self, "_install_signatures_btn") and self._install_signatures_btn:
            self._install_signatures_btn.set_sensitive(True)

        if success:
            self._show_toast("Signatures installed into the system database")
        else:
            logger.error(f"Installazione firme fallita: {output}")
            # QA #7: il messaggio precedente era hardcoded e suggeriva
            # SEMPRE la stessa causa ("helper may not be installed"),
            # anche quando la vera causa (già disponibile in "output" e
            # già loggata correttamente sulla riga sopra) era tutt'altra
            # — es. nessuna firma ancora scaricata. Mostriamo la ragione
            # reale, troncata per restare leggibile in un toast.
            reason = (output or "unknown error").strip()
            if len(reason) > 160:
                reason = reason[:157] + "…"
            self._show_toast(
                f"Installation failed: {reason}",
                Adw.ToastPriority.HIGH,
            )
        return False

    # --- Callbacks ---

    def _on_quick_scan(self, btn):
        self.start_scan([os.path.expanduser("~")])

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
        except (GLib.Error, ValueError) as e:
            logger.error(f"File dialog error: {e}")

    def _on_quarantine_click(self, btn):
        self._refresh_quarantine_view()
        self._view_stack.set_visible_child_name("privacy")
        self._select_sidebar_row_by_id("privacy")

    def _on_virustotal_click(self, btn):
        self._view_stack.set_visible_child_name("privacy")
        self._select_sidebar_row_by_id("privacy")

    def _on_update_db(self, btn):
        if btn:
            btn.set_sensitive(False)
        self._show_toast("Updating virus definitions...")
        thread = threading.Thread(
            target=self._run_update_db_thread, args=(btn,), daemon=True
        )
        thread.start()

    def _run_update_db_thread(self, btn):
        def _callback(success, output):
            GLib.idle_add(self._on_update_done, success, output, btn)

        self._polkit.run_elevated("/usr/bin/freshclam", [], _callback)

    def _on_update_done(self, success, output, btn):
        if btn:
            btn.set_sensitive(True)
        if success:
            self._show_toast("Virus definitions updated successfully")
            self._update_status()
        else:
            self._show_toast("Update failed. Check logs.", Adw.ToastPriority.HIGH)
        return False

    def _on_settings_click(self, btn):
        self._view_stack.set_visible_child_name("settings")
        self._select_sidebar_row_by_id("settings")

    # --- Public API ---

    def _set_scan_buttons_sensitive(self, sensitive):
        """Enable or disable scan buttons to prevent concurrent scans and provide visual feedback."""
        if hasattr(self, "_dashboard_scan_buttons"):
            for btn in self._dashboard_scan_buttons.values():
                btn.set_sensitive(sensitive)
                if not sensitive:
                    btn.set_label("Scanning...")
                else:
                    btn.set_label("Start Scan")

        if hasattr(self, "_custom_scan_btn") and self._custom_scan_btn:
            self._custom_scan_btn.set_sensitive(sensitive)
            if not sensitive:
                self._custom_scan_btn.set_label("Scanning...")
            else:
                self._custom_scan_btn.set_label("Choose Location...")

        if hasattr(self, "_rec_action_btn") and self._rec_action_btn:
            self._rec_action_btn.set_sensitive(sensitive)

    def start_scan(self, paths):
        """Initiate a scan on the given paths."""
        if not paths:
            return
        if self._scan_in_progress:
            self._show_toast("A scan is already in progress")
            return

        self._scan_in_progress = True
        self._set_scan_buttons_sensitive(False)
        self._show_toast(f"Scanning {len(paths)} location(s)...")
        scan_id = self._history.start_scan("manual", ", ".join(paths))

        thread = threading.Thread(
            target=self._run_scan_thread, args=(paths, scan_id), daemon=True
        )
        thread.start()

    def _run_scan_thread(self, paths, scan_id):
        try:
            results = asyncio.run(self._clamav.scan_paths(paths))
        except (OSError, ValueError) as e:
            logger.error(f"Scan failed: {e}")
            GLib.idle_add(self._on_scan_error, str(e))
            return
        GLib.idle_add(self._on_scan_complete, results, scan_id)

    def _on_scan_error(self, message):
        self._scan_in_progress = False
        self._set_scan_buttons_sensitive(True)
        self._show_toast(f"Scan failed: {message}", Adw.ToastPriority.HIGH)
        return False

    def _on_scan_complete(self, results, scan_id):
        self._scan_in_progress = False
        self._set_scan_buttons_sensitive(True)
        infected = [r for r in results if r.infected]
        # QA #2/#5: file troppo grandi o non leggibili non vengono mai
        # davvero ispezionati da clamscan, ma finora sparivano dai
        # risultati senza alcuna indicazione per l'utente. Li rendiamo
        # visibili nel messaggio di fine scansione invece di lasciare che
        # restino nascosti nel solo dettaglio tecnico dello storico.
        skipped = [r for r in results if r.skipped]

        for r in infected:
            r.compute_hash()
            self._history.add_threat(scan_id, r.path, r.virus_name, r.hash)

        self._history.finish_scan(
            scan_id, len(results), len(infected), [r.to_dict() for r in results]
        )
        self._refresh_history_view()
        self._refresh_dashboard_stats()

        skipped_suffix = ""
        if skipped:
            skipped_suffix = f" ({len(skipped)} skipped — too large or access denied)"

        if infected:
            self._show_toast(
                f"Scan complete: {len(infected)} threat(s) found in "
                f"{len(results)} file(s){skipped_suffix}",
                Adw.ToastPriority.HIGH,
            )
            self._prompt_quarantine(infected)
        else:
            self._show_toast(
                f"Scan complete: {len(results)} file(s), no threats found"
                f"{skipped_suffix}"
            )

        return False

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
            self._show_toast("Moving files to quarantine in background...")
            thread = threading.Thread(
                target=self._run_quarantine_thread, args=(infected,), daemon=True
            )
            thread.start()

    def _run_quarantine_thread(self, infected):
        count = sum(
            1
            for r in infected
            if self._quarantine.quarantine(r.path, virus_name=r.virus_name)
        )
        GLib.idle_add(self._on_quarantine_done, count)

    def _on_quarantine_done(self, count):
        self._show_toast(f"{count} file(s) quarantined")
        self._refresh_quarantine_view()
        return False

    def show_quarantine(self):
        self._refresh_quarantine_view()
        self._view_stack.set_visible_child_name("privacy")
        self._select_sidebar_row_by_id("privacy")
        self.present()

    def show_settings(self):
        self._view_stack.set_visible_child_name("settings")
        self._select_sidebar_row_by_id("settings")
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
        self._refresh_dashboard_stats()
        GLib.timeout_add_seconds(30, self._update_status)

    def _update_status(self):
        """Update protection status badge and dashboard."""
        thread = threading.Thread(target=self._run_update_status_thread, daemon=True)
        thread.start()
        return True

    def _run_update_status_thread(self):
        try:
            clamd_ok = self._clamd.is_running()
            db_age = self._clamav.get_database_age()
            GLib.idle_add(self._on_update_status_complete, clamd_ok, db_age)
        except (OSError, ValueError) as e:
            logger.error(f"Background status update error: {e}")

    def _on_update_status_complete(self, clamd_ok, db_age):
        try:
            protected = clamd_ok and db_age < 86400 * 3  # 3 days

            if protected:
                self._set_status(
                    "protected",
                    "Protected",
                    "security-high-symbolic",
                    "You are safe",
                    "We're looking out for your device and data.",
                )
            elif clamd_ok:
                self._set_status(
                    "warning",
                    "Outdated",
                    "view-refresh-symbolic",
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
            if db_age == float("inf"):
                update_text = "Updated: Never"
            elif db_age < 3600:
                update_text = "Updated: Just now"
            elif db_age < 86400:
                update_text = f"Updated: {int(db_age // 3600)}h ago"
            else:
                update_text = f"Updated: {int(db_age // 86400)}d ago"

            if hasattr(self, "_update_label") and self._update_label:
                self._update_label.set_text(update_text)

        except (OSError, ValueError) as e:
            logger.error(f"Status update complete error: {e}")
        return False

    def _refresh_dashboard_stats(self):
        """Update scan stats and dashboard elements."""
        try:
            stats = self._history.get_summary_stats()
        except (OSError, ValueError) as e:
            logger.error(f"Dashboard stats refresh error: {e}")
            return

        if hasattr(self, "_stats_detail_label") and self._stats_detail_label:
            self._stats_detail_label.set_text(
                f"{stats['total_threats_found']} threats · {stats['total_files_scanned']} files scanned"
            )

    @staticmethod
    def _format_relative_time(dt) -> str:
        """Format a datetime as relative string."""
        if dt is None:
            return "Never"
        age = datetime.now(timezone.utc).timestamp() - dt.timestamp()
        if age < 3600:
            return "Just now"
        if age < 86400:
            return f"{int(age // 3600)}h ago"
        return f"{int(age // 86400)}d ago"

    def _set_status(self, level, badge_text, icon_name, title, desc):
        """Update status widgets with given level."""
        # Update header badge
        for cls in [
            "status-badge-protected",
            "status-badge-warning",
            "status-badge-critical",
        ]:
            if hasattr(self, "_status_label") and self._status_label:
                self._status_label.remove_css_class(cls)

        css_class = f"status-badge-{level}"
        if hasattr(self, "_status_label") and self._status_label:
            self._status_label.add_css_class(css_class)
            self._status_label.set_text(badge_text)

        if hasattr(self, "_status_icon") and self._status_icon:
            self._status_icon.set_from_icon_name(icon_name)

        # Update sidebar shield
        if hasattr(self, "_sidebar_shield_image") and self._sidebar_shield_image:
            self._sidebar_shield_image.set_from_icon_name(icon_name)
            for cls in ["shield-protected", "shield-warning", "shield-critical"]:
                self._sidebar_shield_image.remove_css_class(cls)
                self._sidebar_shield_label.remove_css_class(cls)
            self._sidebar_shield_image.add_css_class(f"shield-{level}")
            self._sidebar_shield_label.add_css_class(f"shield-{level}")
            self._sidebar_shield_label.set_text(badge_text)

        # Update dashboard big title & subtitle
        if hasattr(self, "_dashboard_main_title") and self._dashboard_main_title:
            self._dashboard_main_title.set_text(title)
        if hasattr(self, "_dashboard_main_desc") and self._dashboard_main_desc:
            self._dashboard_main_desc.set_text(desc)

    def do_close_request(self):
        """Save window state before close."""
        size = self.get_default_size()
        self._settings.set_int("window-width", size.width)
        self._settings.set_int("window-height", size.height)
        self._settings.set_boolean("window-maximized", self.is_maximized())
        return False
