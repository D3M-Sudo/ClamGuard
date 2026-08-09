#!/usr/bin/env python3
"""
Notifier — Desktop notifications via Gio.Notification
"""
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gio


class Notifier:
    def __init__(self, app):
        self._app = app

    def send(self, title: str, body: str, icon: str = "security-high"):
        notification = Gio.Notification.new(title)
        notification.set_body(body)
        notification.set_icon(Gio.ThemedIcon.new(icon))
        notification.set_priority(Gio.NotificationPriority.NORMAL)
        self._app.send_notification("io.github.d3msudo.clamguard", notification)
