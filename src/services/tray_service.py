#!/usr/bin/env python3
"""
tray_service — Subprocesso StatusNotifierItem per il tray icon.

Sostituisce il precedente approccio (XApp.StatusIcon / AppIndicator3 nel
processo GTK4 principale), che non poteva avere un menu contestuale nativo:
entrambe quelle API richiedono un GtkMenu della ABI GTK3, incompatibile
con un processo che carica GTK4.

Pattern adottato, sul modello di ClamUI
(https://github.com/linx-systems/clamui, vedi
docs/architecture/tray-subprocess.md e src/ui/tray_service.py in quel
repo): il tray gira in un **subprocesso separato** che implementa il
protocollo StatusNotifierItem (SNI) direttamente via GIO D-Bus — nessuna
dipendenza GTK — e il menu contestuale via DBusMenu (libdbusmenu-glib).
Comunica col processo principale GTK4 tramite JSON su stdin/stdout.

Vantaggi rispetto a XApp/AppIndicator3 nello stesso processo:
- nessun conflitto di toolkit (GIO D-Bus è agnostico rispetto a
  GTK3/GTK4)
- isolamento: se il tray crolla, l'app principale resta viva
- menu contestuale nativo vero (via DBusMenu), non un compromesso

Protocollo IPC (stesso formato di ClamUI):
    stdin  (comandi):  {"action": "update_status", "status": "scanning"}
    stdout (eventi):   {"event": "menu_action", "action": "quick_scan"}

Uso: eseguito come processo figlio da tray_manager.py, non pensato per
essere lanciato direttamente dall'utente.
"""

import json
import logging
import sys
import threading

logging.basicConfig(
    level=logging.INFO,
    format="[TrayService] %(levelname)s: %(message)s",
    stream=sys.stderr,  # stdout è riservato all'IPC
)
logger = logging.getLogger(__name__)

try:
    import gi

    gi.require_version("Gio", "2.0")
    gi.require_version("GLib", "2.0")
    from gi.repository import Gio, GLib

    DBUS_AVAILABLE = True
except (ValueError, ImportError) as e:
    logger.error(f"GIO D-Bus non disponibile: {e}")
    DBUS_AVAILABLE = False

if not DBUS_AVAILABLE:
    sys.stdout.write(json.dumps({"event": "error", "message": "GIO D-Bus not available"}) + "\n")
    sys.stdout.flush()
    sys.exit(1)

# libdbusmenu-glib è una dipendenza di sistema opzionale: se assente, il
# tray funziona comunque (icona + click sinistro) ma senza menu contestuale.
DBUSMENU_AVAILABLE = False
Dbusmenu = None
try:
    gi.require_version("Dbusmenu", "0.4")
    from gi.repository import Dbusmenu

    DBUSMENU_AVAILABLE = True
except (ValueError, ImportError):
    logger.info("libdbusmenu non disponibile: il tray non avrà un menu contestuale")


# Interfaccia D-Bus org.kde.StatusNotifierItem (adottata anche da
# xapp-sn-watcher/Cinnamon, KDE Plasma, XFCE col plugin SNI, MATE, Budgie).
STATUS_NOTIFIER_ITEM_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property type="s" name="Category" access="read"/>
    <property type="s" name="Id" access="read"/>
    <property type="s" name="Title" access="read"/>
    <property type="s" name="Status" access="read"/>
    <property type="u" name="WindowId" access="read"/>
    <property type="s" name="IconName" access="read"/>
    <property type="a(iiay)" name="IconPixmap" access="read"/>
    <property type="s" name="IconThemePath" access="read"/>
    <property type="s" name="AttentionIconName" access="read"/>
    <property type="a(iiay)" name="AttentionIconPixmap" access="read"/>
    <property type="(sa(iiay)ss)" name="ToolTip" access="read"/>
    <property type="b" name="ItemIsMenu" access="read"/>
    <property type="o" name="Menu" access="read"/>
    <method name="ContextMenu">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="Activate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="Scroll">
      <arg type="i" name="delta" direction="in"/>
      <arg type="s" name="orientation" direction="in"/>
    </method>
    <signal name="NewIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus">
      <arg type="s" name="status"/>
    </signal>
  </interface>
</node>
"""


class TrayService:
    """Servizio tray StatusNotifierItem + DBusMenu, senza dipendenza GTK."""

    ICON_MAP = {
        "protected": "object-select-symbolic",
        "scanning": "view-refresh-symbolic",
        "warning": "dialog-warning-symbolic",
        "threat": "dialog-error-symbolic",
    }
    SNI_STATUS_MAP = {
        "protected": "Active",
        "scanning": "Active",
        "warning": "NeedsAttention",
        "threat": "NeedsAttention",
    }

    SNI_PATH = "/StatusNotifierItem"
    MENU_PATH = "/MenuBar"
    WATCHER_NAMES = [
        "org.x.StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
        "org.freedesktop.StatusNotifierWatcher",
    ]
    WATCHER_RETRY_DELAY_MS = 2000
    _MAX_IPC_LINE_BYTES = 64 * 1024

    def __init__(self):
        self._loop = None
        self._bus = None
        self._sni_registration_id = 0
        self._running = True
        self._watcher_registered = False
        self._watcher_retry_source_id = 0

        self._current_status = "protected"
        self._window_visible = True

        self._dbusmenu_server = None
        self._menu_root = None
        self._setup_dbusmenu()

    # --- DBusMenu (menu contestuale) ---

    def _setup_dbusmenu(self):
        if not DBUSMENU_AVAILABLE:
            return
        try:
            self._dbusmenu_server = Dbusmenu.Server.new(self.MENU_PATH)
            self._menu_root = Dbusmenu.Menuitem.new()
            self._rebuild_menu()
            self._dbusmenu_server.set_root(self._menu_root)
            logger.info(f"DBusMenu server inizializzato su {self.MENU_PATH}")
        except Exception as e:
            logger.warning(f"Impossibile inizializzare DBusMenu: {e}")
            self._dbusmenu_server = None
            self._menu_root = None

    def _rebuild_menu(self):
        if not self._menu_root or not DBUSMENU_AVAILABLE:
            return
        for child in self._menu_root.get_children():
            self._menu_root.child_delete(child)

        item_id = 1

        toggle = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        toggle.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL,
            "Hide Window" if self._window_visible else "Show Window",
        )
        toggle.connect("item-activated", lambda *_: self._send_action("toggle_window"))
        self._menu_root.child_append(toggle)

        sep = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        sep.property_set(Dbusmenu.MENUITEM_PROP_TYPE, "separator")
        self._menu_root.child_append(sep)

        quick_scan = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        quick_scan.property_set(Dbusmenu.MENUITEM_PROP_LABEL, "Quick Scan")
        quick_scan.connect("item-activated", lambda *_: self._send_action("quick_scan"))
        self._menu_root.child_append(quick_scan)

        update_db = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        update_db.property_set(Dbusmenu.MENUITEM_PROP_LABEL, "Update Definitions")
        update_db.connect("item-activated", lambda *_: self._send_action("update"))
        self._menu_root.child_append(update_db)

        sep2 = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        sep2.property_set(Dbusmenu.MENUITEM_PROP_TYPE, "separator")
        self._menu_root.child_append(sep2)

        quit_item = Dbusmenu.Menuitem.new_with_id(item_id); item_id += 1
        quit_item.property_set(Dbusmenu.MENUITEM_PROP_LABEL, "Quit")
        quit_item.connect("item-activated", lambda *_: self._send_action("quit"))
        self._menu_root.child_append(quit_item)

    # --- Stato / icona ---

    def _get_icon_name(self):
        return self.ICON_MAP.get(self._current_status, "security-high")

    def _get_sni_status(self):
        return self.SNI_STATUS_MAP.get(self._current_status, "Active")

    def _get_tooltip(self):
        return f"ClamGuard — {self._current_status.capitalize()}"

    def update_status(self, status):
        if status not in self.ICON_MAP:
            logger.warning(f"Stato sconosciuto: {status}")
            return False
        self._current_status = status
        self._emit_signal("NewIcon")
        self._emit_signal("NewStatus", GLib.Variant("(s)", (self._get_sni_status(),)))
        self._emit_signal("NewToolTip")
        return False  # one-shot per GLib.idle_add

    def update_window_visible(self, visible):
        self._window_visible = visible
        self._rebuild_menu()
        return False

    # --- D-Bus: registrazione oggetto SNI + watcher discovery ---

    def _on_bus_acquired(self, connection):
        self._bus = connection
        node_info = Gio.DBusNodeInfo.new_for_xml(STATUS_NOTIFIER_ITEM_XML)
        self._sni_registration_id = connection.register_object(
            self.SNI_PATH,
            node_info.interfaces[0],
            self._handle_method_call,
            self._handle_get_property,
            None,
        )
        logger.info(f"StatusNotifierItem registrato su {self.SNI_PATH}")

    def _register_with_watcher(self, watcher_index=0):
        if not self._bus or self._watcher_registered:
            return
        if watcher_index >= len(self.WATCHER_NAMES):
            self._schedule_watcher_retry()
            return
        watcher_name = self.WATCHER_NAMES[watcher_index]
        try:
            self._bus.call(
                watcher_name,
                "/StatusNotifierWatcher",
                "org.kde.StatusNotifierWatcher",
                "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (self.SNI_PATH,)),
                None,
                Gio.DBusCallFlags.NONE,
                -1,
                None,
                self._on_register_complete,
                (watcher_name, watcher_index + 1),
            )
        except Exception as e:
            logger.debug(f"Registrazione con {watcher_name} fallita: {e}")
            self._register_with_watcher(watcher_index + 1)

    def _on_register_complete(self, source, result, user_data):
        watcher_name, next_index = user_data
        try:
            source.call_finish(result)
            self._watcher_registered = True
            logger.info(f"Registrato con {watcher_name}")
        except Exception:
            self._register_with_watcher(next_index)

    def _schedule_watcher_retry(self):
        if not self._running or self._watcher_registered or self._watcher_retry_source_id:
            return
        self._watcher_retry_source_id = GLib.timeout_add(
            self.WATCHER_RETRY_DELAY_MS, self._retry_watcher
        )
        logger.info("Nessun StatusNotifierWatcher trovato; nuovo tentativo tra 2s")

    def _retry_watcher(self):
        self._watcher_retry_source_id = 0
        self._register_with_watcher()
        return False

    def _handle_method_call(self, connection, sender, object_path, interface_name,
                             method_name, parameters, invocation):
        if method_name == "Activate":
            self._send_action("toggle_window")
            invocation.return_value(None)
        elif method_name in ("ContextMenu", "SecondaryActivate"):
            invocation.return_value(None)
        elif method_name == "Scroll":
            invocation.return_value(None)
        else:
            invocation.return_dbus_error(
                "org.freedesktop.DBus.Error.UnknownMethod", f"Unknown method: {method_name}"
            )

    def _handle_get_property(self, connection, sender, object_path, interface_name, property_name):
        if property_name == "Category":
            return GLib.Variant("s", "ApplicationStatus")
        if property_name == "Id":
            return GLib.Variant("s", "clamguard")
        if property_name == "Title":
            return GLib.Variant("s", "ClamGuard")
        if property_name == "Status":
            return GLib.Variant("s", self._get_sni_status())
        if property_name == "WindowId":
            return GLib.Variant("u", 0)
        if property_name == "IconName":
            return GLib.Variant("s", self._get_icon_name())
        if property_name == "IconPixmap":
            return GLib.Variant("a(iiay)", [])
        if property_name == "IconThemePath":
            return GLib.Variant("s", "")
        if property_name == "AttentionIconName":
            return GLib.Variant("s", self._get_icon_name())
        if property_name == "AttentionIconPixmap":
            return GLib.Variant("a(iiay)", [])
        if property_name == "ToolTip":
            return GLib.Variant("(sa(iiay)ss)", ("", [], "ClamGuard", self._get_tooltip()))
        if property_name == "ItemIsMenu":
            return GLib.Variant("b", False)
        if property_name == "Menu":
            return GLib.Variant("o", self.MENU_PATH)
        return None

    def _emit_signal(self, signal_name, args=None):
        if self._bus:
            try:
                self._bus.emit_signal(
                    None, self.SNI_PATH, "org.kde.StatusNotifierItem", signal_name, args
                )
            except Exception as e:
                logger.error(f"Emit {signal_name} fallito: {e}")

    # --- IPC (stdin/stdout) ---

    def _send_message(self, message):
        try:
            sys.stdout.write(json.dumps(message) + "\n")
            sys.stdout.flush()
        except Exception as e:
            logger.error(f"Scrittura IPC fallita: {e}")

    def _send_action(self, action):
        self._send_message({"event": "menu_action", "action": action})

    def handle_command(self, command):
        action = command.get("action")
        if action == "update_status":
            GLib.idle_add(self.update_status, command.get("status", "protected"))
        elif action == "update_window_visible":
            GLib.idle_add(self.update_window_visible, bool(command.get("visible", True)))
        elif action == "quit":
            GLib.idle_add(self._quit)
        elif action == "ping":
            self._send_message({"event": "pong"})
        else:
            logger.warning(f"Comando sconosciuto: {action}")

    def _read_stdin(self):
        try:
            for line in sys.stdin:
                if not self._running:
                    break
                if len(line) > self._MAX_IPC_LINE_BYTES:
                    logger.error(f"Riga IPC di {len(line)} byte scartata (limite {self._MAX_IPC_LINE_BYTES})")
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    command = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON non valido: {e}")
                    continue
                if not isinstance(command, dict):
                    logger.error("Comando IPC scartato: non è un oggetto JSON")
                    continue
                self.handle_command(command)
        except Exception as e:
            logger.error(f"Errore lettura stdin: {e}")
        finally:
            GLib.idle_add(self._quit)

    def _quit(self):
        self._running = False
        if self._bus and self._sni_registration_id:
            self._bus.unregister_object(self._sni_registration_id)
            self._sni_registration_id = 0
        if self._loop:
            self._loop.quit()
        return False

    def run(self):
        connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self._on_bus_acquired(connection)
        self._register_with_watcher()

        self._send_message({"event": "ready"})

        threading.Thread(target=self._read_stdin, daemon=True).start()

        self._loop = GLib.MainLoop()
        logger.info("Avvio GLib main loop")
        self._loop.run()
        logger.info("GLib main loop terminato")


def main():
    try:
        TrayService().run()
    except Exception as e:
        logger.error(f"Errore tray service: {e}")
        print(json.dumps({"event": "error", "message": str(e)}), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
