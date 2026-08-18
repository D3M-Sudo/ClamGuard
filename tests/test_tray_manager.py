#!/usr/bin/env python3
"""CG-016: test per la risoluzione robusta dell'interprete Python nel
subprocesso tray (TrayManager._resolve_interpreter).

Il modulo tray_manager importa gi/GLib a livello top-level; per testarlo
senza un display GTK, questi moduli vengono mockati prima dell'import.
"""

import sys
import unittest
from unittest import mock

# --- Mock GTK prima dell'import di tray_manager ---
_gi_mock = mock.MagicMock()
_glib_mock = mock.MagicMock()
sys.modules["gi"] = _gi_mock
sys.modules["gi.repository"] = mock.MagicMock()
sys.modules["gi.repository.GLib"] = _glib_mock
# ----------------------------------------------------

from src.services.tray_manager import TrayManager  # noqa: E402


class TestResolveInterpreter(unittest.TestCase):
    """CG-016: _resolve_interpreter deve usare sys.executable quando è
    eseguibile, degradare a python3 dal PATH in caso contrario, e
    restituire None se nessuno dei due è disponibile."""

    def setUp(self):
        self.mgr = TrayManager()

    def test_uses_sys_executable_when_executable(self):
        with mock.patch("src.services.tray_manager.sys.executable", "/usr/bin/python3"):
            with mock.patch(
                "src.services.tray_manager.os.access", return_value=True
            ) as mock_access:
                with mock.patch(
                    "src.services.tray_manager.os.path.isfile", return_value=True
                ):
                    result = self.mgr._resolve_interpreter()
        self.assertEqual(result, "/usr/bin/python3")
        mock_access.assert_called_once_with("/usr/bin/python3", mock.ANY)

    def test_falls_back_to_python3_when_sys_executable_missing(self):
        with mock.patch("src.services.tray_manager.sys.executable", "/nonexistent"):
            with mock.patch(
                "src.services.tray_manager.shutil.which", return_value="/usr/bin/python3"
            ):
                result = self.mgr._resolve_interpreter()
        self.assertEqual(result, "/usr/bin/python3")

    def test_returns_none_when_no_interpreter_available(self):
        with mock.patch("src.services.tray_manager.sys.executable", "/nonexistent"):
            with mock.patch("src.services.tray_manager.shutil.which", return_value=None):
                result = self.mgr._resolve_interpreter()
        self.assertIsNone(result)

    def test_start_marks_tray_down_when_no_interpreter(self):
        with mock.patch(
            "src.services.tray_manager.TrayManager._resolve_interpreter",
            return_value=None,
        ):
            self.mgr.start()
        self.assertTrue(self.mgr._tray_down)
        self.assertIsNone(self.mgr._process)

    def test_start_marks_tray_down_when_service_missing(self):
        with mock.patch(
            "src.services.tray_manager.TrayManager._get_service_path",
            return_value="/nonexistent/tray_service.py",
        ):
            self.mgr.start()
        self.assertTrue(self.mgr._tray_down)
        self.assertIsNone(self.mgr._process)


if __name__ == "__main__":
    unittest.main()