#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.third_party_db import (  # noqa: E402
    SANESECURITY_KEY_PATH,
    SignatureProvider,
    ThirdPartyDBManager,
)


def _gpg_available() -> bool:
    """True se gpg e gpgv sono disponibili sul sistema."""
    return shutil.which("gpg") is not None and shutil.which("gpgv") is not None


def _generate_test_key(tmpdir: str) -> str:
    """Genera una coppia chiave GPG temporanea e ritorna il path della
    chiave pubblica esportata. Usata per testare _verify_gpg senza
    dipendere dalla chiave bundled reale."""
    gnupg_home = os.path.join(tmpdir, "gnupg")
    os.makedirs(gnupg_home, mode=0o700, exist_ok=True)

    # Genera una chiave RSA-2048 senza passphrase, in batch.
    gen_params = os.path.join(tmpdir, "gen_params")
    with open(gen_params, "w") as f:
        f.write(
            "Key-Type: RSA\n"
            "Key-Length: 2048\n"
            "Name-Real: ClamGuard Test\n"
            "Name-Email: test@clamguard.local\n"
            "Expire-Date: 0\n"
            "%no-protection\n"
            "%commit\n"
        )
    subprocess.run(
        ["gpg", "--batch", "--homedir", gnupg_home, "--gen-key", gen_params],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )

    # Esporta la chiave pubblica.
    pub_path = os.path.join(tmpdir, "test_key.gpg")
    subprocess.run(
        ["gpg", "--batch", "--homedir", gnupg_home, "--export", "--output", pub_path],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return pub_path


def _sign_file(gnupg_home: str, data_path: str, sig_path: str) -> None:
    """Firma detached un file con la chiave di test."""
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--homedir",
            gnupg_home,
            "--detach-sign",
            "--output",
            sig_path,
            data_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )


class TestThirdPartyUpdater(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = ThirdPartyDBManager(sig_dir=self.tmpdir, state_dir=self.tmpdir)

    def test_provider_status(self):
        status = self.mgr.get_provider_status()
        self.assertGreater(len(status), 0)

    def test_db_permissions(self):
        """Verify that the third party database file has secure 0o600 permissions."""
        db_path = os.path.join(self.tmpdir, "test_perm.db")
        mgr = ThirdPartyDBManager(
            sig_dir=self.tmpdir, state_dir=self.tmpdir, db_path=db_path
        )
        self.assertIsNotNone(mgr)
        self.assertTrue(os.path.exists(db_path))
        mode = os.stat(db_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_sanesecurity_providers_have_gpg_configured(self):
        """CG-013: i provider sanesecurity devono avere signature_url e
        gpg_required=True; gli altri provider no (comportamento invariato)."""
        by_name = {p.name: p for p in self.mgr.providers}
        for name in ("sanesecurity_junk", "sanesecurity_phish"):
            self.assertIn(name, by_name)
            self.assertTrue(by_name[name].signature_url)
            self.assertTrue(by_name[name].gpg_required)
        for name in ("urlhaus", "twinclams", "ditekshen"):
            self.assertIn(name, by_name)
            self.assertIsNone(by_name[name].signature_url)
            self.assertFalse(by_name[name].gpg_required)

    def test_bundled_key_exists(self):
        """CG-013: la chiave pubblica bundled deve esistere nel pacchetto."""
        self.assertTrue(os.path.isfile(SANESECURITY_KEY_PATH))
        self.assertGreater(os.path.getsize(SANESECURITY_KEY_PATH), 0)


@unittest.skipUnless(_gpg_available(), "gpg/gpgv not available")
class TestGpgVerification(unittest.TestCase):
    """CG-013: test di _verify_gpg con una coppia chiave fittizia."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sig_dir = os.path.join(self.tmpdir, "sig")
        self.state_dir = os.path.join(self.tmpdir, "state")
        self.mgr = ThirdPartyDBManager(
            sig_dir=self.sig_dir, state_dir=self.state_dir
        )
        self.gnupg_home = os.path.join(self.tmpdir, "gnupg")
        os.makedirs(self.gnupg_home, mode=0o700, exist_ok=True)
        self.test_key = _generate_test_key(self.tmpdir)

    def test_valid_signature_returns_true(self):
        data_path = os.path.join(self.tmpdir, "payload.ndb")
        with open(data_path, "w") as f:
            f.write("Test signature content\n")
        sig_path = os.path.join(self.tmpdir, "payload.ndb.sig")
        _sign_file(self.gnupg_home, data_path, sig_path)

        with mock.patch(
            "src.core.third_party_db.SANESECURITY_KEY_PATH", self.test_key
        ):
            result = self.mgr._verify_gpg(sig_path, data_path)
        self.assertTrue(result)

    def test_invalid_signature_returns_false(self):
        data_path = os.path.join(self.tmpdir, "payload2.ndb")
        with open(data_path, "w") as f:
            f.write("Test signature content\n")
        sig_path = os.path.join(self.tmpdir, "payload2.ndb.sig")
        _sign_file(self.gnupg_home, data_path, sig_path)

        # Corrompi la firma: deve essere rifiutata.
        with open(sig_path, "ab") as f:
            f.write(b"corrupted")

        with mock.patch(
            "src.core.third_party_db.SANESECURITY_KEY_PATH", self.test_key
        ):
            result = self.mgr._verify_gpg(sig_path, data_path)
        self.assertFalse(result)

    def test_missing_gpg_returns_none(self):
        data_path = os.path.join(self.tmpdir, "payload3.ndb")
        with open(data_path, "w") as f:
            f.write("Test signature content\n")
        sig_path = os.path.join(self.tmpdir, "payload3.ndb.sig")
        _sign_file(self.gnupg_home, data_path, sig_path)

        with mock.patch(
            "src.core.third_party_db.SANESECURITY_KEY_PATH", self.test_key
        ):
            with mock.patch(
                "src.core.third_party_db.shutil.which", return_value=None
            ):
                result = self.mgr._verify_gpg(sig_path, data_path)
        self.assertIsNone(result)


class TestGpgFailClosed(unittest.TestCase):
    """CG-013: una firma GPG invalida su un provider gpg_required=True
    deve BLOCCARE l'aggiornamento (fail-closed)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sig_dir = os.path.join(self.tmpdir, "sig")
        self.state_dir = os.path.join(self.tmpdir, "state")
        self.mgr = ThirdPartyDBManager(
            sig_dir=self.sig_dir, state_dir=self.state_dir
        )

    def _mock_urlopen(self, db_data: bytes, sig_data: bytes):
        """Mock di urlopen: prima risposta = download DB, seconda = firma.

        urlopen è usato come context manager (`with urlopen(...) as resp`),
        quindi ogni risposta deve implementare __enter__ restituendo se
        stessa, altrimenti `resp.read()` restituirebbe un MagicMock e non
        i bytes attesi.
        """
        db_resp = mock.MagicMock()
        db_resp.status = 200
        db_resp.read.return_value = db_data
        db_resp.headers.get.return_value = None
        db_resp.__enter__.return_value = db_resp

        sig_resp = mock.MagicMock()
        sig_resp.status = 200
        sig_resp.read.return_value = sig_data
        sig_resp.headers.get.return_value = None
        sig_resp.__enter__.return_value = sig_resp

        return mock.patch(
            "src.core.third_party_db.urlopen", side_effect=[db_resp, sig_resp]
        )

    def test_invalid_gpg_blocks_update(self):
        provider = SignatureProvider(
            "test_provider",
            "https://example.com/test.ndb",
            "test.ndb",
            signature_url="https://example.com/test.ndb.sig",
            gpg_required=True,
        )
        db_data = b"Test signature database content\n"
        sig_data = b"not a valid gpg signature"

        with self._mock_urlopen(db_data, sig_data):
            with mock.patch(
                "src.core.third_party_db.ThirdPartyDBManager._verify_gpg",
                return_value=False,
            ):
                result = self.mgr._update_provider(provider)

        self.assertFalse(result["success"])
        self.assertIn("GPG signature verification FAILED", result["error"])
        # Nessun file attivato nella sig_dir.
        self.assertEqual(os.listdir(self.mgr.sig_dir), [])

    def test_invalid_gpg_without_required_degrades_to_clamscan(self):
        provider = SignatureProvider(
            "test_provider2",
            "https://example.com/test2.ndb",
            "test2.ndb",
            signature_url="https://example.com/test2.ndb.sig",
            gpg_required=False,
        )
        db_data = b"Test signature database content\n"
        sig_data = b"not a valid gpg signature"

        with self._mock_urlopen(db_data, sig_data):
            with mock.patch(
                "src.core.third_party_db.ThirdPartyDBManager._verify_gpg",
                return_value=False,
            ):
                with mock.patch(
                    "src.core.third_party_db.ThirdPartyDBManager._test_signature",
                    return_value={"valid": True},
                ):
                    result = self.mgr._update_provider(provider)

        self.assertTrue(result["success"])

    def test_missing_gpg_tool_degrades_to_clamscan(self):
        provider = SignatureProvider(
            "test_provider3",
            "https://example.com/test3.ndb",
            "test3.ndb",
            signature_url="https://example.com/test3.ndb.sig",
            gpg_required=True,
        )
        db_data = b"Test signature database content\n"
        sig_data = b"some signature bytes"

        with self._mock_urlopen(db_data, sig_data):
            with mock.patch(
                "src.core.third_party_db.ThirdPartyDBManager._verify_gpg",
                return_value=None,
            ):
                with mock.patch(
                    "src.core.third_party_db.ThirdPartyDBManager._test_signature",
                    return_value={"valid": True},
                ):
                    result = self.mgr._update_provider(provider)

        # gpgv assente → degrada a clamscan, non blocca.
        self.assertTrue(result["success"])

    def test_provider_without_signature_url_skips_gpg(self):
        provider = SignatureProvider(
            "test_provider4",
            "https://example.com/test4.ndb",
            "test4.ndb",
        )
        db_data = b"Test signature database content\n"

        db_resp = mock.MagicMock()
        db_resp.status = 200
        db_resp.read.return_value = db_data
        db_resp.headers.get.return_value = None
        db_resp.__enter__.return_value = db_resp

        with mock.patch(
            "src.core.third_party_db.urlopen", return_value=db_resp
        ):
            with mock.patch(
                "src.core.third_party_db.ThirdPartyDBManager._verify_gpg"
            ) as mock_verify:
                with mock.patch(
                    "src.core.third_party_db.ThirdPartyDBManager._test_signature",
                    return_value={"valid": True},
                ):
                    result = self.mgr._update_provider(provider)

        self.assertTrue(result["success"])
        # _verify_gpg NON deve essere chiamato per provider senza firma.
        mock_verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()