#!/usr/bin/env python3
import os
import tempfile
import unittest
from pathlib import Path

from src.core.privileged_paths import (
    ALLOWED_DEST_DIRS,
    validate_destination,
    validate_source_for_uid,
    verify_staging_root,
)


class TestPrivilegedPaths(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_validate_destination_accepts_allowlisted_dir_and_extension(self):
        # ALLOWED_DEST_DIRS è fissa a /var/lib/clamav: qui verifichiamo solo
        # la logica di validazione dell'estensione/nome, non l'allowlist di
        # produzione (che richiederebbe scrivere realmente sotto /var/lib).
        dest = Path(ALLOWED_DEST_DIRS[0]) / "custom.hdb"
        # Non solleva
        try:
            validate_destination(dest)
        except ValueError as e:
            self.fail(f"destinazione valida rifiutata: {e}")

    def test_validate_destination_rejects_wrong_extension(self):
        dest = Path(ALLOWED_DEST_DIRS[0]) / "malicious.sh"
        with self.assertRaises(ValueError):
            validate_destination(dest)

    def test_validate_destination_rejects_outside_allowlist(self):
        dest = Path("/etc/passwd.hdb")
        with self.assertRaises(ValueError):
            validate_destination(dest)

    def test_validate_source_rejects_wrong_uid(self):
        staged = os.path.join(self.tmpdir, "sig.hdb")
        with open(staged, "wb") as f:
            f.write(b"fake signature")
        os.chmod(staged, 0o600)

        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with self.assertRaises(ValueError):
                # uid inventato, sicuramente diverso dal chiamante reale
                validate_source_for_uid(fd, Path(staged), 999999, Path(self.tmpdir))
        finally:
            os.close(fd)

    def test_validate_source_rejects_world_writable_file(self):
        staged = os.path.join(self.tmpdir, "sig2.hdb")
        with open(staged, "wb") as f:
            f.write(b"fake signature")
        os.chmod(staged, 0o666)  # scrivibile da chiunque: non sicuro

        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with self.assertRaises(ValueError):
                validate_source_for_uid(
                    fd, Path(staged), os.getuid(), Path(self.tmpdir)
                )
        finally:
            os.close(fd)

    def test_validate_source_accepts_valid_staged_file(self):
        staged = os.path.join(self.tmpdir, "sig3.hdb")
        with open(staged, "wb") as f:
            f.write(b"fake signature")
        os.chmod(staged, 0o600)

        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            validate_source_for_uid(fd, Path(staged), os.getuid(), Path(self.tmpdir))
        except ValueError as e:
            self.fail(f"file staged valido rifiutato: {e}")
        finally:
            os.close(fd)

    def test_verify_staging_root_rejects_wrong_permissions(self):
        os.chmod(self.tmpdir, 0o755)  # leggibile da altri: non sicuro
        with self.assertRaises(ValueError):
            verify_staging_root(Path(self.tmpdir), os.getuid())

    def test_verify_staging_root_accepts_owner_only(self):
        os.chmod(self.tmpdir, 0o700)
        try:
            verify_staging_root(Path(self.tmpdir), os.getuid())
        except ValueError as e:
            self.fail(f"staging root valido rifiutato: {e}")


if __name__ == "__main__":
    unittest.main()
