#!/usr/bin/env python3
import unittest
import tempfile
import os
from src.core.quarantine import QuarantineManager


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.q = QuarantineManager(quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "q.db"))

    def test_quarantine_and_restore(self):
        testfile = os.path.join(self.tmpdir, "test.txt")
        with open(testfile, "w") as f:
            f.write("infected content")
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertTrue(self.q.restore(entries[0].id, os.path.join(self.tmpdir, "restored.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, "restored.txt")))

    def test_quarantined_file_is_owner_readable(self):
        """Regressione: il file in quarantena deve restare leggibile dal
        proprietario (0o400), altrimenti restore() fallisce con
        PermissionError per qualunque utente non-root. Il vecchio chmod
        0o000 rendeva questo test indistinguibile da un successo solo
        perché la CI gira come root (root bypassa i permessi UNIX) — qui
        verifichiamo i bit di permesso direttamente, non solo l'esito.
        """
        testfile = os.path.join(self.tmpdir, "test2.txt")
        with open(testfile, "w") as f:
            f.write("infected content")
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        mode = os.stat(entries[0].quarantine_path).st_mode & 0o777
        self.assertTrue(
            mode & 0o400,
            f"il file in quarantena deve restare leggibile dal proprietario, mode={oct(mode)}",
        )

    def test_encryption_salt_persists_across_instances(self):
        """Regressione: il salt PBKDF2 deve essere generato casualmente
        UNA VOLTA per installazione e persistito, non hardcoded. Verifica
        che la stessa password produca la stessa chiave su istanze
        diverse che puntano allo stesso DB (altrimenti i file già
        cifrati non sarebbero più decifrabili dopo un riavvio dell'app).
        """
        q1 = QuarantineManager(quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db"))
        q1.set_encryption(password="hunter2")
        key1 = q1._cipher

        q2 = QuarantineManager(quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db"))
        q2.set_encryption(password="hunter2")
        key2 = q2._cipher

        # Fernet non espone la chiave direttamente; confrontiamo invece
        # che un token cifrato da un'istanza sia decifrabile dall'altra.
        token = key1.encrypt(b"contenuto di prova")
        self.assertEqual(key2.decrypt(token), b"contenuto di prova")

    def test_encryption_salt_differs_across_installations(self):
        """Regressione: prima del fix il salt era la costante hardcoded
        b"alpha_quarantine_salt_v1", identica su OGNI installazione di
        ClamGuard — un attaccante avrebbe potuto precalcolare una singola
        rainbow table valida per tutte le installazioni. Due database di
        quarantena distinti devono avere salt distinti.
        """
        other_dir = tempfile.mkdtemp()
        q1 = QuarantineManager(quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db"))
        q2 = QuarantineManager(quarantine_dir=other_dir, db_path=os.path.join(other_dir, "enc.db"))
        self.assertNotEqual(q1._get_or_create_salt(), q2._get_or_create_salt())


if __name__ == "__main__":
    unittest.main()
