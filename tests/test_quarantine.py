#!/usr/bin/env python3
import os
import tempfile
import unittest

from src.core.quarantine import QuarantineManager


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.q = QuarantineManager(
            quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "q.db")
        )

    def test_quarantine_and_restore(self):
        testfile = os.path.join(self.tmpdir, "test.txt")
        with open(testfile, "w") as f:
            f.write("infected content")
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertTrue(
            self.q.restore(entries[0].id, os.path.join(self.tmpdir, "restored.txt"))
        )
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
        q1 = QuarantineManager(
            quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db")
        )
        q1.set_encryption(password="hunter2")
        key1 = q1._cipher

        q2 = QuarantineManager(
            quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db")
        )
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
        q1 = QuarantineManager(
            quarantine_dir=self.tmpdir, db_path=os.path.join(self.tmpdir, "enc.db")
        )
        q2 = QuarantineManager(
            quarantine_dir=other_dir, db_path=os.path.join(other_dir, "enc.db")
        )
        self.assertNotEqual(q1._get_or_create_salt(), q2._get_or_create_salt())

    def test_symlink_quarantine_prevention(self):
        """Ensure that quarantine refuses to process symbolic links to prevent traversal."""
        target_file = os.path.join(self.tmpdir, "target.txt")
        with open(target_file, "w") as f:
            f.write("some content")
        link_file = os.path.join(self.tmpdir, "symlink.txt")
        os.symlink(target_file, link_file)

        self.assertFalse(self.q.quarantine(link_file, "Test.Virus"))
        self.assertTrue(os.path.exists(link_file))

    def test_symlink_restore_prevention(self):
        """Ensure that restore refuses to overwrite or traverse symbolic links."""
        testfile = os.path.join(self.tmpdir, "test_sym.txt")
        with open(testfile, "w") as f:
            f.write("infected content")
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)

        # Create a symlink at the restore destination
        dest_target = os.path.join(self.tmpdir, "real_dest.txt")
        with open(dest_target, "w") as f:
            f.write("safe content")
        dest_link = os.path.join(self.tmpdir, "symlink_dest.txt")
        os.symlink(dest_target, dest_link)

        # Restore to the symlink path should fail
        self.assertFalse(self.q.restore(entries[0].id, dest_link))
        # Ensure target file was NOT overwritten
        with open(dest_target, "r") as f:
            self.assertEqual(f.read(), "safe content")

    def test_database_permissions(self):
        """Ensure that the quarantine database file is initialized with 0o600 permissions."""
        self.assertTrue(os.path.exists(self.q.db_path))
        mode = os.stat(self.q.db_path).st_mode & 0o777
        self.assertEqual(
            mode, 0o600, f"Expected database permissions to be 0o600, got {oct(mode)}"
        )

    def test_quarantine_hash_matches_content(self):
        """CG-001: l'hash SHA-256 memorizzato nel DB deve corrispondere al
        contenuto reale del file. Prima del fix, hash e dati venivano letti
        in due passaggi separati (TOCTOU): se il file cambiava tra le due
        letture, l'hash non corrispondeva ai byte cifrati/copiati."""
        import hashlib

        content = b"infected content for hash test"
        testfile = os.path.join(self.tmpdir, "hash_test.txt")
        with open(testfile, "wb") as f:
            f.write(content)

        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)
        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(entries[0].file_hash, expected)

    def test_quarantine_preserves_original_if_db_insert_fails(self):
        """CG-002: se l'INSERT nel DB fallisce, il file originale NON deve
        essere rimosso. Prima del fix, l'unlink avveniva PRIMA dell'insert:
        un fallimento del DB lasciava il file rimosso dall'originale e la
        copia in quarantena orfana (non tracciata, irrecuperabile via UI)."""
        testfile = os.path.join(self.tmpdir, "db_fail.txt")
        with open(testfile, "w") as f:
            f.write("infected content")

        # Forza il fallimento dell'INSERT puntando il DB a un path in una
        # directory inesistente (sqlite3.OperationalError).
        self.q.db_path = os.path.join(self.tmpdir, "nonexistent_dir", "q.db")

        self.assertFalse(self.q.quarantine(testfile, "Test.Virus"))
        # L'originale deve essere preservato.
        self.assertTrue(os.path.exists(testfile))
        # Nessuna copia orfana residua nella directory di quarantena.
        leftovers = [
            f
            for f in os.listdir(self.tmpdir)
            if f.startswith(".q_tmp_") or f.endswith(".part")
        ]
        self.assertEqual(leftovers, [])

    def test_restore_refuses_to_overwrite_existing(self):
        """CG-014: restore() non deve sovrascrivere un file esistente alla
        destinazione. Prima del fix, scriveva sopra qualunque file presente,
        perdendo dati senza warning."""
        testfile = os.path.join(self.tmpdir, "collision.txt")
        with open(testfile, "w") as f:
            f.write("infected content")
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)

        # Crea un file alla destinazione di restore.
        dest = os.path.join(self.tmpdir, "collision_dest.txt")
        with open(dest, "w") as f:
            f.write("precious existing data")

        self.assertFalse(self.q.restore(entries[0].id, dest))
        # Il file esistente non deve essere stato toccato.
        with open(dest, "r") as f:
            self.assertEqual(f.read(), "precious existing data")

    def test_encrypted_quarantine_restore_roundtrip(self):
        """CG-001: con la cifratura attiva, quarantine + restore devono
        preservare il contenuto originale (hash calcolato sui byte in
        chiaro, cifrati nello stesso passaggio)."""
        content = b"secret infected payload"
        testfile = os.path.join(self.tmpdir, "enc_roundtrip.txt")
        with open(testfile, "wb") as f:
            f.write(content)

        self.q.set_encryption(key=b"k" * 32)
        self.assertTrue(self.q.quarantine(testfile, "Test.Virus"))
        entries = self.q.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].encrypted)

        dest = os.path.join(self.tmpdir, "enc_restored.txt")
        self.assertTrue(self.q.restore(entries[0].id, dest))
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main()
