#!/usr/bin/env python3
"""
QuarantineManager — Secure file isolation with SHA-256 and optional encryption
"""

import hashlib
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import paths


class AESGCMCipher:
    """AES-256-GCM cipher wrapper validating Auth Tag (MAC) before completion."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self.aesgcm = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 12:
            raise ValueError("Ciphertext too short")
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_file(self, src_path: Path, dst_path: Path) -> None:
        import struct

        with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
            while True:
                chunk = f_in.read(65536)
                if not chunk:
                    break
                nonce = os.urandom(12)
                ciphertext = self.aesgcm.encrypt(nonce, chunk, None)
                f_out.write(struct.pack(">I", len(ciphertext)))
                f_out.write(nonce)
                f_out.write(ciphertext)

    def decrypt_file(self, src_path: Path, dst_path: Path) -> None:
        import struct

        try:
            file_size = os.path.getsize(src_path)
            with open(src_path, "rb") as f_in:
                len_bytes = f_in.read(4)
                if not len_bytes:
                    return
                if len(len_bytes) < 4:
                    raise ValueError("Truncated encrypted file header")
                chunk_len = struct.unpack(">I", len_bytes)[0]
                if chunk_len > file_size or chunk_len == 0:
                    raise ValueError("Does not look like a chunked file")

                nonce = f_in.read(12)
                if len(nonce) < 12:
                    raise ValueError("Truncated encrypted file nonce")
                ciphertext = f_in.read(chunk_len)
                if len(ciphertext) < chunk_len:
                    raise ValueError("Truncated encrypted file ciphertext")

                plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

                with open(dst_path, "wb") as f_out:
                    f_out.write(plaintext)
                    while True:
                        l_bytes = f_in.read(4)
                        if not l_bytes:
                            break
                        if len(l_bytes) < 4:
                            raise ValueError("Truncated chunk length")
                        c_len = struct.unpack(">I", l_bytes)[0]
                        non = f_in.read(12)
                        if len(non) < 12:
                            raise ValueError("Truncated chunk nonce")
                        c_text = f_in.read(c_len)
                        if len(c_text) < c_len:
                            raise ValueError("Truncated chunk ciphertext")
                        p_text = self.aesgcm.decrypt(non, c_text, None)
                        f_out.write(p_text)
        except (InvalidTag, ValueError, struct.error) as e:
            logger.info(f"Falling back to legacy GCM decryption: {e}")
            with open(src_path, "rb") as f_in:
                data = f_in.read()
            if len(data) < 12:
                raise ValueError("Ciphertext too short")
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            with open(dst_path, "wb") as f_out:
                f_out.write(plaintext)


logger = logging.getLogger("clamguard.quarantine")


class QuarantineEntry:
    def __init__(
        self,
        entry_id: int,
        original_path: str,
        quarantine_path: str,
        file_hash: str,
        virus_name: str | None,
        timestamp: datetime,
        encrypted: bool = False,
    ):
        self.id = entry_id
        self.original_path = original_path
        self.quarantine_path = quarantine_path
        self.file_hash = file_hash
        self.virus_name = virus_name
        self.timestamp = timestamp
        self.encrypted = encrypted


class QuarantineManager:
    """Manages quarantined files with integrity verification and optional encryption."""

    def __init__(self, quarantine_dir: str | None = None, db_path: str | None = None):
        self.quarantine_dir = quarantine_dir or paths.app_data_dir("quarantine")
        self.db_path = db_path or paths.app_data_dir("quarantine.db")
        self._cipher = None
        os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.quarantine_dir, 0o700)
        except OSError as e:
            logger.warning(f"Could not set permissions on quarantine dir: {e}")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o600)
        except OSError as e:
            logger.warning(f"Could not set permissions on {self.db_path}: {e}")

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    virus_name TEXT,
                    timestamp REAL,
                    encrypted INTEGER DEFAULT 0,
                    restored INTEGER DEFAULT 0
                )
            """)
            # Salt PBKDF2 casuale, generato una sola volta per installazione
            # e riusato per ogni derivazione successiva (necessario: la
            # stessa password deve produrre sempre la stessa chiave, o i
            # file già in quarantena non sarebbero più decifrabili).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kdf_salt (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt BLOB NOT NULL
                )
            """)

    def _get_or_create_salt(self) -> bytes:
        """Ritorna il salt PBKDF2 di questa installazione, generandolo
        (16 byte casuali via os.urandom) se non esiste ancora.

        SICUREZZA: prima di questo fix il salt era una stringa costante
        hardcoded (b"alpha_quarantine_salt_v1"), identica su ogni
        installazione di ClamGuard. Questo vanifica lo scopo del salt:
        un attaccante può precalcolare UNA rainbow table per quella
        costante e riusarla contro ogni installazione, invece di doverne
        calcolare una per ciascuna. Un salt casuale per-installazione
        elimina questo vantaggio.
        """
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT salt FROM kdf_salt WHERE id=1").fetchone()
            if row:
                return row[0]
            salt = os.urandom(16)
            conn.execute("INSERT INTO kdf_salt (id, salt) VALUES (1, ?)", (salt,))
            return salt

    def set_encryption(self, password: str | None = None, key: bytes | None = None):
        """Enable AES-256-GCM encryption."""
        if key:
            self._cipher = AESGCMCipher(key)
        elif password:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._get_or_create_salt(),
                iterations=480000,
            )
            key = kdf.derive(password.encode())
            self._cipher = AESGCMCipher(key)
        else:
            self._cipher = None

    def quarantine(self, file_path: str, virus_name: str | None = None) -> bool:
        """Move file to quarantine with optional encryption."""
        try:
            src = Path(file_path)
            if not src.exists():
                logger.error(f"File not found: {file_path}")
                return False

            if src.is_symlink() or os.path.islink(file_path):
                logger.error(
                    f"File is a symbolic link, refusing to quarantine: {file_path}"
                )
                return False

            file_hash = paths.compute_file_hash(src)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            q_filename = f"{timestamp}_{src.name}"
            q_path = os.path.join(self.quarantine_dir, q_filename)

            if self._cipher:
                self._cipher.encrypt_file(src, Path(q_path))
                encrypted = True
            else:
                with open(src, "rb") as f_in, open(q_path, "wb") as f_out:
                    while True:
                        chunk = f_in.read(65536)
                        if not chunk:
                            break
                        f_out.write(chunk)
                encrypted = False

            # Sola lettura per il proprietario: isola il file (non scrivibile,
            # non eseguibile) senza impedirne la lettura in fase di restore.
            # La directory di quarantena è già 0o700, quindi resta comunque
            # inaccessibile ad altri utenti.
            os.chmod(q_path, 0o400)

            # Remove original
            src.unlink()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "INSERT INTO quarantine VALUES (NULL, ?, ?, ?, ?, ?, ?, 0)",
                    (
                        str(src),
                        q_path,
                        file_hash,
                        virus_name,
                        datetime.now(timezone.utc).timestamp(),
                        int(encrypted),
                    ),
                )
                entry_id = cursor.lastrowid

            logger.info(f"Quarantined {file_path} as ID {entry_id}")
            return True
        except (OSError, ValueError, sqlite3.Error) as e:
            logger.error(f"Quarantine failed: {e}")
            return False

    def restore(self, entry_id: int, destination: str | None = None) -> bool:
        """Restore file from quarantine after integrity check."""
        dest_path = None
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM quarantine WHERE id=? AND restored=0", (entry_id,)
                ).fetchone()
                if not row:
                    logger.error(
                        f"Quarantine entry {entry_id} not found or already restored"
                    )
                    return False

                original_path, q_path, stored_hash, encrypted = (
                    row[1],
                    row[2],
                    row[3],
                    row[6],
                )
                dest_path = Path(destination or original_path)

                if dest_path.is_symlink() or os.path.islink(str(dest_path)):
                    logger.error(
                        f"Restore target is a symbolic link: {dest_path}. Aborting to prevent symlink traversal."
                    )
                    return False

                os.makedirs(dest_path.parent, exist_ok=True)

                if encrypted:
                    if self._cipher:
                        self._cipher.decrypt_file(Path(q_path), dest_path)
                    else:
                        raise ValueError("No cipher configured for decryption")
                else:
                    with open(q_path, "rb") as f_in, open(dest_path, "wb") as f_out:
                        while True:
                            chunk = f_in.read(65536)
                            if not chunk:
                                break
                            f_out.write(chunk)

                # Set proper permissions
                os.chmod(str(dest_path), 0o644)

                actual_hash = paths.compute_file_hash(dest_path)
                if actual_hash != stored_hash:
                    logger.error(f"Integrity check failed for entry {entry_id}")
                    if dest_path and dest_path.exists():
                        try:
                            os.unlink(dest_path)
                        except OSError:
                            pass
                    return False

                os.unlink(q_path)
                conn.execute("UPDATE quarantine SET restored=1 WHERE id=?", (entry_id,))

            logger.info(f"Restored entry {entry_id} to {dest_path}")
            return True
        except (OSError, ValueError, sqlite3.Error, InvalidTag) as e:
            logger.error(f"Restore failed: {e}")
            if dest_path and dest_path.exists():
                try:
                    os.unlink(dest_path)
                except OSError:
                    pass
            return False

    def delete(self, entry_id: int) -> bool:
        """Permanently delete quarantined file."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT quarantine_path FROM quarantine WHERE id=?", (entry_id,)
                ).fetchone()
                if row and os.path.exists(row[0]):
                    os.unlink(row[0])
                conn.execute("DELETE FROM quarantine WHERE id=?", (entry_id,))
            return True
        except (OSError, ValueError, sqlite3.Error) as e:
            logger.error(f"Delete failed: {e}")
            return False

    def list_entries(self) -> list[QuarantineEntry]:
        """List all active quarantine entries."""
        entries = []
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(
                "SELECT * FROM quarantine WHERE restored=0 ORDER BY timestamp DESC"
            ):
                entries.append(
                    QuarantineEntry(
                        entry_id=row[0],
                        original_path=row[1],
                        quarantine_path=row[2],
                        file_hash=row[3],
                        virus_name=row[4],
                        timestamp=datetime.fromtimestamp(row[5], tz=timezone.utc),
                        encrypted=bool(row[6]),
                    )
                )
        return entries
