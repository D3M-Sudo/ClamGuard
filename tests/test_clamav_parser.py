#!/usr/bin/env python3
import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.clamav import ClamAVScanner


class TestClamAVParser(unittest.TestCase):
    def test_parse_clamd_response_found(self):
        scanner = ClamAVScanner()
        r = scanner._parse_clamd_response(
            "/tmp/eicar", "stream: Eicar-Test-Signature FOUND"
        )
        self.assertTrue(r.infected)
        self.assertEqual(r.virus_name, "Eicar-Test-Signature")

    def test_parse_clamd_response_ok(self):
        scanner = ClamAVScanner()
        r = scanner._parse_clamd_response("/tmp/clean", "/tmp/clean: OK")
        self.assertFalse(r.infected)

    def test_clamscan_fallback_has_chunk_size_default(self):
        """Regressione: _scan_clamd() richiama _scan_clamscan(paths,
        progress_callback) SENZA chunk_size quando clamd fallisce a metà
        scansione. Prima del fix, chunk_size non aveva un valore di
        default: quel fallback avrebbe sollevato TypeError esattamente
        nel momento in cui serve di più (clamd già fallito). Verifichiamo
        che la chiamata usata realmente dal fallback sia vincolabile.
        """
        import inspect

        sig = inspect.signature(ClamAVScanner._scan_clamscan)
        # Chiamata esatta usata dal fallback in _scan_clamd (self, paths, progress_callback)
        sig.bind(
            None, ["/tmp/x"], None
        )  # solleva TypeError se chunk_size non ha default


class TestScanClamscanUsesRealResults(unittest.TestCase):
    """Regressione: _scan_clamscan scartava tutti i risultati parsati da
    clamscan e li rimpiazzava con un unico ScanResult fittizio per ogni
    cartella di input (facendo apparire "1 file scansionato" a prescindere
    dal contenuto reale, e perdendo silenziosamente eventuali minacce
    trovate). Verifichiamo che i risultati reali, uno per file, arrivino
    intatti al chiamante."""

    def test_returns_one_result_per_file_not_per_input_path(self):
        scanner = ClamAVScanner()
        fake_stdout = (
            b"/home/user/a.txt: OK\n"
            b"/home/user/sub/b.txt: OK\n"
            b"/home/user/sub/evil.exe: Eicar-Test-Signature FOUND\n"
        )

        class FakeProc:
            async def communicate(self):
                return (fake_stdout, b"")

        async def fake_create_subprocess_exec(*_args, **_kwargs):
            return FakeProc()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            results = asyncio.run(scanner._scan_clamscan(["/home/user"], None))

        # Prima del fix: len(results) == 1 (un solo ScanResult fittizio per
        # "/home/user", perché nessun risultato parsato ha path == "/home/user").
        self.assertEqual(len(results), 3)
        infected = [r for r in results if r.infected]
        self.assertEqual(len(infected), 1)
        self.assertEqual(infected[0].path, "/home/user/sub/evil.exe")


class TestExpandToFiles(unittest.TestCase):
    """_expand_to_files deve camminare ricorsivamente le cartelle passate
    e restituire i file reali, così che ogni comando clamd SCAN inviato
    corrisponda esattamente a un file (una risposta attesa per comando)."""

    def test_expands_directory_recursively(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.txt"), "w").close()
            sub = os.path.join(d, "sub")
            os.mkdir(sub)
            open(os.path.join(sub, "b.txt"), "w").close()

            files = ClamAVScanner._expand_to_files([d])

            self.assertEqual(
                sorted(files),
                sorted(
                    [
                        os.path.join(d, "a.txt"),
                        os.path.join(sub, "b.txt"),
                    ]
                ),
            )

    def test_single_file_passthrough(self):
        with tempfile.NamedTemporaryFile() as f:
            files = ClamAVScanner._expand_to_files([f.name])
            self.assertEqual(files, [f.name])


class TestScanClamscanCountsCleanFiles(unittest.TestCase):
    """Regressione: il comando clamscan veniva invocato con --infected, che
    stampa una riga SOLO per i file infetti o in errore. I file puliti non
    producevano alcuna riga di output e sparivano dal conteggio "Files
    scanned". Verifichiamo che il comando NON usi --infected, cosicché
    anche i file puliti vengano contati."""

    def test_clamscan_command_does_not_use_infected_flag(self):
        scanner = ClamAVScanner()
        captured_cmd = {}

        class FakeProc:
            async def communicate(self):
                return (b"", b"")

        async def fake_create_subprocess_exec(*args, **_kwargs):
            captured_cmd["cmd"] = args
            return FakeProc()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            asyncio.run(scanner._scan_clamscan(["/tmp/x"], None))

        self.assertNotIn("--infected", captured_cmd["cmd"])


class TestScanClamscanSkipsEmptyExtraDbDir(unittest.TestCase):
    """Regressione: clamscan fa fallire l'INTERO comando (nessun file
    scansionato per nessun path, non solo per quella firma) se una
    cartella passata con --database esiste ma non contiene alcuna firma —
    condizione garantita su ogni installazione pulita, prima che l'utente
    scarichi le prime firme di terze parti. Verifichiamo che una cartella
    extra_db_dirs vuota NON venga passata a --database."""

    def test_empty_extra_db_dir_is_not_passed_to_clamscan(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            scanner = ClamAVScanner(extra_db_dirs=[empty_dir])
            captured_cmd = {}

            class FakeProc:
                async def communicate(self):
                    return (b"", b"")

            async def fake_create_subprocess_exec(*args, **_kwargs):
                captured_cmd["cmd"] = args
                return FakeProc()

            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=fake_create_subprocess_exec,
            ):
                asyncio.run(scanner._scan_clamscan(["/tmp/x"], None))

            self.assertNotIn("--database", captured_cmd["cmd"])

    def test_nonempty_extra_db_dir_is_passed_to_clamscan(self):
        with tempfile.TemporaryDirectory() as db_dir:
            open(os.path.join(db_dir, "sig.ndb"), "w").close()
            scanner = ClamAVScanner(extra_db_dirs=[db_dir])
            captured_cmd = {}

            class FakeProc:
                async def communicate(self):
                    return (b"", b"")

            async def fake_create_subprocess_exec(*args, **_kwargs):
                captured_cmd["cmd"] = args
                return FakeProc()

            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=fake_create_subprocess_exec,
            ):
                asyncio.run(scanner._scan_clamscan(["/tmp/x"], None))

            self.assertIn("--database", captured_cmd["cmd"])
            self.assertIn(db_dir, captured_cmd["cmd"])


class TestScanClamscanIsRecursive(unittest.TestCase):
    """Regressione: clamscan di default NON scende nelle sottocartelle
    (serve --recursive). Senza questo flag venivano scansionati solo i
    file presenti direttamente nella cartella scelta dall'utente,
    ignorando silenziosamente ogni file più in profondità. Verifichiamo
    che il comando includa --recursive."""

    def test_clamscan_command_uses_recursive_flag(self):
        scanner = ClamAVScanner()
        captured_cmd = {}

        class FakeProc:
            async def communicate(self):
                return (b"", b"")

        async def fake_create_subprocess_exec(*args, **_kwargs):
            captured_cmd["cmd"] = args
            return FakeProc()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            asyncio.run(scanner._scan_clamscan(["/tmp/x"], None))

        self.assertIn("--recursive", captured_cmd["cmd"])


class TestScanClamdInstreamStreaming(unittest.TestCase):
    """Verifichiamo che _scan_file_instream funzioni correttamente con il
    nuovo meccanismo di streaming asincrono chunk-by-chunk e che trasmetta i chunk."""

    def test_instream_streams_chunks_correctly(self):
        scanner = ClamAVScanner()

        # Prepariamo un file di test con contenuto noto
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"A" * 100000)  # > 65536 byte, quindi si divide in 2 chunk
            temp_path = f.name

        try:
            reader = AsyncMock()
            reader.readline.side_effect = [
                b"stream: OK\n"
            ]
            writer = MagicMock()
            writer.write = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()

            async def fake_open_unix_connection(_path):
                return reader, writer

            with patch(
                "asyncio.open_unix_connection",
                side_effect=fake_open_unix_connection,
            ):
                result = asyncio.run(scanner._scan_file_instream(temp_path))

            self.assertFalse(result.infected)
            self.assertIsNone(result.error)

            # Verifichiamo che i chunk siano stati scritti
            # Dovremmo avere:
            # 1. nINSTREAM\n
            # 2. Primo chunk (>I length + data)
            # 3. Secondo chunk (>I length + data)
            # 4. Zero-length chunk termination (00 00 00 00)
            written_bytes = b"".join(call.args[0] for call in writer.write.call_args_list)
            self.assertTrue(written_bytes.startswith(b"nINSTREAM\n"))
            self.assertTrue(written_bytes.endswith(b"\x00\x00\x00\x00"))
            # Total size should be header + 2 chunk lengths (4 bytes each) + 100000 bytes + 4 bytes EOF
            self.assertEqual(len(written_bytes), len(b"nINSTREAM\n") + 4 + 65536 + 4 + (100000 - 65536) + 4)
        finally:
            os.unlink(temp_path)


class TestScanClamdOneCommandPerFile(unittest.TestCase):
    """Regressione: _scan_clamd inviava un comando SCAN per ogni path di
    input (spesso una cartella) leggendo una sola riga di risposta, mentre
    clamd può rispondere con più righe per una directory — causando sia il
    sottoconteggio dei file scansionati sia un possibile disallineamento
    del protocollo tra una directory e la successiva. Verifichiamo che ora
    venga inviato un comando SCAN per ciascun file reale, non per cartella."""

    def test_sends_one_scan_command_per_real_file(self):
        scanner = ClamAVScanner()

        reader = AsyncMock()
        reader.readline.side_effect = [
            b"/tmp/scandir/a.txt: OK\n",
            b"/tmp/scandir/b.txt: OK\n",
        ]
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        async def fake_open_unix_connection(_path):
            return reader, writer

        with (
            patch(
                "asyncio.open_unix_connection",
                side_effect=fake_open_unix_connection,
            ),
            patch.object(
                ClamAVScanner,
                "_expand_to_files",
                return_value=["/tmp/scandir/a.txt", "/tmp/scandir/b.txt"],
            ),
        ):
            results = asyncio.run(scanner._scan_clamd(["/tmp/scandir"]))

        # Prima del fix: un solo comando SCAN per "/tmp/scandir" e una sola
        # readline(), quindi un solo ScanResult indipendentemente dal
        # numero di file reali nella cartella.
        self.assertEqual(writer.write.call_count, 2)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
