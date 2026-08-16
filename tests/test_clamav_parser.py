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
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.txt"), "w").close()
            sub = os.path.join(d, "sub")
            os.mkdir(sub)
            open(os.path.join(sub, "b.txt"), "w").close()
            open(os.path.join(sub, "evil.exe"), "w").close()

            fake_stdout = (
                f"{d}/a.txt: OK\n"
                f"{sub}/b.txt: OK\n"
                f"{sub}/evil.exe: Eicar-Test-Signature FOUND\n"
            ).encode()

            class FakeProc:
                async def communicate(self):
                    return (fake_stdout, b"")

            async def fake_create_subprocess_exec(*_args, **_kwargs):
                return FakeProc()

            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=fake_create_subprocess_exec,
            ):
                results = asyncio.run(scanner._scan_clamscan([d], None))

        # Prima del fix: len(results) == 1 (un solo ScanResult fittizio per
        # la cartella, perché nessun risultato parsato ha path == cartella).
        self.assertEqual(len(results), 3)
        infected = [r for r in results if r.infected]
        self.assertEqual(len(infected), 1)
        self.assertTrue(infected[0].path.endswith("evil.exe"))


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

        with tempfile.NamedTemporaryFile() as f, patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            asyncio.run(scanner._scan_clamscan([f.name], None))

        self.assertNotIn("--infected", captured_cmd["cmd"])


class TestScanClamscanSkipsEmptyExtraDbDir(unittest.TestCase):
    """Regressione: clamscan fa fallire l'INTERO comando (nessun file
    scansionato per nessun path, non solo per quella firma) se una
    cartella passata con --database esiste ma non contiene alcuna firma —
    condizione garantita su ogni installazione pulita, prima che l'utente
    scarichi le prime firme di terze parti. Verifichiamo che una cartella
    extra_db_dirs vuota NON venga passata a --database."""

    def test_empty_extra_db_dir_is_not_passed_to_clamscan(self):
        with tempfile.TemporaryDirectory() as empty_dir, tempfile.NamedTemporaryFile() as f:
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
                asyncio.run(scanner._scan_clamscan([f.name], None))

            self.assertNotIn("--database", captured_cmd["cmd"])

    def test_nonempty_extra_db_dir_is_passed_to_clamscan(self):
        with tempfile.TemporaryDirectory() as db_dir, tempfile.NamedTemporaryFile() as f:
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
                asyncio.run(scanner._scan_clamscan([f.name], None))

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

        with tempfile.NamedTemporaryFile() as f, patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            asyncio.run(scanner._scan_clamscan([f.name], None))

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
            reader.readline.side_effect = [b"stream: OK\n"]
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
            written_bytes = b"".join(
                call.args[0] for call in writer.write.call_args_list
            )
            self.assertTrue(written_bytes.startswith(b"nINSTREAM\n"))
            self.assertTrue(written_bytes.endswith(b"\x00\x00\x00\x00"))
            # Total size should be header + 2 chunk lengths (4 bytes each) + 100000 bytes + 4 bytes EOF
            self.assertEqual(
                len(written_bytes),
                len(b"nINSTREAM\n") + 4 + 65536 + 4 + (100000 - 65536) + 4,
            )
        finally:
            os.unlink(temp_path)


class TestScanClamdPassesCorrectArgToExpand(unittest.TestCase):
    """Regressione: _scan_clamd chiamava self._expand_to_files(paths) dove
    "paths" risolveva al MODULO importato (`from . import paths`), non al
    parametro della funzione (chiamato scan_paths) — perché entrambi
    condividono lo stesso identificatore "paths" nello scope del modulo.
    A runtime questo solleva TypeError ("module object is not iterable")
    non appena si tenta di iterarci dentro _expand_to_files, interrompendo
    ogni scansione che usa clamd. Il test di regressione precedente
    (TestScanClamdOneCommandPerFile) non lo intercettava perché mockava
    _expand_to_files con un return_value fisso, senza verificare
    l'argomento ricevuto. Qui verifichiamo esplicitamente che riceva la
    lista di path passata alla funzione, non il modulo."""

    def test_expand_to_files_receives_the_scan_paths_argument(self):
        scanner = ClamAVScanner()
        received_args = []

        def fake_expand(paths_arg):
            received_args.append(paths_arg)
            return []

        with patch.object(ClamAVScanner, "_expand_to_files", side_effect=fake_expand):
            asyncio.run(scanner._scan_clamd(["/tmp/scandir", "/tmp/other"]))

        self.assertEqual(len(received_args), 1)
        # Prima del fix, "paths_arg" sarebbe stato il modulo
        # src.core.paths (non iterabile / non confrontabile a una lista).
        self.assertEqual(received_args[0], ["/tmp/scandir", "/tmp/other"])


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


class TestScanClamscanSkipsOversizedFiles(unittest.TestCase):
    """QA #2 (critico): clamscan, in modalità normale (non --debug),
    stampa "<path>: OK" in modo identico sia per un file davvero
    scansionato sia per uno scartato internamente perché troppo grande
    (default clamscan ~200MB) — verificato empiricamente con
    `clamscan --debug`, che mostra "File too large (...), ignoring" solo
    in quella modalità estremamente verbosa, mai in output normale.
    Verifichiamo che un file oltre MAX_SCAN_FILE_SIZE non venga nemmeno
    passato a clamscan, e risulti nei risultati come skipped=True."""

    def test_oversized_file_is_excluded_and_marked_skipped(self):
        scanner = ClamAVScanner()
        scanner.MAX_SCAN_FILE_SIZE = (
            1024  # 1 KiB, per non creare file veri enormi nel test
        )
        captured_cmd = {}

        class FakeProc:
            async def communicate(self):
                return (b"", b"")

        async def fake_create_subprocess_exec(*args, **_kwargs):
            captured_cmd["cmd"] = args
            return FakeProc()

        with tempfile.TemporaryDirectory() as d:
            small = os.path.join(d, "small.txt")
            with open(small, "wb") as f:
                f.write(b"x" * 100)
            big = os.path.join(d, "big.bin")
            with open(big, "wb") as f:
                f.write(b"x" * 2048)

            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=fake_create_subprocess_exec,
            ):
                results = asyncio.run(scanner._scan_clamscan([d], None))

        skipped = [r for r in results if r.skipped]
        self.assertEqual(len(skipped), 1)
        self.assertTrue(skipped[0].path.endswith("big.bin"))
        self.assertIn("exceeds", skipped[0].error)
        # Il file grande non deve MAI raggiungere clamscan: solo il file
        # piccolo va passato come argomento del comando.
        self.assertNotIn(big, captured_cmd["cmd"])
        self.assertIn(small, captured_cmd["cmd"])

    def test_max_filesize_flag_passed_to_clamscan(self):
        scanner = ClamAVScanner()
        captured_cmd = {}

        class FakeProc:
            async def communicate(self):
                return (b"", b"")

        async def fake_create_subprocess_exec(*args, **_kwargs):
            captured_cmd["cmd"] = args
            return FakeProc()

        with tempfile.NamedTemporaryFile() as f, patch(
            "asyncio.create_subprocess_exec",
            side_effect=fake_create_subprocess_exec,
        ):
            asyncio.run(scanner._scan_clamscan([f.name], None))

        max_mb = scanner.MAX_SCAN_FILE_SIZE // (1024 * 1024)
        self.assertIn(f"--max-filesize={max_mb}M", captured_cmd["cmd"])
        self.assertIn(f"--max-scansize={max_mb}M", captured_cmd["cmd"])


class TestParseClamscanAccessDenied(unittest.TestCase):
    """QA #5 (alto): un file senza permessi di lettura produceva una riga
    "<path>: Access denied" nell'output di clamscan, non riconosciuta da
    nessuno dei rami del parser (FOUND / OK / ERROR) e quindi scartata
    silenziosamente — il file spariva del tutto dai risultati, senza
    alcuna indicazione per l'utente. Verifichiamo che venga ora
    riconosciuto e riportato come skipped, non semplicemente ignorato."""

    def test_access_denied_line_is_captured_not_dropped(self):
        scanner = ClamAVScanner()
        output = (
            "/home/user/readable.txt: OK\n" "/home/user/noperm.txt: Access denied\n"
        )
        results = scanner._parse_clamscan_output(output)

        self.assertEqual(len(results), 2)
        denied = [r for r in results if "noperm.txt" in r.path]
        self.assertEqual(len(denied), 1)
        self.assertTrue(denied[0].skipped)
        self.assertIn("Access denied", denied[0].error)


class TestPathValidation(unittest.TestCase):
    """CG-005: _expand_to_files deve validare i path di input prima di
    qualsiasi operazione. Prima del fix accettava qualsiasi stringa,
    inclusi symlink a file sensibili (es. /etc/shadow) o path con
    traversal."""

    def test_symlink_to_sensitive_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "shadow_link")
            os.symlink("/etc/shadow", link)
            files = ClamAVScanner._expand_to_files([link])
            self.assertEqual(files, [])

    def test_path_traversal_is_rejected(self):
        files = ClamAVScanner._expand_to_files(["/tmp/../etc/shadow"])
        self.assertEqual(files, [])

    def test_relative_path_is_rejected(self):
        files = ClamAVScanner._expand_to_files(["relative/path"])
        self.assertEqual(files, [])

    def test_nonexistent_path_is_rejected(self):
        files = ClamAVScanner._expand_to_files(["/nonexistent/definitely/not/here"])
        self.assertEqual(files, [])

    def test_valid_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.txt"), "w").close()
            files = ClamAVScanner._expand_to_files([d])
            self.assertEqual(files, [os.path.join(d, "a.txt")])


class TestPreferClamdSetting(unittest.TestCase):
    """QA #4 (alto): lo switch 'Use clamd daemon' in Settings era
    collegato a GSettings ma il valore non veniva mai letto da nessuna
    parte del codice — ClamAVScanner._use_clamd si autodeterminava
    sempre via _detect_clamd(), rendendo lo switch puramente decorativo.
    Verifichiamo che prefer_clamd=False forzi clamscan anche quando
    clamd sarebbe altrimenti disponibile, e che prefer_clamd non possa
    MAI forzare clamd ON se i controlli di sicurezza di _detect_clamd()
    falliscono (nessun socket reale disponibile)."""

    def test_prefer_clamd_false_forces_clamscan_even_if_available(self):
        scanner = ClamAVScanner(prefer_clamd=False)
        scanner._clamd_available = True  # simula clamd realmente disponibile
        self.assertFalse(scanner._use_clamd)

    def test_prefer_clamd_true_does_not_override_safety_checks(self):
        scanner = ClamAVScanner(prefer_clamd=True)
        scanner._clamd_available = False  # nessun socket sicuro trovato
        self.assertFalse(scanner._use_clamd)

    def test_prefer_clamd_is_live_not_cached_at_construction(self):
        scanner = ClamAVScanner(prefer_clamd=True)
        scanner._clamd_available = True
        self.assertTrue(scanner._use_clamd)

        # Simula il toggle dello switch a runtime (window.py aggiorna
        # scanner.prefer_clamd su notify::active): deve avere effetto
        # immediato, senza richiedere di ricreare lo ClamAVScanner.
        scanner.prefer_clamd = False
        self.assertFalse(scanner._use_clamd)


if __name__ == "__main__":
    unittest.main()
