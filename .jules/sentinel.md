# Security Sentinel Journal

This journal documents critical, repository-specific security vulnerabilities, learnings, and prevention methods for ClamGuard.

## 2026-08-11 - CSV Formula Injection Prevention in Scan History Exports
**Vulnerability:** The scan history CSV export feature allowed user-controlled scan targets (such as file or directory paths containing formula injection characters like `=`, `+`, `-`, `@`, `\t`, or `\r`) to be written directly into the generated CSV file. This could lead to CSV Formula Injection (CWE-1236), executing arbitrary commands or formulas on the system of any administrator or user opening the exported spreadsheet.
**Learning:** Even internal metadata (like file paths or target directory names) must be sanitized before exporting to public formats like CSV, as those strings might contain user-controllable or attacker-crafted names that spreadsheet applications interpret as executable expressions.
**Prevention:** Always sanitize all string fields written to CSV exports by prepending a single quote (`'`) to any cell value that starts with formula characters (`=`, `+`, `-`, `@`, `\t`, `\r`).

## 2026-08-10 - Secure Database and Cache Hardening
**Vulnerability:** Core application databases (including SQLite databases for history, quarantine metadata, VirusTotal cache, and third-party databases) were created using default system umask permissions (often 0o644 or 0o755), allowing local non-owner users to read sensitive scan histories, threat metadata, and cached VirusTotal analysis reports. Additionally, the VirusTotal cache was configured to default to root-only paths (`/var/lib/clamguard`), which causes runtime PermissionError crashes for zero-privilege user-space environments (such as Flatpak sandboxes).
**Learning:** For desktop applications operating under a zero-privilege or sandboxed model, local files containing sensitive metadata (such as scan logs, encryption salts, and cached external API reports) must reside inside user-writable directories (e.g. XDG app data) and have their file permissions explicitly hardened to owner-only access (`0o600`) right after initialization.
**Prevention:** Always use XDG base directory specification helpers to locate application databases and secure created files explicitly using standard file permission controls (e.g., `os.chmod(db_path, 0o600)`) within defensive `try-except` blocks.

## 1. Subprocess & Command Injection (CWE-78, CWE-88)
- **Vulnerability**: Command injection could occur if user-controllable input (such as scanned file paths or malicious directories) is passed without isolating boundaries to the CLI.
- **Prevention**: Always pass arguments as lists of strings and use the `--` delimiter to separate CLI options from paths (e.g. `["clamscan", "--no-summary", "--", file_path]`).

## 2. UNIX Socket & clamd Integration (CWE-732, CWE-20)
- **Vulnerability**: File scans can fail with Permission Denied when accessing user home folders (0700 permissions) since `clamd` runs as `clamav`.
- **Prevention**: Implement automatic fallback to `INSTREAM` chunk-streaming protocol if socket errors or permission denials are detected. Pack stream chunks with a big-endian 4-byte unsigned length in network byte order, terminated with a zero-length chunk (`00 00 00 00`). Always enforce explicit connect and read timeouts (e.g. via `asyncio.wait_for`) to avoid denial of service (DoS).

## 3. Cryptography & Quarantine Isolation (CWE-327, CWE-59)
- **Vulnerability**: Using `Fernet` (AES-128-CBC) lacks modern authenticated decryption schemes if not validated carefully. Symlink traversal could overwrite critical system files during recovery/quarantine.
- **Prevention**: Upgrade to `AES-256-GCM` via `AESGCM` with random 12-byte nonces. Enforce validation of the Auth Tag (MAC) in memory prior to completing file writes. Restrict access permissions of the quarantine directory to `0o700` and quarantine database files to `0o600`. Perform explicit symbolic link checks (`Path.is_symlink()`) to prevent arbitrary file moves or recovery traversals.

## 4. UI Concurrency & Thread Safety (CWE-362)
- **Vulnerability**: Updating GTK4 widgets from secondary/background threads can lead to thread safety issues, GUI freezes, or memory corruption.
- **Prevention**: Wrap all GUI-bound updates from threads inside `GLib.idle_add(...)` and ensure that the callback returns `False` to prevent repeated scheduling in the main loop.
