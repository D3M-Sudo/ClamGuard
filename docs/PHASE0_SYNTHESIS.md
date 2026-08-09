
# FASE 0 — Sintesi Ricerca e Affinamenti Architetturali

## Progetti Analizzati
1. **ClamUI** (linx-systems/clamui) — GUI GTK4/libadwaita per ClamAV con quarantena hash-verified,
   scan profiles, system audit, VirusTotal opt-in, Flatpak/.deb. Pattern UI moderno ma non 
   esplicitamente "dashboard" con status badge prominente.
2. **Fangfrisch** (rseichter/fangfrisch) — Downloader firme terze con verifica digest, intervalli
   configurabili, esecuzione non privilegiata, on_update_exec per test integrità clamscan.
3. **clamav-unofficial-sigs** (extremeshok) — Script bash completo per firme Sanesecurity,
   SecuriteInfo, URLhaus, MalwarePatrol, ditekshen, twinclams, interServer, RFXN. Test HAM,
   whitelist IGN2, GPG verify.
4. **VirusTotal API v3** — Client ufficiale Python `virustotal-python`, rate-limit aware,
   supporta lookup hash, upload opzionale, environment key.
5. **Flatpak Security** — Evitare `filesystem=host`, usare portali, conditional permissions,
   `--persist` per config, minimizzare D-Bus.

## Miglioramenti Chiave Proposti per Alpha
1. **Dashboard Bitdefender-Style**: Header con status badge colorato (Verde/Giallo/Rosso) che 
   riassume in un colpo d'occhio lo stato di protezione. Card rapide ad azione in stile Adwaita 
   con icone grandi e titoli bold, non liste semplici.
2. **Daemon Firme Terze Integrato**: Non solo wrapper di Fangfrisch, ma daemon Python dedicato
   con SQLite state, download parallelo, verifica SHA256/MD5 per ogni provider, rollback atomico
   su fallimento test clamscan.
3. **Quarantena con Cifratura Opzionale**: Oltre a SHA-256 + chmod 000, supporto a cifratura
   AES-256-GCM via `cryptography`, chiave derivata da SecretService o passphrase utente.
4. **Flatpak Hardening Avanzato**: Manifest con permessi minimi, uso di `org.freedesktop.Flatpak`
   spawn per operazioni host (clamscan), portali per file picker, `--persist=.config/alpha`.
5. **System Tray Dual-Mode**: Supporto nativo StatusNotifierItem (KDE/GNOME) + XApp.StatusIcon
   (Cinnamon/MATE) con fallback GTK4, indicatori live di protezione.
6. **Async I/O su clamd socket**: Parsing ad alte prestazioni dell'output clamdscan via asyncio
   streams, evitando blocchi UI su scansioni di grandi directory.
7. **VirusTotal v3 con Cache Locale**: Lookup hash con cache SQLite locale per ridurre chiamate API,
   rispettando rate limit con exponential backoff.
