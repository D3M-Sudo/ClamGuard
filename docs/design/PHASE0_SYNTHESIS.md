
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
4. **VirusTotal API v3** — Integrazione diretta via `requests` (API v3), rate-limit aware,
   supporta lookup hash, upload opzionale, environment key.
5. **Flatpak Security** — Evitare `filesystem=host`, usare portali, conditional permissions,
   `--persist` per config, minimizzare D-Bus.

## Miglioramenti Chiave Proposti per ClamGuard
1. **Dashboard Bitdefender-Style**: Header con status badge colorato (Verde/Giallo/Rosso) che 
   riassume in un colpo d'occhio lo stato di protezione. Card rapide ad azione in stile Adwaita 
   con icone grandi e titoli bold, non liste semplici.
2. **Daemon Firme Terze Integrato**: Non solo wrapper di Fangfrisch, ma daemon Python dedicato
   con SQLite state, download parallelo, verifica SHA256/MD5 per ogni provider, rollback atomico
   su fallimento test clamscan.
3. **Quarantena con Cifratura Opzionale**: Oltre a SHA-256 + chmod 000, supporto a cifratura
   AES-256-GCM via `cryptography`, chiave derivata da SecretService o passphrase utente.
4. **Flatpak Hardening Avanzato**: Manifest con permessi minimi, uso di `org.freedesktop.Flatpak`
   spawn per operazioni host (clamscan), portali per file picker, `--persist=.config/clamguard`.
5. **System Tray Dual-Mode**: Supporto nativo StatusNotifierItem (KDE/GNOME) + XApp.StatusIcon
   (Cinnamon/MATE) con fallback GTK4, indicatori live di protezione.
6. **Async I/O su clamd socket**: Parsing ad alte prestazioni dell'output clamdscan via asyncio
   streams, evitando blocchi UI su scansioni di grandi directory.
7. **VirusTotal v3 con Cache Locale**: Lookup hash con cache SQLite locale per ridurre chiamate API,
   rispettando rate limit con exponential backoff.

## Stato di Implementazione

La sintesi sopra descrive la ricerca condotta prima dell'inizio dello sviluppo (Fase 0). Di seguito
la mappatura verso il codice attuale, aggiornata dopo il giro di bug-fix e la stabilizzazione della
pipeline CI/build:

| Proposta | Stato | Riferimento nel codice |
|---|---|---|
| Dashboard Bitdefender-style | Implementato | `src/window.py`, `src/ui/views` |
| Daemon firme terze con stato SQLite | Implementato | `src/core/third_party_db.py`, `src/daemon/updater_daemon.py` |
| Quarantena con cifratura opzionale (AES-256-GCM/Fernet) | Implementato | `src/core/quarantine.py` |
| Flatpak hardening (permessi minimi, portali, `--persist`) | Implementato | `build-aux/flatpak/io.github.d3msudo.clamguard.json` |
| System tray dual-mode | Implementato | `src/services/tray_manager.py`, `src/services/tray_service.py` |
| Async I/O su clamd socket | Implementato | `src/core/clamav.py` |
| VirusTotal v3 con cache locale | Implementato | `src/core/virustotal.py` |
| Binari CLI (`clamguard`, `clamguard-daemon`) generati dal build | Implementato (fix successivo) | `src/clamguard.in`, `src/clamguard-daemon.in`, `src/meson.build` |
| Installazione privilegiata firme terze via Polkit | Implementato | `src/core/privileged_paths.py`, `src/cli/install_helper.py`, `src/services/polkit.py` |

Nota: i binari `clamguard` e `clamguard-daemon` (invocati dagli unit systemd in `data/systemd/`) non
venivano prodotti dal build originario, lasciando gli unit systemd e la voce `Exec=` del `.desktop`
non funzionanti. Il problema è stato individuato e risolto nel giro di bug-fix più recente; vedi i
commenti in testa a `src/clamguard.in` e `src/clamguard-daemon.in` per il dettaglio.
