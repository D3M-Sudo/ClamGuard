# ClamGuard — Fix Tracker

> **Scopo:** tracciare tutti i fix derivati dalla code review (`clamguard_review_report.md`), il loro stato e le affermazioni del report risultate inaccurate sul codice attuale.
> **Sessione corrente:** Priorità 1–2 (sicurezza + hardening VirusTotal). Fix mirati, senza refactoring architetturale.

---

## Legenda stato

- ✅ **Risolto** — fix implementato e testato
- ⬜ **Da fare** — fix pianificato, non ancora implementato
- 🔲 **Fuori scope** — pianificato ma non in questa sessione
- ➖ **Non applicabile** — affermazione del report non confermata dal codice attuale

---

## Priorità 1 — Sicurezza / Affidabilità (fix bloccanti)

| ID | Modulo | Problema | Stato |
|----|--------|----------|-------|
| CG-001 | `core/quarantine.py` | **TOCTOU:** hash calcolato in lettura separata dai dati criptati. File modificabile tra le due letture → hash DB ≠ dati. | ✅ |
| CG-002 | `core/quarantine.py` | **Perdita dati:** l'INSERT nel DB avviene DOPO `src.unlink()`. Se l'insert fallisce, il file è rimosso dall'originale e la copia in quarantena è orfana (non tracciata, irrecuperabile via UI). | ✅ |
| CG-005 | `core/clamav.py` | **Nessuna validazione path input.** `_expand_to_files` accetta qualsiasi stringa, inclusi symlink a file sensibili. | ✅ |
| CG-014 | `core/quarantine.py` | **Collisione restore:** `restore()` sovrascrive file esistenti senza warning. | ✅ |

## Priorità 2 — Hardening VirusTotal

| ID | Modulo | Problema | Stato |
|----|--------|----------|-------|
| CG-008 | `core/virustotal.py` | **Nessun retry esponenziale** su 503/timeout (il docstring dichiara "exponential backoff" ma non c'è alcun retry). | ✅ |
| CG-009 | `core/virustotal.py` | **Upload senza limite dimensione:** `f.read()` intero file in RAM → OOM su file grandi. | ✅ |
| CG-017 | `core/virustotal.py` | **Nessun TLS hardening:** `requests.Session()` senza `certifi`/`trust_env=False`. | ✅ |

## Priorità 3 — Robustezza scanner / Architettura

| ID | Modulo | Problema | Stato |
|----|--------|----------|-------|
| CG-006 | `core/clamav.py` | Timeout clamd 300s fisso, senza streaming/progress. | 🔲 |
| CG-015 | `core/clamav.py` | Parsing `split(":")` fragile su path con `:`. | 🔲 |
| — | `window.py` | **Refactoring `ScanController`:** estrarre la logica business (scan, quarantena, history) da `window.py` in un `core/scan_controller.py`. `window.py` deve solo ricevere eventi e aggiornare la UI. | 🔲 |

## Priorità 4 — Feature / Qualità

| ID | Modulo | Problema | Stato |
|----|--------|----------|-------|
| CG-012 | `core/quarantine.py` | Nessuna rotazione/quota quarantena (crescita indefinita disco). | 🔲 |
| CG-013 | `core/third_party_db.py` | Nessuna verifica GPG firme terze parti (mitigata parzialmente da `_test_signature` via clamscan). | 🔲 |
| CG-016 | `services/tray_manager.py` | `sys.executable` nel subprocess potrebbe differire in Flatpak. | 🔲 |
| CG-018 | `tests/` | Nessun test EICAR end-to-end. | 🔲 |

---

## Affermazioni del report NON confermate dal codice attuale

Queste voci del report `clamguard_review_report.md` sono risultate **inaccurate** dopo la validazione incrociata col codice sorgente. Non richiedono fix.

| ID | Claim del report | Realtà nel codice |
|----|------------------|-------------------|
| CG-003 | Race condition GTK: `_on_scan_complete()` accede a `_quarantine_list` senza main thread | Tutti i callback che toccano widget passano per `GLib.idle_add()`. Il pattern thread-safe è corretto. Il vero problema è lavoro pesante sincrono sul main thread (`r.compute_hash()` in `_on_scan_complete`), non una race. |
| CG-004 | Nessun lock scan multipli | Il flag `_scan_in_progress` esiste ed è toccato solo sul main thread; tutti gli entry point passano da `start_scan`. Le scansioni concorrenti sono di fatto impedite. Un lock/session ID è hardening, non fix di un bug attivo. |
| CG-007 | Rate limit VT "troppo permissivo" → supera quota 4 req/min | Intervallo fisso 15s = esattamente 4 req/min (limite free tier). Non è una sliding window, ma non è "troppo permissivo". |
| CG-010 | `run_elevated()` blocca la UI per 300s | `run_elevated` è sempre chiamato da thread in background in `window.py`. La UI non si blocca. |
| CG-011 | Progress bar fittizia (pulse) | Non esiste alcuna `Gtk.ProgressBar` nel codice. I bottoni cambiano solo etichetta in "Scanning...". Il problema reale è l'assenza totale di feedback di progresso. |
| CG-019 | i18n assente (hardcoded inglese) | Esiste `po/` con `it.po`, `LINGUAS`, `meson.build`, `POTFILES.in`. L'i18n è configurata. |
| CG-020 | View VirusTotal e Settings sono placeholder | Entrambe sono implementate con funzionalità reali (`window.py` righe 950–1073 e 1227–1336). |
| — | Struttura: esiste `app.py` | Non esiste `app.py`; la `Gio.Application` è in `main.py` (`ClamGuardApplication`). Il report omette anche `cli/`, `core/freshclam.py` e `ui/`. |

---

## Note di sessione

- **Approccio:** fix mirati, adattati all'architettura asyncio già presente in ClamGuard. Spunti da ClamUI solo dove utile.
- **Refactoring `ScanController`:** suggerito dal report (Priorità 3) ma **fuori scope** in questa sessione per scelta dell'utente. Tracciato sopra come backlog.
- **Test:** i fix alle Priorità 1–2 aggiornano `tests/test_quarantine.py`, `tests/test_virustotal.py`, `tests/test_clamav_parser.py`.