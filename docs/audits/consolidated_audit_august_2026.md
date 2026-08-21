# Audit Consolidato — Agosto 2026

Questo documento unisce e consolida le relazioni dei cinque audit tecnici eseguiti a metà agosto 2026 relativi alla stabilità, robustezza della pipeline di scansione, icone, implementazione di VirusTotal/Settings e analisi statica complessiva dell'applicazione ClamGuard.

---

## Indice
1. [Audit 1 — Pipeline di Scansione (11-08-2026)](#audit-1--pipeline-di-scansione-11-08-2026)
2. [Audit 2 — Stato della Dashboard (11-08-2026)](#audit-2--stato-della-dashboard-11-08-2026)
3. [Audit 3 — Icone Rotte e Crash di Avvio (12-08-2026)](#audit-3--icone-rotte-e-crash-di-avvio-12-08-2026)
4. [Audit 4 — Implementazione Viste VirusTotal e Settings (12-08-2026)](#audit-4--implementazione-viste-virustotal-e-settings-12-08-2026)
5. [Audit 5 — QA Audit: Build, Dynamic Testing & Static Analysis (13-08-2026)](#audit-5--qa-audit-build-dynamic-testing--static-analysis-13-08-2026)

---

## Audit 1 — Pipeline di Scansione (11-08-2026)

* **Modulo analizzato:** `src/core/clamav.py`

### Metodo di test
L'app è stata compilata e installata realmente (build meson, non un mock), eseguita sotto Xvfb con clamd/clamscan reali, e pilotata a click come un utente. I bug qui descritti sono stati prima osservati empiricamente (risultati sbagliati in cronologia scansioni), poi confermati leggendo il codice, poi corretti, poi rivalidati con:
* Invocazione diretta di `ClamAVScanner.scan_paths()` su cartelle reali, confrontando `len(risultati)` col conteggio reale (`find -type f | wc -l`);
* Una firma ClamAV di test creata ad-hoc (database `.hdb` locale) per verificare che un file infetto venga davvero rilevato e non perso;
* L'intera suite di test automatici (`pytest tests/`), più 8 nuovi test di regressione, uno per ciascun bug qui sotto.

Sono stati trovati **4 bug distinti** che si sommano tra loro: correggerne solo alcuni avrebbe lasciato la scansione ancora rotta.

### Bug Individuati e Corretti

#### Bug 1 — Risultati reali scartati e rimpiazzati con un placeholder
* **Sintomo:** Qualunque cartella scansionata, la cronologia riportava sempre "1 files, 0 threats", indipendentemente dal contenuto reale.
* **Causa:** `clamscan` produce già una riga di output corretta per ogni file scansionato (`_parse_clamscan_output` la parsava già bene). Il bug era nel passo successivo: il codice cercava, per ogni *cartella* di input, un risultato il cui `path` combaciasse esattamente con la stringa della cartella stessa — cosa che non può mai accadere, dato che i risultati parlano di file (`/home/utente/file.txt`), non di cartelle (`/home`). Il match falliva sempre, e veniva creato un unico `ScanResult` finto e pulito al posto di tutti i risultati reali (comprese eventuali minacce trovate in profondità, silenziosamente perse).
* **Fix:** Usare direttamente i risultati parsati (`results.extend(...)`) invece di rimapparli sui path di input.

#### Bug 2 — `--infected` nascondeva i file puliti dal conteggio
* **Sintomo:** Anche dopo il fix del Bug 1, il conteggio restava sbagliato (sottostimato di quasi tutto).
* **Causa:** Il flag `--infected` passato a `clamscan` fa sì che vengano stampate **solo** le righe dei file infetti o in errore: i file puliti non producono alcuna riga di output e quindi non vengono mai conteggiati come "scansionati".
* **Fix:** Rimosso `--infected`. Senza quel flag, clamscan stampa anche `<path>: OK` per ogni file pulito.

#### Bug 3 — clamscan non scansiona le sottocartelle di default
* **Sintomo:** Il più grave dei quattro. Verificato con un confronto diretto:
  ```bash
  find src/ tests/ -type f | wc -l          → 64 file reali
  clamscan --no-summary --stdout src tests  → 13 righe di output
  clamscan --recursive ... src tests        → 64 righe di output
  ```
  `clamscan`, di suo, **non scende nelle sottocartelle** a meno di passare esplicitamente `-r`/`--recursive`. Senza questo flag, ogni scansione (Quick Scan, Custom Scan, System Scan) esaminava solo i file presenti *direttamente* nella cartella scelta, ignorando silenziosamente tutto il resto — cioè, nella pratica, quasi tutti i file reali di un utente.
* **Fix:** Aggiunto `--recursive` al comando.

#### Bug 4 — `--database <cartella-vuota>` fa fallire l'intero comando
* **Sintomo:** Il più impattante in assoluto. Su un'installazione pulita (nessuna firma di terze parti ancora scaricata dalla vista Database), *ogni* scansione falliva integralmente:
  ```
  $ clamscan --database /percorso/vuoto --recursive ... /tmp/qualche_cartella
  ERROR: Can't open file or directory
  (LibClamAV Error: cli_loaddbdir: No supported database files found in ...)
  ```
  `ClamAVScanner` riceve sempre `extra_db_dirs=[third_party.sig_dir]` dalla UI (`window.py:39`), e quella cartella viene creata vuota al primo avvio (`os.makedirs(..., exist_ok=True)`). Passare `--database` su una cartella esistente ma senza firme al suo interno non viene ignorato da clamscan: fa fallire l'intero comando con **nessun risultato per nessun file**, mascherato dal parser come un unico risultato fittizio "ERROR" — lo stesso identico sintomo del Bug 1, ma con causa completamente diversa. Questo è il motivo per cui, durante la validazione, il fix dei Bug 1–3 da solo non bastava a far funzionare la scansione end-to-end.
* **Fix:** La cartella viene passata a `--database` solo se contiene realmente almeno un file (`any(os.scandir(extra_dir))`).

### Riscritura di `_scan_clamd()`
Non testabile empiricamente in questo ambiente (nessun demone `clamd` in esecuzione), ma confermato per lettura del codice: il comando `SCAN <path>` di clamd, se `<path>` è una directory, può rispondere con un numero di righe non prevedibile a priori (una per file scansionato all'interno). Il codice faceva un solo `readline()` per comando inviato — oltre a scartare risultati (stesso sintomo del Bug 1), rischiava un **disallineamento del protocollo**: righe di risposta non lette, rimaste nel buffer del socket, venivano interpretate come risposta al comando *successivo*, mescolando risultati tra cartelle diverse.
* **Fix:** Ogni path di input viene espanso client-side nell'elenco reale dei file (`_expand_to_files`, con `os.walk`) *prima* di parlare con clamd, e viene inviato un comando `SCAN <file>` per singolo file — così un comando corrisponde sempre esattamente a una riga di risposta.

### Test automatici aggiunti
`tests/test_clamav_parser.py` — 8 nuovi test, uno per bug:
* `TestScanClamscanUsesRealResults` (Bug 1)
* `TestScanClamscanCountsCleanFiles` (Bug 2)
* `TestScanClamscanIsRecursive` (Bug 3)
* `TestScanClamscanSkipsEmptyExtraDbDir` (Bug 4, 2 casi: cartella vuota e non vuota)
* `TestExpandToFiles` (espansione client-side per clamd, 2 casi)
* `TestScanClamdOneCommandPerFile` (protocollo clamd)

---

## Audit 2 — Stato della Dashboard (11-08-2026)

* **Moduli analizzati:** `src/window.py`, `src/core/history.py`

### Bug Individuati e Corretti

#### Bug 1 — `Status update error: cannot convert float NaN to integer`
* **File:** `src/window.py`, `_update_status()`
* **Sintomo:** Ad ogni avvio e ad ogni ciclo di refresh (ogni 30s), un errore compariva nel log; l'etichetta "Updated: ..." in alto restava bloccata sul testo iniziale hardcoded, mai aggiornata.
* **Causa:** Quando nessun database ClamAV è installato sul sistema (condizione comune su un'installazione pulita, prima del primo "Update DB"), `get_database_age()` ritorna `float("inf")`. Il codice poi calcolava:
  ```python
  update_text = f"Updated: {int(db_age // 86400)}d ago"
  ```
  In Python, `float('inf') // 86400` non produce `inf` ma **`nan`** (particolarità dell'aritmetica IEEE754 sulla floor division), e `int(nan)` solleva `ValueError: cannot convert float NaN to integer`. L'eccezione veniva intercettata e solo loggata — invisibile a un utente che lancia l'app da Flatpak senza terminale.
* **Fix:** Gestito esplicitamente il caso `db_age == float("inf")` prima del calcolo, mostrando "Updated: Never" (informazione corretta e più utile del crash silenzioso).

#### Bug 2 — Le statistiche della dashboard non si aggiornavano mai
* **File:** `src/window.py` (creazione dashboard + `_on_scan_complete`), `src/core/history.py`
* **Sintomo:** Dopo qualunque scansione completata (visibile in History), la dashboard continuava a mostrare "Threats blocked: 0 / Files scanned: 0 / Last scan: Never", sempre gli stessi tre valori impostati alla creazione della UI.
* **Causa:** Le tre righe venivano create una sola volta con valori hardcoded, salvate in `self._stats_rows` (riferimento al contenitore, non ai singoli Label) — e non lette mai più da nessuna parte del file. `_on_scan_complete` aggiornava solo la cronologia (`_refresh_history_view`), senza alcun collegamento verso quei tre widget.
* **Fix:** 
  * `HistoryManager.get_summary_stats()` (nuovo metodo): somma `files_scanned` e `threats_found` su tutte le scansioni completate, e restituisce il timestamp dell'ultima.
  * I tre `Gtk.Label` di valore vengono ora salvati per riferimento (`self._stat_labels`), non solo il contenitore.
  * `_refresh_dashboard_stats()` (nuovo metodo): rilegge i totali e aggiorna i tre Label. Richiamato all'avvio (`_start_status_monitor`) e dopo ogni scansione completata (`_on_scan_complete`).

### Test automatici aggiunti
`tests/test_history.py` — nuova classe `TestSummaryStats` (3 test):
* Nessuna scansione ancora effettuata → tutti i totali a zero, `last_scan` None.
* Somma corretta su più scansioni completate.
* Una scansione avviata ma non ancora conclusa (`start_scan` senza `finish_scan`) non deve comparire nei totali.

---

## Audit 3 — Icone Rotte e Crash di Avvio (12-08-2026)

* **Modulo analizzato:** `src/window.py`

### Bug Individuati e Corretti

#### Bug 1 — 7 nomi icona inesistenti nel tema Adwaita
* **Causa:** Sette nomi usati nel codice non esistevano in nessuna installazione standard di Adwaita (verificato con `Gtk.IconTheme.has_icon()`).
* **Fix:** Sostituite con le rispettive icone simboliche o alternative compatibili e pienamente rasterizzabili:

| Nome usato (rotto) | Sostituito con | Dove |
|---|---|---|
| `security-high` | `security-high-symbolic` | badge di stato (x2) |
| `appointment-soon` | `appointment-soon-symbolic` | stat "Last scan" |
| `document-open-recent` | `document-open-recent-symbolic` | riga History |
| `software-update-available` | `view-refresh-symbolic` | card "Update DB" |
| `folder-quarantine` | `changes-prevent-symbolic` | card "Quarantine" |
| `globe` | `system-search-symbolic` | card "VirusTotal" |
| `preferences-system` | `preferences-system-symbolic` | card "Settings" |

#### Bug 2 (Critico) — Crash all'avvio causato da `"accessible-name"`
* **Sintomo:** L'app crashava immediatamente all'avvio prima di mostrare la finestra, riportando:
  ```
  TypeError: object of type `GtkMenuButton' does not have property `accessible-name'
  ```
* **Causa:** Il codice (proveniente da una PR di accessibilità precedente) usava `widget.set_property("accessible-name", ...)` su pulsante menu, pulsante Quick Scan, card della dashboard e pulsanti in Quarantena. Tuttavia, `"accessible-name"` non è una GObject property in GTK4.
* **Fix:** Sostituite tutte e 4 le chiamate con la sintassi corretta dell'API GTK4:
  ```python
  Gtk.Accessible.update_property([Gtk.AccessibleProperty.LABEL], [testo])
  ```

---

## Audit 4 — Implementazione Viste VirusTotal e Settings (12-08-2026)

* **Moduli analizzati:** `src/window.py`, `src/core/virustotal.py`, `src/services/credentials.py`

### Vista VirusTotal
* Implementato pulsante "Choose File to Check" agganciato a `Gtk.FileDialog` per la selezione di singoli file.
* La chiamata di lookup (`VirusTotalClient.lookup_file`) viene eseguita in un thread separato (`threading.Thread`) per non bloccare il main loop della UI durante l'I/O di rete.
* Visualizzazione dei risultati strutturata in un `Adw.PreferencesGroup` che mostra: report dei motori di scansione, classificazione malicious/suspicious, tipo di file e nomi noti.
* Gestione robusta di diversi stati: integrazione disabilitata, API key non configurata, lookup fallita per rete o limiti API. La vista si aggiorna automaticamente a runtime (`notify::active`) se lo switch in Settings viene modificato.

### Vista Settings
Implementata come `Adw.PreferencesPage` con tre gruppi logici, usando il binding bidirezionale nativo di GSettings (`Gio.Settings.bind()`) per persistere immediatamente i cambiamenti:
* **Scanning:** Uso di clamd vs clamscan, path del socket clamd, auto-scan dei download.
* **Protection:** Cifratura quarantena (AES-256 via libsecret), database di firme di terze parti, icona nella barra di sistema.
* **VirusTotal:** Abilitazione integrazione, inserimento API Key (tramite `Adw.PasswordEntryRow` mascherata) con salvataggio sicuro via `CredentialsService.store_vt_key()`.

### Bug Corretto durante l'Implementazione
* **Sintomo:** Loop infinito e blocco dell'applicazione con centinaia di log di tipo `Adwaita-CRITICAL`.
* **Causa:** `Adw.PreferencesGroup` non espone i widget inseriti tramite `add()` direttamente con `get_first_child()`. Un tentativo di svuotare il gruppo iterando su `get_first_child()` e chiamando `remove()` falliva perché il widget non era figlio diretto del contenitore ma racchiuso in widget interni.
* **Fix:** Tenuta traccia esplicita dei riferimenti diretti ai widget aggiunti tramite liste Python (`self._vt_status_rows`, `self._vt_result_rows`), passandoli poi singolarmente a `remove()`.

---

## Audit 5 — QA Audit: Build, Dynamic Testing & Static Analysis (13-08-2026)

* **Metodologia:** build reale meson/ninja installata ed eseguita sotto Xvfb con clamd/clamscan reali, seguita da analisi statica estesa (`ruff`, `bandit`, `mypy`, `vulture`, `radon`).

### Tabella dei Problemi Corretti

| # | Gravità | Componente | Sintomo | Causa | Soluzione |
|---|---|---|---|---|---|
| **1** | 🔴 Critico | `core/clamav.py` `_scan_clamd` | Crash (TypeError) nel flusso scansione con clamd attivo | Veniva passato accidentalmente il *modulo* `paths` anziché la lista `scan_paths` a `_expand_to_files()` | Sostituito con la variabile corretta. Aggiunta una gestione difensiva dei `TypeError` nel blocco |
| **2** | 🔴 Critico | `core/clamav.py` `_scan_clamscan` | File di grandi dimensioni (es. 200MB) saltati istantaneamente e marcati come sani | Clamscan escludeva i file grandi ("File too large, ignoring"). In output standard non produceva righe di errore e il parser li assumeva OK | Introdotto pre-controllo dimensione lato client (limite 2GB, file saltati marcati `skipped`), aggiunte flag esplicite `--max-filesize`/`--max-scansize` |
| **3** | 🟠 Alto | `core/clamav.py` `_parse_clamscan_output` | File senza permessi di lettura ignorati silenziosamente | Il parser non catturava `"Access denied"` stampato da clamscan, ignorando la riga | Riconosciuta la riga, i file vengono marcati esplicitamente come `skipped` |
| **4** | 🟠 Alto | Settings → "Use clamd daemon" | Lo switch non aveva effetto | Il valore GSettings `use-clamd` non veniva mai effettivamente letto da `ClamAVScanner` | Aggiunto parametro `prefer_clamd` letto all'avvio e aggiornato dinamicamente via listener `notify::active` |
| **5** | 🟠 Alto | Settings → "Encrypt quarantined files" | Promessa di cifratura attiva ma file non cifrati | `QuarantineManager.set_encryption()` non veniva mai invocato | Collegato lo switch a `Gio.Settings "changed::quarantine-encrypt"`. Chiave generata e archiviata via libsecret con fallback sicuro in assenza di keyring |
| **6** | 🟡 Medio | UI — layout finestra | Finestra tagliata (1324×780px invece dei 1100×780px di design) su monitor piccoli | `Gtk.Grid` con `set_column_homogeneous(True)` forzava le colonne a estendersi quanto la card più larga | Sostituito `Gtk.Grid` con `Gtk.FlowBox` che gestisce il wrapping nativo |
| **7** | 🟡 Medio | UI — flusso errori | Toast mostravano errori generici fuorvianti | Messaggi di errore hardcoded in caso di eccezioni | Sostituiti i messaggi fissi con l'estrazione della stringa d'errore reale (troncata a 160 caratteri per leggibilità) |
| **8** | 🟢 Basso | Sidebar | Voci "My Account" e "Notifications" non navigabili | Pagine placeholder o non mappate correttamente nel ViewStack | Rimossa voce "My Account" (inutile), implementata la pagina reale "Notifications" nel ViewStack. Corrette in corsa 2 icone Adwaita mancanti (`bell-symbolic`, `eye-symbolic`) |

### Analisi Statica Residua e Validazione
* **Bandit:** Rilevati avvisi solo per subprocess con argomenti in forma di lista e `shell=False` (sicuro).
* **Mypy:** Una manciata di segnalazioni minori su attributi non tipizzati, nessun impatto a runtime.
* **Test automatici:** Raggiunti **48/48 test passati** su tutta la suite (aggiunti 10 test di regressione: 6 per bug #1/#2/#5, 4 per bug #3).
