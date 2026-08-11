# Audit: stato dashboard (`src/window.py`, `src/core/history.py`) — 2026-08-11

## Metodo

Stessa metodologia dell'audit precedente (`docs/scan_audit_20260811.md`):
app compilata e installata realmente, eseguita sotto Xvfb, pilotata a
click. Bug osservati empiricamente, confermati leggendo il codice,
corretti, rivalidati con l'app reale (screenshot prima/dopo) più test
automatici.

## Bug 1 — `Status update error: cannot convert float NaN to integer`

**File:** `src/window.py`, `_update_status()`
**Sintomo:** ad ogni avvio e ad ogni ciclo di refresh (ogni 30s), un
errore compariva nel log; l'etichetta "Updated: ..." in alto restava
bloccata sul testo iniziale hardcoded, mai aggiornata.

Quando nessun database ClamAV è installato sul sistema (condizione comune
su un'installazione pulita, prima del primo "Update DB"),
`get_database_age()` ritorna `float("inf")`. Il codice poi calcolava:
```python
update_text = f"Updated: {int(db_age // 86400)}d ago"
```
In Python, `float('inf') // 86400` non produce `inf` ma **`nan`**
(particolarità dell'aritmetica IEEE754 sulla floor division), e
`int(nan)` solleva `ValueError: cannot convert float NaN to integer`.
L'eccezione veniva intercettata e solo loggata — invisibile a un utente
che lancia l'app da Flatpak senza terminale.

**Fix:** gestito esplicitamente il caso `db_age == float("inf")` prima
del calcolo, mostrando "Updated: Never" (informazione corretta e più
utile del crash silenzioso).

**Verifica:** log di avvio pulito, nessun errore; badge in alto mostra
correttamente "Updated: Never" su un sistema senza database (screenshot
allegati alla PR).

## Bug 2 — le statistiche della dashboard non si aggiornavano mai

**File:** `src/window.py` (creazione dashboard + `_on_scan_complete`),
`src/core/history.py`
**Sintomo:** dopo qualunque scansione completata (visibile in History),
la dashboard continuava a mostrare "Threats blocked: 0 / Files scanned: 0
/ Last scan: Never", sempre gli stessi tre valori impostati alla
creazione della UI.

Le tre righe venivano create una sola volta con valori hardcoded, salvate
in `self._stats_rows` (riferimento al contenitore, non ai singoli
Label) — e non lette mai più da nessuna parte del file.
`_on_scan_complete` aggiornava solo la cronologia (`_refresh_history_view`),
senza alcun collegamento verso quei tre widget.

**Fix:**
- `HistoryManager.get_summary_stats()` (nuovo metodo): somma
  `files_scanned` e `threats_found` su tutte le scansioni completate, e
  restituisce il timestamp dell'ultima.
- I tre `Gtk.Label` di valore vengono ora salvati per riferimento
  (`self._stat_labels`), non solo il contenitore.
- `_refresh_dashboard_stats()` (nuovo metodo): rilegge i totali e
  aggiorna i tre Label. Richiamato all'avvio (`_start_status_monitor`) e
  dopo ogni scansione completata (`_on_scan_complete`).

**Verifica empirica (screenshot allegati alla PR):**
1. Avvio pulito, history vuota → dashboard mostra "0 / 0 / Never" (corretto,
   nessuna scansione ancora effettuata — comportamento invariato per questo
   caso).
2. Custom Scan su una cartella di test (1 file scansionato, nessuna
   minaccia) → dashboard aggiornata a "Files scanned: 1 · Last scan: Just
   now", sincronizzata col toast "Scan complete: 1 file(s), no threats
   found".
3. Secondo scan (Quick Scan) → "Files scanned: 2" (accumulo corretto tra
   scansioni successive, non sovrascrittura).

## Test automatici aggiunti

`tests/test_history.py` — nuova classe `TestSummaryStats` (3 test):
- nessuna scansione ancora effettuata → tutti i totali a zero, `last_scan`
  None
- somma corretta su più scansioni completate
- una scansione avviata ma non ancora conclusa (`start_scan` senza
  `finish_scan`) non deve comparire nei totali

Suite completa: 28/28 test passati, `ruff check` pulito su tutti i file
modificati.

## Non affrontato in questo giro (priorità successiva)

- Le 7 icone non esistenti nel tema Adwaita moderno (priorità 3 concordata)
- VirusTotal e Settings ancora stub ("View implementation pending")
- Il fix del conteggio scan vero e proprio (priorità 1) è in
  `fix/scan-result-mapping` (PR separata, ancora da mergiare) — questa PR
  è stata sviluppata e testata indipendentemente da quella, sul branch
  `testing` così com'è oggi; una volta mergiate entrambe, "Files scanned"
  in dashboard rifletterà anche i conteggi corretti (ricorsivi) della
  pipeline di scan.
