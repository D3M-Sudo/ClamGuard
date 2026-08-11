# Audit: pipeline di scansione (`src/core/clamav.py`) — 2026-08-11

## Metodo

L'app è stata compilata e installata realmente (build meson, non un mock),
eseguita sotto Xvfb con clamd/clamscan reali, e pilotata a click come un
utente. I bug qui descritti sono stati prima osservati empiricamente
(risultati sbagliati in cronologia scansioni), poi confermati leggendo il
codice, poi corretti, poi rivalidati con:

- invocazione diretta di `ClamAVScanner.scan_paths()` su cartelle reali,
  confrontando `len(risultati)` col conteggio reale (`find -type f | wc -l`);
- una firma ClamAV di test creata ad-hoc (database `.hdb` locale) per
  verificare che un file infetto venga davvero rilevato e non perso;
- l'intera suite di test automatici (`pytest tests/`), più 8 nuovi test di
  regressione, uno per ciascun bug qui sotto.

Sono stati trovati **4 bug distinti** che si sommano tra loro: correggerne
solo alcuni avrebbe lasciato la scansione ancora rotta.

## Bug 1 — risultati reali scartati e rimpiazzati con un placeholder

**File:** `_scan_clamscan()`
**Sintomo:** qualunque cartella scansionata, la cronologia riportava
sempre "1 files, 0 threats", indipendentemente dal contenuto reale.

`clamscan` produce già una riga di output corretta per ogni file
scansionato (`_parse_clamscan_output` la parsava già bene). Il bug era nel
passo successivo: il codice cercava, per ogni *cartella* di input, un
risultato il cui `path` combaciasse esattamente con la stringa della
cartella stessa — cosa che non può mai accadere, dato che i risultati
parlano di file (`/home/utente/file.txt`), non di cartelle (`/home`).
Il match falliva sempre, e veniva creato un unico `ScanResult` finto e
pulito al posto di tutti i risultati reali (comprese eventuali minacce
trovate in profondità, silenziosamente perse).

**Fix:** usare direttamente i risultati parsati (`results.extend(...)`)
invece di rimapparli sui path di input.

## Bug 2 — `--infected` nascondeva i file puliti dal conteggio

**File:** `_scan_clamscan()`
**Sintomo:** anche dopo il fix del Bug 1, il conteggio restava sbagliato
(sottostimato di quasi tutto).

Il flag `--infected` passato a `clamscan` fa sì che vengano stampate
**solo** le righe dei file infetti o in errore: i file puliti non
producono alcuna riga di output e quindi non vengono mai conteggiati come
"scansionati".

**Fix:** rimosso `--infected`. Senza quel flag, clamscan stampa anche
`<path>: OK` per ogni file pulito.

## Bug 3 — clamscan non scansiona le sottocartelle di default

**File:** `_scan_clamscan()`
**Sintomo:** il più grave dei quattro. Verificato con un confronto diretto:
```
find src/ tests/ -type f | wc -l          → 64 file reali
clamscan --no-summary --stdout src tests  → 13 righe di output
clamscan --recursive ... src tests        → 64 righe di output
```
`clamscan`, di suo, **non scende nelle sottocartelle** a meno di passare
esplicitamente `-r`/`--recursive`. Senza questo flag, ogni scansione
(Quick Scan, Custom Scan, System Scan) esaminava solo i file presenti
*direttamente* nella cartella scelta, ignorando silenziosamente tutto il
resto — cioè, nella pratica, quasi tutti i file reali di un utente.

**Fix:** aggiunto `--recursive` al comando.

## Bug 4 — `--database <cartella-vuota>` fa fallire l'intero comando

**File:** `_scan_clamscan()`
**Sintomo:** il più impattante in assoluto. Su un'installazione pulita
(nessuna firma di terze parti ancora scaricata dalla vista Database),
*ogni* scansione falliva integralmente:
```
$ clamscan --database /percorso/vuoto --recursive ... /tmp/qualche_cartella
ERROR: Can't open file or directory
(LibClamAV Error: cli_loaddbdir: No supported database files found in ...)
```
`ClamAVScanner` riceve sempre `extra_db_dirs=[third_party.sig_dir]` dalla
UI (`window.py:39`), e quella cartella viene creata vuota al primo avvio
(`os.makedirs(..., exist_ok=True)`). Passare `--database` su una cartella
esistente ma senza firme al suo interno non viene ignorato da clamscan:
fa fallire l'intero comando con **nessun risultato per nessun file**,
mascherato dal parser come un unico risultato fittizio "ERROR" — lo stesso
identico sintomo del Bug 1, ma con causa completamente diversa. Questo è
il motivo per cui, durante la validazione, il fix dei Bug 1–3 da solo non
bastava a far funzionare la scansione end-to-end.

**Fix:** la cartella viene passata a `--database` solo se contiene
realmente almeno un file (`any(os.scandir(extra_dir))`).

## `_scan_clamd()` — stessa famiglia di bug, riscritto

**File:** `_scan_clamd()`
Non testabile empiricamente in questo ambiente (nessun demone `clamd` in
esecuzione), ma confermato per lettura del codice: il comando `SCAN
<path>` di clamd, se `<path>` è una directory, può rispondere con un
numero di righe non prevedibile a priori (una per file scansionato
all'interno). Il codice faceva un solo `readline()` per comando inviato —
oltre a scartare risultati (stesso sintomo del Bug 1), rischiava un
**disallineamento del protocollo**: righe di risposta non lette,
rimaste nel buffer del socket, venivano interpretate come risposta al
comando *successivo*, mescolando risultati tra cartelle diverse.

**Fix:** ogni path di input viene espanso client-side nell'elenco reale
dei file (`_expand_to_files`, con `os.walk`) *prima* di parlare con
clamd, e viene inviato un comando `SCAN <file>` per singolo file — così
un comando corrisponde sempre esattamente a una riga di risposta.

## Validazione finale

```
$ find src/ tests/ -type f | wc -l
64
$ python3 -c "... scanner.scan_paths(['src','tests']) ..."
Risultati: 64   Infetti: 0
```
```
# con una firma di test creata ad-hoc (md5 di un file noto)
$ python3 -c "... scanner.scan_paths(['/tmp/testscan']) ..."
Risultati: 2
  /tmp/testscan/b.txt infected=True   (firma rilevata correttamente)
  /tmp/testscan/a.txt infected=False
```

## Test automatici aggiunti

`tests/test_clamav_parser.py` — 8 nuovi test, uno per bug:
- `TestScanClamscanUsesRealResults` (Bug 1)
- `TestScanClamscanCountsCleanFiles` (Bug 2)
- `TestScanClamscanIsRecursive` (Bug 3)
- `TestScanClamscanSkipsEmptyExtraDbDir` (Bug 4, 2 casi: cartella vuota e
  non vuota)
- `TestExpandToFiles` (espansione client-side per clamd, 2 casi)
- `TestScanClamdOneCommandPerFile` (protocollo clamd)

Suite completa: 33/33 test passati, `ruff check` pulito.

## Non affrontato in questo giro (fuori scope)

- `Status update error: cannot convert float NaN to integer` e le
  statistiche dashboard mai aggiornate (priorità 2 concordata)
- Icone non esistenti nel tema Adwaita moderno (priorità 3)
- Viste stub "View implementation pending" per VirusTotal e Settings
- Un crash ripetuto del subprocesso tray (`Tray crashato 3 volte in 60s`),
  osservato durante questa sessione di test ma non ancora indagato
