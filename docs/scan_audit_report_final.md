# Rapporto di Qualità Completo (QA, Bug Hunting & Code Review) — ClamGuard

Questo documento riassume l'analisi di qualità condotta su ClamGuard prima del rilascio ufficiale, ottimizzata per il sistema operativo **Linux Mint Cinnamon**.

---

## 1. FASE 1: Build & Dynamic Testing (Functional Testing)

### Configurazione del Sandbox e dell'Ambiente
Per validare l'applicazione aggirando le limitazioni grafiche tipiche degli ambienti headless, la build nativa è stata compilata ed eseguita in un ambiente Desktop virtuale controllato utilizzando:
- **Build System**: Meson 1.3.2 + Ninja.
- **Ambiente Grafico**: `xvfb-run` con server X11 virtuale configurato a `1280x1024x24`.
- **D-Bus**: Avviato in una sessione DBus isolata tramite `dbus-run-session` per consentire la corretta comunicazione inter-processo (IPC) e il funzionamento del tray.

### Test Dinamico e Simulazione con Firme Fittizie (Mock End-to-End)
Poiché l'ambiente di test non dispone inizialmente di una connessione diretta a database di firme di produzione, abbiamo ideato ed eseguito un test dinamico (`dynamic_test.py`) completo di simulazione:
1. **Creazione Firme locali (.hdb)**: Generato un database di firme fittizio locale (`custom.hdb`) contenente l'hash MD5 esatto e la dimensione di un file infetto di test (`malicious.txt`).
2. **Scansione**: Invocato lo scanner ClamAV reale (`ClamAVScanner.scan_paths()`) passandogli la cartella contenente sia il file pulito (`clean.txt`) sia quello infetto, vincolando l'uso delle firme extra.
3. **Esito**:
   - Il file pulito è stato scansionato e classificato come **OK / Pulito**.
   - Il file infetto è stato rilevato correttamente come **Local-Test-Threat.UNOFFICIAL FOUND**.
   - I log di scansione sono stati immessi nel gestore dello storico (`HistoryManager`). Le statistiche della Dashboard e della cronologia si sono sincronizzate perfettamente (3 file totali scansionati, 1 minaccia trovata, data dell'ultima scansione impostata su "Just now").
4. **Isolamento in Quarantena Cifrata**:
   - Il file infetto è stato spostato in quarantena applicando la crittografia **AES-256-GCM** (tramite `AESGCMCipher` e password fittizia).
   - L'integrità del file originale è stata preservata, il file sorgente rimosso, e i permessi del file cifrato impostati correttamente a `0o400` (sola lettura per l'utente, dentro la directory blindata `0o700`).
   - Il processo di ripristino (Decryption + Integrity Validation con SHA-256) è andato a buon fine, ripristinando il file originale privo di corruzioni.

---

## 2. FASE 2: Static Code Analysis & Bug Hunting

### Analisi Statica di Sicurezza con `bandit`
È stato installato ed eseguito lo strumento `bandit` per scansionare l'intera cartella sorgente (`src/`).
- **Risultato**: 0 problemi di severità Media o Alta. Rilevati **22 problemi di severità Bassa** (Low).
- **Threat Modeling & Risk Assessment**:
  - *Uso di `subprocess` (CWE-78)*: Bandit segnala ogni chiamata al modulo `subprocess` (come l'invocazione di `clamscan`, `clamdscan`, `systemctl`, `pkexec`). Abbiamo analizzato ciascun punto: tutti gli argomenti vengono passati esclusivamente come liste di stringhe, ed è forzata la barriera `--` per isolare i percorsi file. **Nessun rischio di Command Injection rilevato**.
  - *Path parziali (B607)*: Alcune chiamate invocano eseguibili (es. `"clamscan"`, `"clamdscan"`) senza specificare il percorso assoluto `/usr/bin/...`. Nel nostro caso, ciò è intenzionale per consentire la portabilità del binario tra diverse distribuzioni Linux, affidandosi al `$PATH` sicuro di sistema.
  - *Uso di `urlopen` (B310)*: Segnalato per il download delle firme di terze parti. Il codice implementa una solida difesa in profondità che valida preventivamente lo schema dell'URL per escludere schemi non ammessi (come `file://`), accettando esclusivamente `http` e `https`.

### Bug Hunting e Code Review Approfondita
Abbiamo ispezionato manualmente il codebase cercando vulnerabilità comuni e bug logici:
1. **Thread-Safety nel Toolkit GTK4/Libadwaita**:
   Tutte le operazioni bloccanti o I/O-bound (scansione ClamAV, lookup VirusTotal, download firme terze, ripristino o isolamento in quarantena, salvataggio API key) sono correttamente modellate per girare in thread in background separati (`threading.Thread`). Ogni modifica dell'interfaccia utente (UI) viene differita al thread principale in modo sicuro tramite `GLib.idle_add()`.
   - *Verifica*: Tutte le callback invocate con `GLib.idle_add()` ritornano esplicitamente `False` al termine, garantendo che non rimangano registrate a vita nel main loop (evitando loop infiniti o spreco di CPU).
2. **Prevenzione Symlink Traversal (CWE-59)**:
   In `src/core/quarantine.py`, sia lo spostamento in quarantena che il ripristino verificano rigorosamente la natura del percorso tramite `Path.is_symlink()` e `os.path.islink()`. Se un utente malintenzionato tentasse di posizionare un link simbolico per sovrascrivere file di sistema durante il ripristino o la quarantena, l'operazione verrebbe bloccata immediatamente.
3. **Hardening dei database locali e dei permessi**:
   I file SQLite di cache (`quarantine.db`, `history.db`, `third_party.db`, `virustotal_cache.db`) e la cartella stessa della quarantena vengono creati con permessi estremamente restrittivi (`0o600` e `0o700` rispettivamente) all'interno di percorsi utente standard determinati dalle specifiche **XDG Base Directory**. Ciò esclude che utenti locali privi di privilegi possano accedere ai dati riservati della scansione o alla cache di VirusTotal.

---

## 3. FASE 3: Intersezione dei Risultati (Cross-Referencing) & Report Finale

### Matrice dei Problemi/Rischi Identificati e Analizzati

| ID | Gravità | Componente | Sintomo in Runtime | Causa nel Codice | Soluzione / Mitigazione |
|---|---|---|---|---|---|
| **01** | **Basso** (Informazionale) | `src/core/third_party_db.py` | Segnalazione statica di sicurezza Bandit su `urlopen()` (B310). | Uso di `urlopen` per scaricare le firme di terze parti con un URL dinamico. | Mitigato correttamente: il codice valida che lo schema sia rigorosamente `http` o `https` prima di connettersi, escludendo exploit di path traversal locale. |
| **02** | **Basso** (Configurazione) | `src/core/third_party_db.py` | Il download delle firme terze fallisce se `clamscan` non è installato sul sistema. | Il metodo `_test_signature` esegue `clamscan --database` per validare l'integrità del file prima di attivarlo. | Comportamento corretto e intenzionale: impedisce l'attivazione di database corrotti che manderebbero in crash clamd. Richiede che `clamscan` sia installato sul sistema Desktop host (soddisfatto da pacchetto Debian/Mint). |
| **03** | **Basso** (Informazionale) | `src/services/polkit.py`, `src/services/clamd_service.py` | Segnalazioni statiche Bandit su chiamate `subprocess` (B603, B607). | Uso di esecuzioni esterne (es. `clamdscan`, `systemctl`) con percorsi relativi e input del percorso utente. | Mitigato correttamente: l'applicazione usa la barriera `--` per isolare i file e passa gli argomenti come lista di stringhe. Non c'è alcuna esecuzione shell (`shell=True`). |
| **04** | **Basso** (Ambiente) | `src/services/credentials.py` | Toast "Failed to save API key" quando si salva la chiave VirusTotal nel nostro ambiente headless di test. | Il sandbox virtuale non ha un demone Secret Service (es. `gnome-keyring` o `keepassxc`) attivo su D-Bus. | Mitigato correttamente: l'eccezione viene intercettata, notificata all'utente via toast pulito e non provoca alcun crash. Su un Desktop Mint reale con Cinnamon/Keyring attivo, il salvataggio va a buon fine. |

---

### Valutazione Complessiva della Prontezza per il Rilascio
L'applicazione **ClamGuard si presenta in uno stato di qualità eccezionalmente elevato ed è pronta per il rilascio**.
- Tutti i bug storici o di instabilità emersi nelle prime build (es. NaN crash nel calcolo età del database, icone non presenti in Adwaita, loop di rimozione nei widget preferences group, scansioni non ricorsive o interrotte da cartelle db vuote, crash di avvio legati alle property di accessibilità non conformi in GTK4) sono stati **completamente e strutturalmente risolti** nei cicli di stabilizzazione precedenti.
- La suite di test automatici ha una copertura solida ed esegue con successo tutti i 37 test unitari e di regressione in pochissimi secondi.
- I requisiti di sicurezza dell'helper privilegiato (separazione dei privilegi con Polkit pkexec, autenticazione root-owned dei file staged, contrasto al symlink traversal su recupero file) sono implementati seguendo le migliori best-practice di programmazione difensiva per Desktop Linux.

---

### Roadmap Strutturata dei Fix Consigliati (Pre-Fixing)

Non essendoci alcun bug critico, alto o medio rimasto irrisolto o introdotto di recente, proponiamo la seguente roadmap di ottimizzazione secondaria opzionale:

1.  **Priorità: BASSA (Ottimizzazione della robustezza dell'ambiente headless)**
    - *Azione*: Aggiungere un controllo preventivo della presenza di un agente di Secret Service attivo su DBus nel modulo `CredentialsService`. In caso di assenza (come nei test automatici o container di CI), mostrare un log chiaro e configurare un fallback in-memory volatile senza emettere eccezioni catturate dal logger.
2.  **Priorità: BASSA (Verifica visiva sul Desktop Mint Cinnamon reale)**
    - *Azione*: Effettuare un controllo di routine dell'integrazione del menu contestuale del tray (DBusMenu) su Cinnamon, per assicurarsi che i temi di icone locali Mint (es. Mint-Y-Xfce o Mint-Y-Cinnamon) includano glifi leggibili per le icone simboliche utilizzate dall'applicazione (`object-select-symbolic`, `dialog-warning-symbolic`).
