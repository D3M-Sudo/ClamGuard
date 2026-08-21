# ClamGuard — Report bug hunting (sessione 3)

Analisi statica sistematica sull'intero codebase, prima di considerare la base "finita". Toolchain: **Ruff** (linting, 900+ regole incl. bugbear/pyflakes/security), **Bandit** (analisi di sicurezza dedicata), **mypy** (type-checking — utile a rivelare bug logici, non solo mismatch di tipo), **vulture** (codice morto).

Metodo: prima un run ampio per calibrare (Ruff con `--select ALL` ha prodotto 387 hit, quasi tutti stile/formattazione — non bug), poi ristretto alle categorie che intercettano bug reali (`F,B,PLE,S,ASYNC` per Ruff, severità medium+ per Bandit). Ogni finding è stato letto in contesto prima di decidere se è un bug reale o un falso positivo, e ogni fix è stato verificato — con test automatico dove sensato, con riproduzione diretta dove no.

---

## 🔴 Bug critici

### 1. Socket clamd spoofabile via `/tmp`
**File:** `core/clamav.py` — trovato da Bandit (B108) e Ruff (S108)

`_find_socket()` includeva `/tmp/clamd.socket` tra i path candidati per il socket di controllo di clamd. `/tmp` è scrivibile da qualunque utente locale: un attaccante non privilegiato poteva precreare lì un socket fasullo e far credere all'app di parlare col vero demone antivirus — facendo segnalare "pulito" file realmente infetti, o intercettando i file inviati per la scansione.

**Fix:** rimosso `/tmp/clamd.socket` dai candidati. Aggiunta anche una verifica di proprietà del socket (`uid < 1000`, cioè utente di sistema) come difesa in profondità sui due path legittimi restanti.

### 2. Salt PBKDF2 hardcoded, identico su ogni installazione
**File:** `core/quarantine.py` — trovato leggendo il contesto attorno a un warning di mypy (non un finding diretto)

La cifratura opzionale della quarantena derivava la chiave da password con PBKDF2 usando un salt **costante** (`b"alpha_quarantine_salt_v1"`), identico su ogni installazione di ClamGuard. Questo vanifica lo scopo del salt: un attaccante può precalcolare *una* rainbow table valida per quella costante e riusarla contro ogni installazione, invece di doverne calcolare una per ciascuna.

**Fix:** salt casuale (`os.urandom(16)`) generato una sola volta per installazione e persistito in una nuova tabella `kdf_salt` nel DB quarantena — così la stessa password continua a produrre la stessa chiave tra riavvii (i file già cifrati restano decifrabili), ma installazioni diverse hanno salt diversi.

**Verifica:** 2 nuovi test (`test_encryption_salt_persists_across_instances`, `test_encryption_salt_differs_across_installations`).

### 3. Fallback clamd→clamscan rotto (`TypeError` nel percorso critico)
**File:** `core/clamav.py` — trovato da **mypy** (`Missing positional argument "chunk_size"`)

Quando `clamd` falliva a metà scansione (crash, timeout, connessione persa), il codice tentava un fallback:
```python
return await self._scan_clamscan(paths, progress_callback)
```
ma `_scan_clamscan()` non aveva un valore di default per `chunk_size` — questa chiamata avrebbe sollevato `TypeError` **esattamente nel momento in cui il fallback serve di più**, cioè quando clamd ha già fallito. Un bug di questo tipo è quasi impossibile da notare leggendo il codice linearmente: emerge solo seguendo un percorso di errore specifico, che è precisamente ciò per cui gli strumenti di type-checking sono utili.

**Fix:** aggiunto `chunk_size: int = 100` come default.

**Verifica:** riprodotto il crash prima del fix (chiamata diretta con la stessa firma usata dal fallback → `TypeError` confermato), poi il fix (stesso identico test → nessun errore di tipo, solo `FileNotFoundError` perché `clamscan` non è installato in questo sandbox). Aggiunto anche un test di regressione permanente basato su `inspect.signature().bind()`.

## 🟡 Bug minori / difetti di manutenzione

### 4. Version drift — tre fonti di verità indipendenti
**File:** `main.py`

`--version`, il dialog "About", e `main()` avevano ciascuno la stringa `"0.1.0"` hardcoded separatamente. Il parametro `version` passato dal launcher (derivato da `meson.project_version()`) veniva silenziosamente scartato: un bump di versione in `meson.build` non si sarebbe mai riflesso nell'app.

**Fix:** `version` ora propagato da `main()` → `ClamGuardApplication.__init__(version=...)` → `self._version`, usato in entrambi i punti.

### 5. Refusi rimasti dal rename ClamGuard
Trovati con una ricerca mirata dopo aver notato il primo (voce di menu "About Alpha" ancora presente — un residuo perché lo script di sostituzione del rename cercava la stringa esatta `"Alpha"` tra virgolette, non `"About Alpha"`). Una volta trovato uno, ho cercato sistematicamente tutti gli altri:

- Voce di menu "About Alpha" → "About ClamGuard"
- Header `User-Agent: Alpha/0.1.0` nelle richieste HTTP ai provider di firme → `ClamGuard/0.1.0`
- Docstring/log in `main.py`, `README.md`, e sei file `__init__.py` (creati *prima* della sessione di rename, mai toccati da quello script)

Nessun impatto funzionale, ma visibile all'utente (menu) e nei log — vale la pena averli chiusi ora.

## 🔵 Indurimenti difensivi (nessun bug attivo, ma riducono la superficie)

- **Validazione schema URL prima del download firme** (`third_party_db.py`): i provider di default sono tutti `https`, ma l'URL viene riletto da SQLite ad ogni avvio, non solo dai default hardcoded — un controllo esplicito costa poco ed elimina la fiducia implicita.
- **`cursor.lastrowid` reso fail-fast** (`history.py`): tipizzato `int | None` da sqlite3; in pratica non è mai `None` dopo un INSERT riuscito, ma se lo fosse, propagare `None` come `scan_id` avrebbe corrotto silenziosamente i record collegati (minacce, storico) più a valle.
- **Riferimento esplicito al pulsante "Install into system database"** (`window.py`): prima recuperato via `get_last_child()`, fragile e implicito — si sarebbe rotto silenziosamente aggiungendo un widget dopo in futuro. Ora un attributo diretto.
- **17 import inutilizzati rimossi** (rilevati da Ruff F401, confermati uno per uno prima della rimozione — incluso `Secret` in `main.py`, verificato che `credentials.py` lo importa autonomamente).

## Falsi positivi identificati e chiusi esplicitamente

Bandit fa solo pattern-matching sull'AST, non analisi del flusso dati: segnala ogni `urlopen()`/`chmod()` a prescindere dal contesto. Due categorie di falsi positivi, chiuse con `# nosec` **motivato** (mai per silenziare, sempre spiegando perché è sicuro) invece di disabilitare il controllo globalmente:

- **B310** (`urlopen`) su `third_party_db.py`: raggiungibile solo dopo la validazione esplicita dello schema aggiunta al punto precedente — bandit non vede la guardia.
- **B103** (`chmod 0o755`) ×2 su `install_helper.py`: operano solo su directory (mai file) sotto `/usr/{bin,lib,share}` — 0o755 è lo standard per directory di sistema, bandit non distingue file da directory.

I restanti 19 avvisi Ruff (`S603`/`S607`, subprocess) sono tutti chiamate con argv fisso e binario hardcoded (`clamscan`, `clamdscan`, `systemctl`, `pkexec`), mai `shell=True` né interpolazione di stringhe non fidate — pattern legittimo, rivisto uno per uno, nessuna azione necessaria.

## Verifica finale

```
$ python3 -m unittest discover -s tests -v
Ran 17 tests in 0.144s — OK   (3 nuovi test di regressione)

$ bandit -r src -ll
Medium: 0   High: 0   (era Medium: 4 all'inizio)

$ ruff check src --select F,B,PLE,S,ASYNC
19 (tutti S603/S607 rivisti e legittimi — nessun bug)
```

py_compile pulito su tutto l'albero.
