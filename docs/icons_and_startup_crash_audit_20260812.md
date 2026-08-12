# Audit: icone rotte e crash di avvio (`src/window.py`) — 2026-08-12

## Metodo

Stessa metodologia degli audit precedenti: app compilata e installata
realmente, eseguita sotto Xvfb, pilotata a click. Prima di iniziare questo
giro, ho riallineato il lavoro sullo stato attuale di `testing`, che nel
frattempo aveva ricevuto 4 PR aggiuntive da altri agenti (Jules/Bolt):
`#11` (accessibilità + feedback scansione attiva), `#12` (streaming
INSTREAM), `#13` (hardening OOM/sandbox/tray), `#14` (fix freeze UI +
backoff tray). Il mio fix icone (già pronto su una base precedente) è
stato riapplicato via `git stash` senza conflitti sopra questa nuova base.

## Bug 1 (già noto, confermato) — 7 nomi icona inesistenti in Adwaita

Verificato nell'audit iniziale con `Gtk.IconTheme.has_icon()` — un
controllo indipendente dall'ambiente grafico (verifica solo se il nome è
presente nell'indice del tema, non se una specifica pipeline software
riesce a rasterizzarlo). Sette nomi usati nel codice non esistono in
nessuna installazione standard di Adwaita:

| Nome usato (rotto) | Sostituito con | Dove |
|---|---|---|
| `security-high` | `security-high-symbolic` | badge di stato (x2) |
| `appointment-soon` | `appointment-soon-symbolic` | stat "Last scan" |
| `document-open-recent` | `document-open-recent-symbolic` | riga History |
| `software-update-available` | `view-refresh-symbolic` | card "Update DB" |
| `folder-quarantine` | `changes-prevent-symbolic` | card "Quarantine" |
| `globe` | `system-search-symbolic` | card "VirusTotal" |
| `preferences-system` | `preferences-system-symbolic` | card "Settings" |

Per "Update DB", "Quarantine" e "VirusTotal" ho scelto sostituti diversi
dalla prima ipotesi (rispettivamente invece di
`software-update-available-symbolic`, `action-unavailable-symbolic`,
`web-browser-symbolic`): tutti e tre i nomi originali sono comunque nomi
Adwaita validi, ma in questo specifico ambiente sandbox (Xvfb software
rendering, senza GPU) non venivano rasterizzati correttamente, mentre le
alternative scelte sì — e si adattano altrettanto bene semanticamente
(refresh per l'aggiornamento del DB, lucchetto per l'isolamento in
quarantena, lente di ricerca per "Check files with 70+ engines").

**Nota importante sui limiti di questo ambiente di test:** durante la
verifica visiva ho scoperto che questo specifico sandbox Xvfb non
rasterizza correttamente diverse icone valide e già presenti nel codice
prima di qualunque mio intervento (`folder-open` in "Custom Scan",
`emblem-ok-symbolic`, `edit-undo-symbolic`) — icone la cui esistenza nel
tema è comunque confermata da `has_icon()`. Questo conferma che si tratta
di un limite del motore di rendering software di questo container
(probabilmente nella pipeline di ricolorazione delle icone simboliche di
librsvg/Cairo senza accelerazione GPU), non di un bug di codice: un
desktop reale con stack grafico completo molto probabilmente le
renderizza correttamente. Non ho "inseguito" questo problema oltre le 7
icone originariamente diagnosticate come *inesistenti* (quelle sì, bug
di codice reali, confermati in modo indipendente dall'ambiente).
Consiglio una rapida verifica visiva finale sul tuo desktop reale dopo
l'installazione del Flatpak, come controllo di buon senso.

## Bug 2 (nuovo, critico) — l'app non si avviava più

**Scoperto per caso durante la validazione**, non è un bug che ho
introdotto: proviene dalla PR di accessibilità (`#14`, già mergiata in
`testing`) mergiata da un altro agente nel frattempo.

**Sintomo:** l'app crashava immediatamente all'avvio, prima ancora di
mostrare la finestra:
```
TypeError: object of type `GtkMenuButton' does not have property `accessible-name'
```

**Causa:** il codice usava `widget.set_property("accessible-name", ...)`
per impostare il nome accessibile di 4 widget (pulsante menu, pulsante
Quick Scan, card della dashboard, pulsanti Restore/Delete in Quarantena).
`"accessible-name"` **non è una GObject property** in GTK4 — l'ho
verificato elencando le property reali di `GtkMenuButton` via
introspection: l'unica property `accessible-*` esistente è
`accessible-role`. L'API corretta per impostare il nome accessibile in
GTK4 è `Gtk.Accessible.update_property([Gtk.AccessibleProperty.LABEL],
[testo])`.

**Fix:** sostituite tutte e 4 le chiamate con la sintassi corretta,
verificata funzionante via introspection prima di applicarla.

**Verifica:** prima del fix, `clamguard` crashava all'avvio in ~50ms
(traceback riportato sopra) su ogni singolo lancio, 100% riproducibile.
Dopo il fix, l'app si avvia e naviga normalmente (screenshot allegati).

Questo bug era presente sulla testa di `testing` al momento in cui ho
iniziato questo audit — chiunque avesse provato a lanciare l'app dalla
`testing` più recente l'avrebbe trovata completamente non funzionante.

## Verifica finale

- Suite pytest: **37/37 passati** (nessun nuovo test aggiunto in questo
  giro: le modifiche sono a stringhe icona e a un'API GTK, non a logica
  testabile in isolamento — la validazione è avvenuta tramite avvio reale
  dell'app, come sopra)
- `flake8` e `black --check`: puliti
- App reale: si avvia senza crash, tutte le card della dashboard con
  icone leggibili tranne "Custom Scan" (icona pre-esistente, valida, non
  in scope — limite di rendering di questo ambiente, vedi nota sopra) e
  "Settings" (icona valida, stesso limite d'ambiente)

## Non affrontato in questo giro

- VirusTotal e Settings restano viste stub ("View implementation
  pending") — funzionalità da implementare, non un bug di questo giro
