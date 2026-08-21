# Debito tecnico e valutazioni future — 2026-08-16

Documento per annotare problemi noti, non urgenti, che richiedono una
valutazione più approfondita in un momento successivo. Non contiene azioni
da eseguire subito.

---

## `libdbusmenu`: warning di build massicci, non nostri

**Origine:** segnalato osservando il log completo della CI `flatpak-builder`
sul commit `756d6d6` (PR #19). La build **ha successo** (bundle `.flatpak`
generato correttamente), ma produce un numero molto alto di warning durante
la compilazione del modulo `libdbusmenu` del manifesto Flatpak.

### Cosa sono esattamente

`libdbusmenu` (glib + gtk3) è una libreria C di supporto al menu contestuale
della system tray, dichiarata come modulo `autotools` nel manifesto
(`build-aux/flatpak/io.github.d3msudo.clamguard.json`) e **compilata da
sorgente ad ogni build** da un tarball Launchpad/Canonical del 2016
(`libdbusmenu-16.04.0.tar.gz`) — non un pacchetto di sistema, non nostro
codice.

I warning osservati sono di tre tipi, tutti interni a quel tarball:
- `g_type_class_add_private is deprecated` e macro `G_ADD_PRIVATE` correlate
  (decine di occorrenze, in praticamente ogni file `.c` del modulo)
- API GTK3 deprecate usate dal parser interno di libdbusmenu
  (`gtk_image_menu_item_*`, `gtk_stock_lookup`, `gdk_threads_enter/leave`,
  `gtk_action_*`)
- Warning di `g-ir-scanner`/`vapigen` in fase di generazione introspection
  (tag GTK-Doc deprecati, annotazioni `closure` non valide su non-callback,
  segnali che confliggono con metodi dello stesso nome) e un
  `Package dbusmenu-glib-0.4 was not found in the pkg-config search path`
  durante la generazione del `.gir` di `libdbusmenu-gtk` (rientra comunque
  nel corretto completamento del passo — costruito comunque con successo
  subito dopo via `--pkg Dbusmenu-0.4` esplicito)

**Nessuno di questi è causato da o correggibile in `src/`**: sono tutti
interni al sorgente C di libdbusmenu 16.04.0, un progetto che non riceve
più sviluppo attivo da anni.

Il manifesto già mitiga parzialmente con `"cflags": "-Wno-error"` (i warning
non vengono promossi a errori, altrimenti la build fallirebbe del tutto vista
la quantità).

### Opzioni valutate, nessuna scelta ancora

1. **Non fare nulla** — i warning sono cosmetici, non impediscono la build,
   non hanno impatto a runtime. Costo zero, rumore nei log rimane.
2. **Sopprimere ulteriormente il rumore nel manifesto** — es. reindirizzare
   `stdout`/aggiungere flag di compilazione più aggressivi per silenziare i
   deprecation warning (`-Wno-deprecated-declarations` esplicito invece del
   generico `-Wno-error`). Puramente cosmetico, riduce la leggibilità dei
   log CI in caso di problemi *reali* futuri, non risolve la causa.
3. **Sostituire la dipendenza** — verificare se esiste un fork mantenuto di
   `libdbusmenu`, o se è possibile ottenere lo stesso menu contestuale della
   tray tramite un'altra via (es. libreria di sistema già pacchettizzata nel
   runtime `org.gnome.Platform`, se disponibile, invece di compilare da
   sorgente). Opzione più impegnativa: richiede capire se il menu contestuale
   del tray dipende in modo stretto dalle API GTK3 specifiche di
   `libdbusmenu-gtk3`, e se un'alternativa comprometterebbe la compatibilità
   con gli status area/tray di Cinnamon, XFCE, MATE, KDE che il progetto
   supporta (vedi commenti in `src/services/tray_service.py` sull'interfaccia
   `org.kde.StatusNotifierItem`).

**Nessuna azione presa in questo giro.** Da riprendere quando si deciderà se
vale la pena investire tempo in questo (probabilmente solo se emergeranno
problemi reali di compatibilità/manutenibilità con `libdbusmenu`, non per il
solo rumore nei log).

---

## `po/LINGUAS` mancante — risolto

Per contro, nello stesso log era presente un warning realmente nostro,
**già corretto**: `po/LINGUAS` (l'elenco delle lingue abilitate, richiesto da
meson/msgfmt per il merge delle traduzioni in `.desktop`/`.metainfo.xml`)
non esisteva, nonostante `po/it.po` fosse presente. Aggiunto `po/LINGUAS`
con `it`. Verificato in locale: il passo "Merging translations" ora
completa senza warning.

**Nota collegata — risolta in questo stesso giro:** `po/it.po` conteneva
traduzioni per stringhe UI ormai obsolete (`Scan`, `Quarantine`, `History`,
`VirusTotal`, `Database`, `Settings` — nomenclatura pre-redesign), non più
presenti nell'interfaccia attuale a sidebar (`Dashboard`, `Protection`,
`Privacy`, `Notifications`, `Preferences`). `po/POTFILES.in` referenziava
inoltre 6 file sotto `src/ui/views/` mai esistiti nella struttura attuale
del repository (`window.py` è monolitico).

Rigenerato il `.pot` con la pipeline meson reale (`ninja clamguard-pot`)
per vedere esattamente cosa è davvero estraibile oggi: **solo 3 stringhe**,
tutte dal file `.desktop.in` (`Name`, `Comment`, `Keywords` — chiavi
standard riconosciute automaticamente da `msgfmt --desktop` anche senza il
prefisso `_`). `src/window.py`, pur elencato in `POTFILES.in`, non
contribuisce nessuna stringa: **il codice Python non usa `gettext`/`_()` da
nessuna parte** — nessuna delle etichette UI (anche quelle ancora presenti
letteralmente nel codice, es. "Scan", "VirusTotal") è marcata come
traducibile.

Sincronizzato `it.po` con `msgmerge` (le 6 voci orfane sono state spostate
in coda come commenti `#~`, per storico, non cancellate) e tradotte le 3
stringhe reali. Verificato end-to-end: il `.desktop` generato dalla build
ora contiene davvero `Name[it]=`, `Comment[it]=`, `Keywords[it]=`.

**Resta un lavoro più corposo, non affrontato qui** (fuori scope per un
fix di drift): per una localizzazione reale dell'interfaccia servirebbe
marcare con `_()` le decine di stringhe UI in `src/window.py` — nessuna lo
è oggi, quindi anche con `po/LINGUAS` e `POTFILES.in` corretti, l'app gira
sempre in inglese a prescindere dalla lingua di sistema. Da valutare se e
quando investire in questo (probabilmente non prioritario finché l'app non
è vicina al rilascio pubblico).
