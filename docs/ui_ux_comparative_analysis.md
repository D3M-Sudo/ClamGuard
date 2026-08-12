# Analisi Comparativa UI/UX: ClamGuard vs Bitdefender Antivirus per Mac

Il presente documento descrive l'analisi comparativa tra l'attuale interfaccia utente di **ClamGuard** e il design di riferimento di **Bitdefender Antivirus per Mac**, delineando le discrepanze, il piano d'azione incrementale ed esempi di codice mirati per allineare l'applicazione a standard estetici e funzionali elevati nel contesto Linux desktop.

---

## 1. Report delle Differenze Riscontrate

### 1.1 Layout e Struttura della Sidebar
* **Bitdefender (Riferimento):** Presenta una sidebar scura a sinistra molto marcata, strutturata in tre blocchi principali:
  * **Branding / Stato Visivo:** Un grande scudo verde con un check bianco al centro (un indicatore visivo immediato dello stato).
  * **Menu di Navigazione Principale:** Dashboard, Protection, Privacy, Notifications.
  * **Supporto e Utility in basso:** My Account, Preferences, Help.
  * **Estetica:** Sfondo antracite scuro, icone lineari chiare, selezione evidenziata da un cambio di background soft o un indicatore discreto.
* **ClamGuard (Corrente):**
  * Utilizza un'HeaderBar con un badge di stato e un pulsante "Quick Scan" rapido.
  * La navigazione avviene tramite un `Adw.ViewSwitcherBar` posizionato in basso (stile mobile/responsivo), che presenta tutte le schede in modo piatto: Dashboard, Quarantine, History, VirusTotal, Database, Settings.
  * Non esiste una vera barra laterale scura, riducendo l'impatto visivo di "centro di controllo" di sicurezza dell'applicazione.

### 1.2 Tipografia e Gerarchia del Content Area
* **Bitdefender (Riferimento):**
  * **Titoli Generosi:** Il titolo "You are safe" utilizza un font bold e ampio, accompagnato da un sottotitolo descrittivo pulito ed elegante.
  * **Card Arrotondate (Bordi Marcati):** Le sezioni sono inserite in card di colore bianco puro con un `border-radius` marcato (circa `18px` o `24px`) e ombreggiature molto morbide su uno sfondo grigio chiarissimo (`#f5f5f7`).
  * **Banner di Raccomandazione:** Un container orizzontale in alto con angoli arrotondati, testata grigia per la paginazione interattiva (`< 1/3 >`), un testo di invito all'azione e pulsanti dedicati ("Scan" in blu pieno, "Not now" in stile link).
  * **Griglia delle Scansioni:** Box paralleli per "Quick Scan" e "System Scan" con icone illustrative, sottotitoli di categoria e pulsanti a pillola con bordo sottile ("Start Scan").
  * **Card di Stato a Tre Colonne in Basso:** Opzioni rapide come "Premium Security", "Safe Files" con toggle integrato, e "Web Protection" con indicatori colorati.
* **ClamGuard (Corrente):**
  * Lo stato principale della Dashboard è racchiuso in una card orizzontale grigia con una struttura a due colonne (Icona + Stato a sinistra, Statistiche a destra).
  * Le azioni secondarie sono disposte in una griglia generica 3x2 che include: System Scan, Custom Scan, Quarantine, VirusTotal, Update DB, Settings.
  * L'estetica segue strettamente i colori standard di Libadwaita senza forzare il contrasto forte bicolore (Scuro/Chiaro) tipico di Bitdefender.

### 1.3 Palette Colori e Stati
* **Bitdefender (Riferimento):**
  * **Sidebar:** Antracite scuro (`#11161d` o simile).
  * **Sfondo Content Area:** Grigio chiarissimo neutro (`#f5f5f7`).
  * **Card:** Bianco puro (`#ffffff`).
  * **Accenti di Stato:** Verde brillante (`#22c55e` o simile) per lo stato protetto. Blu di sistema (`#0066cc`) per le azioni principali.
* **ClamGuard (Corrente):**
  * Utilizza i colori standard del tema Libadwaita (`@card_bg_color`, `@window_bg_color`). Se l'utente usa il tema scuro, l'intera applicazione diventa scura; se usa il tema chiaro, diventa interamente chiara. Manca il bicolore forzato che conferisce identità all'applicazione.

---

## 2. Piano d'Azione Incrementale

### Fase 1: Riorganizzazione Strutturale di `src/window.py`
1. **Rimuovere l'Adw.ViewSwitcherBar in basso** e riprogettare la navigazione.
2. **Creare un layout orizzontale principale (`Gtk.Box`)**:
   * **Sinistra (Sidebar):** Un box verticale con classe CSS `.sidebar-dark`. All'interno inseriremo:
     * Il widget dello Scudo di Stato (Grande cerchio/scudo con icona dinamica protetto/rischio).
     * Un `Gtk.ListBox` o pulsanti verticali per: Dashboard, Protection, Privacy.
     * Un box in fondo per: My Account (placeholder), Preferences (Settings), Help (About dialog).
   * **Destra (Content Area):** Un `Gtk.Stack` o `Adw.ViewStack` racchiuso in un container con classe CSS `.content-area`.
3. **Mappatura delle Schede dello Stack:**
   * **Dashboard:** Nuovo layout con il titolo grande "You are safe", il Widget delle Raccomandazioni, e la griglia con Quick Scan / System Scan e i moduli di stato.
   * **Protection:** Una vista unificata che contiene la sezione di avvio Custom Scan, la lista della Cronologia delle scansioni e la gestione del Database delle firme.
   * **Privacy:** Una vista unificata che contiene la lista dei file in Quarantena e l'integrazione di verifica VirusTotal.
   * **Preferences (Settings):** La pagina delle impostazioni esistente.

### Fase 2: Implementazione dei Nuovi Componenti in `src/window.py`
1. **Widget Raccomandazioni Interattivo (Recommendation Banner):**
   * Creare una classe o un metodo helper per gestire una lista di dizionari contenente le raccomandazioni correnti:
     * Slide 1: System Scan Recommendation (Azione: esegue System Scan).
     * Slide 2: VirusTotal Integration (Azione: sposta l'utente sulla scheda Settings per configurare la chiave API).
     * Slide 3: Database Signatures Update (Azione: avvia l'aggiornamento firme).
   * Visualizzare il contatore (es. "1/3") e gestire i click sui pulsanti freccia `<` e `>` per aggiornare i testi e l'azione associata in modo fluido.
2. **Card di Scansione Principali:**
   * Disegnare i pulsanti "Quick Scan" e "System Scan" all'interno della Dashboard come card ampie con icone grandi a sinistra, testi descrittivi e pulsante a pillola "Start Scan".
3. **Moduli di Stato Inferiori:**
   * Card "Premium Security" (mostra le statistiche aggregate come file scansionati/minacce bloccate).
   * Card "Safe Files" (collegata al toggle di crittografia quarantena).
   * Card "Web Protection" (mostra indicatori di stato simulati dei browser più noti).

### Fase 3: Forzatura del Tema Visivo via CSS in `src/main.py`
1. Modificare `_setup_css` per definire colori specifici:
   * Sfondo della Sidebar: `#11161d`.
   * Testi e icone della Sidebar: colori chiari/bianco ad alto contrasto.
   * Sfondo della Content Area: `#f5f5f7`.
   * Sfondo delle Card: `#ffffff` con bordo grigio molto sottile e arrotondamento a `18px`.
   * Pulsanti primari in blu e pulsanti a pillola outline per "Start Scan".

---

## 3. Esempio di Codice Mirato per la Struttura e lo Stile

Ecco come verrà modificata l'architettura principale in ClamGuard per ottenere questo look:

```python
# Esempio di struttura della Sidebar scura e del layout a due colonne
class ClamGuardWindow(Adw.ApplicationWindow):
    def _build_ui(self):
        # Layout orizzontale principale
        self.main_layout = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_content(self.main_layout)

        # 1. SIDEBAR SCURA
        self.sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.sidebar.add_css_class("sidebar-dark")
        self.sidebar.set_size_request(260, -1)

        # Scudo di stato nella sidebar
        self.shield_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.shield_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.shield_icon.add_css_class("sidebar-shield")
        self.shield_box.append(self.shield_icon)
        self.sidebar.append(self.shield_box)

        # Lista di navigazione
        self.nav_list = Gtk.ListBox()
        self.nav_list.add_css_class("sidebar-nav")
        # Aggiungere righe per Dashboard, Protection, Privacy...
        self.sidebar.append(self.nav_list)

        # Sezione inferiore (Preferences, Help)
        self.bottom_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        # Aggiungere voci di supporto...
        self.sidebar.append(self.bottom_box)

        self.main_layout.append(self.sidebar)

        # 2. CONTENT AREA CHIARA
        self.content_area = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.content_area.add_css_class("content-area-light")
        self.content_area.set_hexpand(True)

        # View Stack per le viste principali
        self.view_stack = Adw.ViewStack()
        self.content_area.append(self.view_stack)

        self.main_layout.append(self.content_area)
```

In questo modo l'applicazione mantiene tutta la robustezza di Libadwaita per la gestione del ciclo di vita dei widget, ma assume un'estetica professionale e moderna ispirata al design Bitdefender.
