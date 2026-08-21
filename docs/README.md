# Documentazione ClamGuard

Questa cartella contiene la documentazione di progetto, organizzata per argomento.

## Struttura

```
docs/
├── README.md                                    # Questo indice
├── FIX_TRACKER.md                               # Tracciamento attivo dei fix della code review
├── technical_debt_and_future_considerations.md  # Note su debito tecnico e valutazioni future
├── design/                                      # Ricerca, visione architetturale e analisi UI/UX
│   ├── PHASE0_SYNTHESIS.md                      # Sintesi della ricerca iniziale (Fase 0)
│   └── ui_ux_comparative_analysis.md            # Analisi comparativa UI/UX con Bitdefender
└── audits/                                      # Storico degli audit tecnici e dei bug hunt
    ├── clamguard_bughunt_report_20260809.md     # Report bug hunting sessione 3 (analisi statica)
    └── consolidated_audit_august_2026.md        # Audit consolidato: scan, dashboard, icone, VirusTotal, QA
```

## Documenti attivi

- **`FIX_TRACKER.md`**: traccia lo stato dei fix derivati dalla code review (`clamguard_review_report.md`), con priorità e note di dettaglio.
- **`technical_debt_and_future_considerations.md`**: annota problemi noti non urgenti (es. warning di build di `libdbusmenu`, localizzazione i18n) da valutare in futuro.

## Ricerca e design (`design/`)

- **`PHASE0_SYNTHESIS.md`**: sintesi della ricerca condotta prima dello sviluppo, con la mappatura proposta→implementata di ciascuna funzionalità.
- **`ui_ux_comparative_analysis.md`**: analisi comparativa tra l'interfaccia di ClamGuard e il design di riferimento Bitdefender, con piano d'azione incrementale.

## Storico audit (`audits/`)

- **`clamguard_bughunt_report_20260809.md`**: report della sessione di bug hunting del 09/08/2026 (analisi statica con Ruff, Bandit, mypy, vulture).
- **`consolidated_audit_august_2026.md`**: consolidamento dei cinque audit eseguiti tra l'11 e il 13 agosto 2026 (pipeline di scansione, dashboard, icone/crash, VirusTotal/Settings, QA completo).