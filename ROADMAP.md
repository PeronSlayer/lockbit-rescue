# Roadmap prossimi miglioramenti

Questa roadmap raccoglie i prossimi sprint consigliati per migliorare il tool, ordinati per impatto pratico e riduzione del rischio operativo.

## Sprint 7 - Release e distribuzione

Obiettivo: rendere le release pulite, affidabili e facili da scaricare.

- Stabilizzare definitivamente il workflow release.
- Pubblicare release normali, non prerelease.
- Usare naming pulito: `release-YYYY.MM.DD-run`.
- Garantire sempre gli asset `.tar.gz`, `.zip` ed `.exe`.
- Pulire automaticamente le vecchie release `auto-*`.
- Generare `SHA256SUMS.txt` e allegarlo alla release.
- Documentare la verifica dei checksum.
- Valutare firma GPG opzionale degli artifact.
- Migliorare il pacchetto Windows con cartella root chiara e `README-WINDOWS.txt`.

## Sprint 8 - UX Recovery

Obiettivo: rendere il tool piu utile per utenti non esperti e vittime che devono recuperare dati reali.

- Migliorare il wizard guidato.
- Validare meglio le directory scelte.
- Controllare spazio disco disponibile prima della recovery.
- Rilevare WSL su Windows e guidare l'utente.
- Aggiungere riepilogo finale prima dell'avvio.
- Estendere `--plan-only` con stima recoverability per gruppo.
- Mostrare oracle validi, motivi di skip e file potenzialmente recuperabili con Phase 2.
- Aggiungere report HTML oltre al JSON.
- Rendere i messaggi CLI piu chiari e gli exit code piu stabili.

## Sprint 9 - Recovery Quality

Obiettivo: aumentare qualita del recupero, tracciabilita e riduzione dei falsi positivi.

- Aggiungere manifest completo `manifest.csv` e `manifest.json`.
- Mappare sorgente encrypted, output recovered, stato, motivo skip/failure e gruppo KEK.
- Gestire collisioni di basename in output.
- Definire una policy stabile per nomi duplicati.
- Rafforzare la verifica contenuti con magic bytes, estensione e dimensioni attese.
- Migliorare euristiche per PDF, JPEG, ZIP e Office.
- Rendere il resume piu robusto con cache stato run.

## Sprint 10 - Performance

Obiettivo: far scalare meglio il tool su dataset grandi.

- Ottimizzare scanner directory e progress reporting.
- Introdurre batching e skip anticipati su size/ext.
- Separare limiti CPU e I/O.
- Aggiungere profili `safe`, `balanced` e `fast`.
- Rendere la cache keystream versionata e invalidabile in modo sicuro.
- Creare benchmark suite con dataset sintetici.

## Sprint 11 - CI e qualita progetto

Obiettivo: evitare regressioni e release rotte.

- Stabilizzare definitivamente CI e release workflow.
- Validare workflow con `actionlint`.
- Validare shell script con `shellcheck`.
- Espandere test pytest per CLI, JSON report, manifest, collisioni output e plan-only.
- Aggiungere lint Python con `ruff`.
- Introdurre type checks graduali sui moduli nuovi.

## Sprint 12 - Sicurezza e governance

Obiettivo: rendere il progetto piu serio, mantenibile e sicuro.

- Aggiungere `SECURITY.md`.
- Chiarire scope di uso legittimo e segnalazione bug.
- Aggiungere issue templates per bug, recovery help e feature request.
- Migliorare release notes automatiche.
- Aggiungere lista artifact e checksum nelle release notes.
- Pin versioni GitHub Actions dove opportuno.
- Configurare Dependabot per GitHub Actions e pip.

## Priorita consigliata

1. Sprint 7: chiudere release, checksum e pacchetto Windows.
2. Sprint 9: manifest, deduplica e qualita recovery.
3. Sprint 8: wizard e UX per utenti non esperti.
4. Sprint 11: CI, lint e test piu solidi.
5. Sprint 10: performance dopo stabilizzazione comportamento.
6. Sprint 12: governance e supply chain hardening.

La roadmap Sprint 7-12 risulta completata al 2026-05-28.

## Stato avanzamento (2026-05-28)

- Sprint 7: completato
- Sprint 8: completato
- Sprint 9: completato
- Sprint 10: completato
- Sprint 11: completato
- Sprint 12: completato

## Nota finale

Le attivita previste nei sei sprint sono state implementate e documentate in codice, workflow, test e documentazione.