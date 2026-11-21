# Fixture dello scanner sbd_patterns.py

- `bad/` contiene codice **volutamente insicuro**: ogni riga attesa è preceduta da un commento
  `sbd-expect-next: <ID regola>`. Il self-test verifica che lo scanner trovi esattamente quei finding.
- `good/` contiene le versioni sicure: lo scanner non deve trovare nulla (verifica dei falsi positivi).
- Le fixture per segreti e PAN sono generate a runtime dal self-test, così il repository non contiene
  stringhe con la forma di credenziali reali.

Non copiare il codice di `bad/` in progetti reali. Questa directory è esclusa dalle scansioni tramite
`secure-by-design/.sbdignore`.
