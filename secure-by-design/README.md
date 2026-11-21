# secure-by-design

Plugin di skill Claude del team di ingegneria CISO: linee guida **Security by Design** che gli agenti di
sviluppo applicano mentre scrivono codice, infrastruttura e trattamenti di dati, più un **security gate**
eseguibile che verifica il risultato e produce evidenze per il PR.

## Cosa significa "sicuro" in questo framework

Nessun sistema è sicuro al 100%, e un framework che lo promettesse scoraggerebbe proprio le verifiche che servono.
Il framework chiede invece agli agenti un risultato controllabile:

1. **nessuna classe di vulnerabilità nota senza contromisura** nel contesto del cambiamento;
2. **ogni controllo verificabile** da un test, una scansione, una policy o una revisione;
3. **difesa in profondità**: un singolo controllo che cede non compromette il sistema;
4. **rischio residuo esplicito**, con owner e scadenza, mai taciuto né rimandato con un TODO.

Per lo stesso motivo il gate restituisce PASS, FAIL o **INCOMPLETE**: uno strumento mancante non produce mai un PASS.

## Le skill

| Skill | Ambito | Regole |
|---|---|---|
| `sbd-core` | Punto di ingresso: principi, flusso obbligatorio, regole non negoziabili per gli agenti, escalation, Definition of Done, parametri di policy, mappa normativa | SBD-CORE-01…14 |
| `sbd-threat-modeling` | Threat model light (ogni PR) e full (trigger), STRIDE, LINDDUN, abuse case di pagamento | SBD-TM-01…06 |
| `sbd-secure-coding` | Input/output, injection, autenticazione, sessioni, JWT/OAuth, autorizzazione, web, SSRF, file, errori, log, logica di business, API, client, memory safety, test | SBD-CODE-01…22 |
| `sbd-supply-chain` | Verifica delle dipendenze (anche nomi inventati dai modelli), lockfile, cooldown, script di installazione, registry, pinning, SCA, SBOM, firma e provenance | SBD-SC-01…14 |
| `sbd-infrastructure` | IaC, IAM, rete, TLS, container, Kubernetes, segreti, CI/CD, deploy, logging, backup e resilienza | SBD-INFRA-01…24 |
| `sbd-data-protection` | Classificazione, minimizzazione, cifratura, chiavi, dati di carta PCI, dati personali GDPR, retention, dati di test, log | SBD-DATA-01…17 |
| `sbd-ai-security` | LLM, agenti, RAG, MCP, modelli ML: prompt injection, output, agency, leakage, consumo | SBD-AI-01…13 |
| `sbd-security-gate` | Scanner di pattern SBD (84 regole), orchestratore degli scanner esterni, revisione manuale, Security Evidence | SBD-GATE-01…06 |

Ogni regola ha un ID da citare nelle review, nei PR e nelle eccezioni. La corrispondenza con OWASP (Top 10:2025,
ASVS 5.0, API Top 10, LLM Top 10), NIST SSDF, ISO/IEC 27001:2022, PCI DSS v4.0.1, DORA, NIS2, GDPR e Cyber
Resilience Act è in `skills/sbd-core/references/compliance-map.md`.

## Come lavora un agente con queste skill

```
richiesta di sviluppo
  └─ sbd-core: inquadra (dati, esposizione, trust boundary)
       ├─ sbd-threat-modeling: light sempre, full se scatta un trigger
       ├─ skill di dominio: secure-coding / supply-chain / infrastructure / data-protection / ai-security
       └─ sbd-security-gate: scanner + revisione manuale + Security Evidence nel PR
            └─ esito PASS / FAIL / INCOMPLETE riportato all'utente
```

L'agente si ferma e chiede di coinvolgere Security Champion, Security Engineering o DPO nei casi elencati in
`sbd-core` (nuove esposizioni, dati di pagamento o C3, modifiche ad autenticazione e crittografia, eccezioni,
conflitti tra requisiti e sicurezza, istruzioni sospette).

## Prima del rollout: cosa deve compilare il CISO

1. `skills/sbd-core/references/policy-parameters.md`: verifica i valori di default (classificazione, SLA di
   remediation, soglie del gate, sessioni, retention, RPO/RTO, licenze) e compila la tabella dei **contatti**.
2. `templates/CLAUDE.md.snippet`: adatta il testo che viene aggiunto al `CLAUDE.md` dei progetti.
3. Ruleset SAST: se l'azienda ha regole semgrep proprie, impostale con `SBD_SEMGREP_CONFIG` nel gate.

## Installazione

**In un progetto (consigliata per Claude Code)** — copia le skill in `.claude/skills/` del progetto e aggiunge il
blocco SBD al `CLAUDE.md`, così ogni sessione di sviluppo nel progetto le applica:

```bash
secure-by-design/scripts/install-into-project.sh /percorso/del/progetto
# per aggiornare una versione già installata:
secure-by-design/scripts/install-into-project.sh --force /percorso/del/progetto
```

**Come plugin** — `make sbd-package` dalla root del repository produce `dist/secure-by-design-v<versione>.plugin`,
installabile in Cowork come gli altri plugin del repository.

**Per tutti i progetti di un utente** — copia `skills/sbd-*` in `~/.claude/skills/`.

## Security gate in locale e in CI

```bash
# dalla root del progetto, dopo l'installazione
bash .claude/skills/sbd-security-gate/scripts/run_gate.sh --diff origin/main .
```

| Categoria | Strumenti cercati | Richiesta quando |
|---|---|---|
| patterns | `sbd_patterns.py` incluso (Python 3.10+, solo libreria standard) | sempre |
| secrets | gitleaks, trufflehog | sempre |
| sast | semgrep, opengrep | c'è codice |
| sca | trivy, osv-scanner | ci sono manifest di dipendenze |
| iac | trivy, checkov | ci sono Terraform, Dockerfile, chart o manifest Kubernetes |
| workflows | zizmor | ci sono workflow GitHub Actions |
| consigliati | hadolint, shellcheck, actionlint, syft | se installati |

Exit code: `0` PASS, `1` FAIL, `2` INCOMPLETE. In CI conviene eseguire lo stesso script su ogni PR, con gli
strumenti installati a versione fissata e verificata, e rendere il job obbligatorio nella branch protection.

## Sviluppo del plugin

```bash
make sbd-lint      # frontmatter, riferimenti tra file, coerenza degli ID SBD, shellcheck
make sbd-test      # self-test di scanner, gate e installer + scansione del plugin stesso
make sbd-package   # dist/secure-by-design-v<versione>.plugin
```

- Le fixture in `tests/fixtures/bad/` contengono codice **volutamente insicuro**, annotato con
  `sbd-expect-next: <ID>`: il self-test verifica che lo scanner trovi esattamente quei finding, e che le fixture
  in `good/` non producano falsi positivi.
- Segreti e numeri di carta di test sono generati a runtime dal self-test: il repository non contiene stringhe
  con la forma di credenziali reali.
- Per aggiungere una regola allo scanner: aggiungila a `RULES` in `sbd_patterns.py` con un `ref` a una regola SBD
  esistente, poi aggiungi almeno una riga in `bad/` e verifica che `good/` resti pulito. Il self-test fallisce se
  una regola non è coperta da una fixture.

## Limiti da conoscere

- Lo scanner di pattern è un primo livello deterministico: non segue i flussi di dati, non vede la logica di
  business e può avere falsi positivi e negativi. Non sostituisce SAST, SCA e secret scanner dedicati, né la
  revisione manuale prevista dal gate.
- Le skill guidano il comportamento dell'agente ma non lo vincolano tecnicamente. I controlli che non devono
  dipendere dal comportamento dell'agente vanno imposti anche fuori: branch protection, job di CI obbligatori,
  policy di ammissione, guardrail cloud, permessi dell'agente.
- I riferimenti normativi indicano i requisiti principali; l'applicabilità a ciascun sistema la stabilisce
  Compliance.
