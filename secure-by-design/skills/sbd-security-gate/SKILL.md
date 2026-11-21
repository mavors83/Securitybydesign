---
name: sbd-security-gate
description: >
  Security gate Security by Design: verifica obbligatoria prima di dichiarare concluso un task, prima di ogni
  commit, push o pull request, e quando viene chiesta una security review, un controllo di sicurezza o una
  verifica di vulnerabilità. Esegue lo scanner di pattern SBD incluso (segreti, PAN, crittografia debole, TLS
  disattivato, injection, deserializzazione, Docker, Kubernetes, Terraform, GitHub Actions) e gli scanner
  esterni disponibili (gitleaks, semgrep, trivy, osv-scanner, checkov, zizmor, hadolint, shellcheck), guida la
  revisione manuale per dominio e produce il blocco Security Evidence per il PR con esito PASS, FAIL o
  INCOMPLETE. Trigger: "ho finito", "pronto per il merge", "apri la PR", "commit", "security review",
  "controlla la sicurezza", "è sicuro?", "scan", "SAST", "vulnerabilità", "prima del rilascio".
---

# Security gate

Il gate è il momento in cui si passa da "credo che sia sicuro" a "ho verificato questi controlli con questi
strumenti, con questo esito". Ha tre parti: **verifica automatica** (scanner), **revisione mirata** (ciò che gli
scanner non vedono: autorizzazione, logica di business, flussi di dati) e **evidenza** (cosa è stato verificato e
cosa no, scritto nel PR).

## Regole

**SBD-GATE-01 — Esegui il gate prima di dichiarare concluso il lavoro.** Prima di comunicare all'utente che un
task è finito, prima di commit, push e apertura di PR. Per un PR usa la modalità diff rispetto al branch di
destinazione; prima di un rilascio esegui la scansione completa.

**SBD-GATE-02 — Riporta l'esito esattamente com'è.** PASS solo se tutte le categorie richieste sono state
eseguite senza finding bloccanti. Se uno strumento manca o fallisce l'esito è INCOMPLETE o FAIL, e lo dici
all'utente indicando cosa non è stato verificato. Non riformulare un INCOMPLETE come "nessun problema trovato".

**SBD-GATE-03 — Correggi, non sopprimere.** Un finding si chiude correggendo il codice. La soppressione è ammessa
solo per un falso positivo verificato, sulla riga interessata, con ID della regola e motivazione
(`sbd-ignore: <ID> <motivazione>`, oppure il meccanismo nativo dello scanner con motivazione). Vietati:
soppressioni di massa, esclusioni di directory di codice applicativo, modifiche alla configurazione degli
scanner o alle soglie per far passare il gate, disattivazione di job di CI (SBD-CORE-02). Per un finding vero
che non puoi correggere nel task serve un'eccezione (`sbd-core/references/policy-parameters.md`, sezione 9).

**SBD-GATE-04 — Un segreto trovato si revoca.** Se il gate trova un segreto reale, rimuoverlo dal codice non
basta: è nella cronologia git e potenzialmente già copiato. Avvisa l'utente, che deve revocarlo e ruotarlo
subito, e segnala al SOC se il repository è condiviso o il segreto è di produzione.

**SBD-GATE-05 — La revisione manuale è parte del gate.** Gli scanner non trovano autorizzazione mancante, IDOR,
errori di logica di business, dati sensibili nei flussi sbagliati. Esegui la checklist di revisione per i domini
toccati dal cambiamento.

**SBD-GATE-06 — Evidenza nel PR.** Ogni PR contiene il blocco *Security Evidence* compilato con il template in
`references/security-evidence-template.md`.

## Procedura

### 1. Verifica automatica

Lo script si trova nella directory di questa skill. Dalla root del progetto:

```bash
# PR: solo le modifiche rispetto al branch di destinazione
bash <directory-della-skill>/scripts/run_gate.sh --diff origin/main .

# Rilascio o prima adozione: scansione completa
bash <directory-della-skill>/scripts/run_gate.sh .
```

Categorie e strumenti, nell'ordine in cui vengono cercati:

| Categoria | Richiesta quando | Strumenti |
|---|---|---|
| `patterns` | sempre | `scripts/sbd_patterns.py` (incluso, solo Python 3.10+) |
| `secrets` | sempre | gitleaks, trufflehog |
| `sast` | ci sono file di codice | semgrep, opengrep (regole da `SBD_SEMGREP_CONFIG`, default `p/default`) |
| `sca` | ci sono manifest di dipendenze | trivy, osv-scanner |
| `iac` | ci sono Terraform, Dockerfile, chart o manifest Kubernetes | trivy, checkov |
| `workflows` | ci sono workflow GitHub Actions | zizmor |
| consigliati | se lo strumento è installato | hadolint, shellcheck, actionlint, syft (SBOM) |

Esiti: `0` PASS, `1` FAIL, `2` INCOMPLETE. Lo script scrive log per categoria e un `summary.md` pronto da incollare
nel PR. Gli strumenti primari (trivy per `sca` e `iac`) applicano le soglie di policy (bloccano su High/Critical,
ignorano le vulnerabilità senza fix); i fallback (osv-scanner, checkov) sono più severi e bloccano su qualsiasi
finding, quindi lo stesso progetto può avere un esito diverso secondo lo strumento installato: in caso di FAIL,
verifica la severità reale dei finding nel log prima di trattarli come bloccanti. Se uno strumento richiesto manca, chiedi all'utente se installarlo: installalo solo da fonte ufficiale, a
versione fissata e con verifica di checksum o firma (SBD-CORE-10). Nella CI aziendale gli stessi strumenti
devono essere già presenti.

Lo scanner di pattern si può usare anche da solo:

```bash
python3 <directory-della-skill>/scripts/sbd_patterns.py --diff origin/main .   # righe modificate
python3 <directory-della-skill>/scripts/sbd_patterns.py --list-rules           # catalogo delle regole
python3 <directory-della-skill>/scripts/sbd_patterns.py --json --fail-on medium src/
```

Soppressioni: `sbd-ignore: <ID>[,<ID>] <motivazione di almeno 10 caratteri>` in coda alla riga interessata, o su
una riga di solo commento immediatamente sopra. Un file `.sbdignore` nella root del progetto (un glob per riga)
esclude percorsi: va usato solo per codice di terzi, codice generato o fixture di test, ogni voce con un commento
che la motivi. Lo scanner redige i segreti nell'output: non incollare mai i valori originali in chat o nei ticket.

### 2. Triage dei finding

Per ogni finding:
1. **Vero positivo** → correggi seguendo il `Fix` indicato e la regola SBD citata, poi riesegui il gate.
2. **Falso positivo** → verifica davvero (leggi il contesto, il flusso dei dati), poi sopprimi con motivazione.
3. **Vero positivo non risolvibile ora** → fermati, informa l'utente, avvia il processo di eccezione.

Le vulnerabilità di dipendenze senza fix disponibile seguono `sbd-core/references/policy-parameters.md`, sezione 3.

### 3. Revisione manuale mirata

Rispondi a ogni domanda pertinente ai domini toccati. Una risposta "non so" è un punto da verificare, non un
"sì".

**Codice applicativo e API** (`sbd-secure-coding`)
- Ogni endpoint nuovo o modificato richiede autenticazione? Il default del framework è "nega"? (SBD-CODE-09)
- Ogni accesso a una risorsa tramite ID verifica owner o tenant lato server? C'è un test che prova l'accesso
  di un altro utente? (SBD-CODE-09, -21)
- Gli input sono validati con schema e i campi sconosciuti rifiutati? (SBD-CODE-01)
- Le query sono parametrizzate, anche quelle "interne"? (SBD-CODE-03)
- Importi, stati e limiti sono calcolati e imposti server-side, con idempotenza dove serve? (SBD-CODE-16)
- Gli errori restituiscono messaggi generici e i log non contengono dati sensibili? (SBD-CODE-14, -15)
- Ci sono timeout, limiti di dimensione e paginazione? (SBD-CODE-17)

**Dipendenze** (`sbd-supply-chain`)
- Ogni nuova dipendenza è stata verificata (esistenza, identità, età, licenza, vulnerabilità)? (SBD-SC-01, -02)
- Il lockfile è aggiornato e il suo diff è stato letto? (SBD-SC-03)

**Infrastruttura** (`sbd-infrastructure`)
- Nessuna nuova esposizione pubblica non prevista dal threat model? (SBD-INFRA-07, -08)
- Permessi IAM e RBAC minimi, senza wildcard? (SBD-INFRA-04, -13)
- Container non root, immagini per digest? (SBD-INFRA-11, -12)
- Segreti solo dal secret manager? (SBD-INFRA-15)
- Workflow CI con permessi minimi, action per SHA, nessuna interpolazione di input non fidati? (SBD-INFRA-18)

**Dati** (`sbd-data-protection`)
- Ogni dato nuovo è classificato e i controlli corrispondono alla matrice? (SBD-DATA-01)
- Nessun PAN o SAD conservato, nessun dato reale nei test? (SBD-DATA-06, -11)
- Retention e cancellazione definite per i nuovi store, comprese le copie derivate? (SBD-DATA-08, -14)

**AI** (`sbd-ai-security`)
- L'output del modello è validato prima dell'uso? I tool agiscono con i permessi dell'utente? (SBD-AI-01, -03)
- Esiste la combinazione dati privati + contenuto non fidato + canale di uscita? Come è mitigata? (SBD-AI-04)

**Threat model** (`sbd-threat-modeling`)
- Il threat model light è nel PR? Scattava un trigger per il full? (SBD-TM-01, -02)

### 4. Evidenza

Compila il blocco *Security Evidence* (`references/security-evidence-template.md`) e inseriscilo nella
descrizione del PR. Includi il `summary.md` del gate. Indica in modo esplicito le verifiche non eseguite.

## Come comunicare l'esito all'utente

```text
Security gate: INCOMPLETE
- patterns: PASS (sbd_patterns, diff rispetto a origin/main)
- secrets: NOT_RUN — gitleaks non installato
- sast: PASS (semgrep p/default)
- sca: PASS (trivy, soglia HIGH/CRITICAL)
Revisione manuale: autorizzazione object-level verificata con test (OrderAccessTest), nessuna nuova esposizione.
Non verificato: scansione dei segreti. Consiglio di installare gitleaks o di affidarsi al job di CI prima del merge.
```

## Riferimenti

- `scripts/run_gate.sh` — orchestratore del gate (bash, compatibile con bash 3.2 di macOS).
- `scripts/sbd_patterns.py` — scanner di pattern SBD, solo libreria standard Python.
- `references/security-evidence-template.md` — template del blocco Security Evidence per il PR.
