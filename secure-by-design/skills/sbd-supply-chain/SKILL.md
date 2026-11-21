---
name: sbd-supply-chain
description: >
  Sicurezza della software supply chain Security by Design. Usare SEMPRE prima di aggiungere, aggiornare o
  rimuovere una dipendenza (npm, pnpm, yarn, pip, uv, poetry, Maven, Gradle, Go modules, NuGet, Cargo),
  un'immagine Docker base, una GitHub Action o un template CI, un tool scaricato, un SDK, un plugin, un modello
  ML o un server MCP, e quando si configurano lockfile, registry, SBOM, firma degli artefatti o provenance
  SLSA. Previene typosquatting, slopsquatting (pacchetti inventati dai modelli), dependency confusion,
  pacchetti compromessi e script di installazione malevoli. Trigger: "npm install", "pip install",
  "aggiungi libreria", "aggiorna dipendenze", "Renovate", "Dependabot", "SBOM", "cosign", "SLSA",
  "lockfile", "vulnerabilità in una dipendenza", "CVE".
---

# Software supply chain

Ogni dipendenza è codice di terzi che gira con i privilegi della tua applicazione e, durante la build, con
quelli della tua pipeline. Gli incidenti recenti (pacchetti npm compromessi con worm che rubano token,
GitHub Action manomesse che esfiltrano segreti, pacchetti con nomi inventati dai modelli e poi registrati da
attaccanti) mostrano che il rischio si materializza soprattutto in due momenti: **quando si aggiunge** una
dipendenza e **quando si installa** una nuova versione. Le regole che seguono presidiano entrambi.

## Prima di aggiungere una dipendenza

**SBD-SC-01 — Verifica necessità e identità del pacchetto.**
1. Serve davvero? Se la libreria standard o una dipendenza già presente fa il lavoro, non aggiungerne.
   Evita pacchetti per funzioni banali.
2. **Il nome esiste ed è quello giusto?** Controlla sul registry ufficiale che il pacchetto esista, con il nome
   esatto, e che il repository sorgente collegato sia quello del progetto atteso. Un nome che ricordi o che ti è
   stato suggerito (anche da te stesso) può essere inventato: i nomi plausibili ma inesistenti vengono
   registrati apposta da attaccanti (slopsquatting). Diffida di varianti con trattini, underscore, prefissi o
   suffissi rispetto a progetti noti (typosquatting).
3. Se non puoi verificare l'esistenza e l'identità (rete assente, registry non raggiungibile), **non aggiungere
   la dipendenza**: dichiaralo all'utente e chiedi conferma.

**SBD-SC-02 — Valuta salute, reputazione e licenza.** Prima dell'adozione verifica e riporta nel PR:
- età del pacchetto e della versione (default in `sbd-core/references/policy-parameters.md`, sezione 8);
- maintainer attivi, frequenza dei rilasci, issue di sicurezza aperte, numero di utilizzatori;
- punteggio OpenSSF Scorecard quando disponibile;
- vulnerabilità note (OSV, GitHub Advisory) sulla versione scelta;
- presenza di script di installazione (`preinstall`, `install`, `postinstall`, build nativi);
- licenza compatibile con l'allowlist; licenze in lista di review richiedono approvazione legale.

Per le dipendenze che entrano in componenti C3 o nel percorso dei pagamenti, l'adozione di una libreria mai
usata in azienda richiede la revisione del Security Champion.

## Installazione riproducibile

**SBD-SC-03 — Lockfile versionato e installazione frozen.** Il lockfile è committato e la CI installa solo da
lockfile, verificando gli hash di integrità:

| Ecosistema | Installazione in CI |
|---|---|
| npm | `npm ci --ignore-scripts` |
| pnpm | `pnpm install --frozen-lockfile` |
| Yarn (Berry) | `yarn install --immutable` |
| pip | `pip install --require-hashes -r requirements.txt` (file generato con `pip-compile --generate-hashes` o `uv pip compile --generate-hashes`) |
| uv | `uv sync --locked` |
| Poetry | `poetry install` con `poetry.lock` committato; in CI `poetry check --lock` |
| Go | `go mod download && go mod verify`; `GOFLAGS=-mod=readonly`; `GONOSUMDB`/`GOPRIVATE` solo per moduli interni |
| Maven | versioni esplicite (niente range né `LATEST`), plugin `maven-enforcer` con `requireReleaseDeps` |
| Gradle | dependency locking e `gradle/verification-metadata.xml` con checksum |
| NuGet | `packages.lock.json` e `dotnet restore --locked-mode` |
| Cargo | `Cargo.lock` committato, `cargo build --locked` |

Modificare il lockfile è un cambiamento da revisionare: guarda il diff, non solo il manifest.

**SBD-SC-04 — Cooldown sulle nuove versioni.** Non adottare release pubblicate da meno del periodo di cooldown
(default 7 giorni), salvo fix di sicurezza valutati: la maggior parte dei pacchetti compromessi viene
individuata e ritirata nei primi giorni. Configuralo negli strumenti: Renovate `minimumReleaseAge`, pnpm
`minimumReleaseAge`, uv `exclude-newer`, Dependabot `cooldown`.

**SBD-SC-05 — Script di installazione disattivati di default.** Gli script di lifecycle delle dipendenze sono il
vettore principale dei worm della supply chain. npm: `--ignore-scripts` (o `ignore-scripts=true` in `.npmrc`)
con eccezioni esplicite; pnpm 10+: gli script sono bloccati di default, autorizza solo i pacchetti necessari con
`onlyBuiltDependencies`; Bun: `trustedDependencies`. Per Python preferisci wheel a sdist che eseguono codice
in build. La build gira senza segreti di deploy in ambiente (SBD-INFRA-18).

**SBD-SC-06 — Un solo registry controllato, nessuna dependency confusion.** Le dipendenze si risolvono da un
registry o proxy interno (Artifactory, Nexus, CodeArtifact o equivalente) che fa da cache dei registry
pubblici e applica le policy. Pacchetti interni con scope o namespace riservato (`@azienda/`, gruppo Maven
dell'azienda) e mapping esplicito scope → registry. Vietato `--extra-index-url` in pip (mescola indici e
permette di sostituire pacchetti interni con omonimi pubblici): usa un solo `--index-url` verso il proxy.
Registra i nomi dei pacchetti interni anche sui registry pubblici, quando è possibile, per evitarne
l'occupazione.

**SBD-SC-07 — Tutto ciò che si esegue è fissato in modo immutabile.**
- Immagini container: per digest (`image@sha256:…`), con il tag in commento per leggibilità.
- GitHub Actions e template CI di terzi: per SHA completo di 40 caratteri (`uses: org/action@<sha> # vX.Y.Z`),
  mai per tag o branch; preferisci action ufficiali o verificate e riduci al minimo quelle di terzi.
- Tool scaricati in pipeline o nei Dockerfile: versione esatta e verifica di checksum o firma
  (`sha256sum -c`, `cosign verify-blob`, `gpg --verify`).
- Moduli Terraform, chart Helm, plugin: versione esatta da registry interno o fonte ufficiale.

## Monitoraggio e integrità

**SBD-SC-08 — Analisi delle vulnerabilità delle dipendenze (SCA) in CI.** Ogni PR e ogni build esegue la SCA
(osv-scanner, Trivy, Grype, Dependabot, Snyk o equivalente aziendale). Finding Critical o High con fix
disponibile bloccano il merge; gli SLA per ciò che è già in produzione sono in
`sbd-core/references/policy-parameters.md`. Per le vulnerabilità non raggiungibili documenta la valutazione
(VEX). Strumenti con analisi di raggiungibilità (es. `govulncheck`) sono preferiti dove disponibili.

**SBD-SC-09 — SBOM per ogni artefatto.** Ogni immagine, pacchetto o binario rilasciato ha una SBOM
(CycloneDX o SPDX) generata in build (Syft, cdxgen, plugin di build), archiviata con l'artefatto e usata per
l'inventario dei componenti (PCI DSS 6.3.2, DORA art. 8, Cyber Resilience Act).

**SBD-SC-10 — Artefatti firmati con provenance, verificati al deploy.** La pipeline firma gli artefatti
(Sigstore cosign, preferibilmente keyless con identità OIDC della pipeline) e genera attestazioni di
provenance SLSA. Il deploy accetta solo artefatti firmati dalla pipeline attesa: la verifica avviene in
admission control (SBD-INFRA-14) o nello step di deploy. Livello minimo SLSA Build L2, obiettivo L3.

**SBD-SC-11 — Aggiornamenti continui, dipendenze minime.** Aggiornamenti automatici con Renovate o
Dependabot, raggruppati, con test e cooldown. Rimuovi le dipendenze inutilizzate (depcheck, `go mod tidy`,
deptry, plugin di analisi delle dipendenze Maven). Le dipendenze abbandonate (nessun rilascio da oltre due
anni, maintainer irraggiungibili) vanno sostituite pianificandolo.

## Codice e servizi di terzi

**SBD-SC-12 — Codice copiato o generato: stessa disciplina.** Il codice copiato da siti, gist o altri progetti
riporta origine e licenza in un commento e passa la stessa review del codice scritto in casa. Il codice
generato da assistenti AI è codice non revisionato finché un umano non lo approva: verifica che le API e i
pacchetti usati esistano davvero e facciano ciò che il codice presume.

**SBD-SC-13 — Servizi terzi, SaaS, API e server MCP passano dalla valutazione fornitori.** Una nuova
integrazione con un fornitore che riceve dati C2 o C3, o che diventa necessaria al funzionamento del servizio,
richiede la valutazione del rischio di terza parte (DORA art. 28-30, NIS2 art. 21(2)(d)) e, per dati personali,
un accordo sul trattamento (GDPR art. 28). Fermati ed escala prima di integrare. I server MCP e i plugin degli
agenti sono trattati come dipendenze privilegiate: fonte verificata, versione fissata, permessi e token minimi
(`sbd-ai-security`, SBD-AI-13).

## Quando una dipendenza è compromessa

**SBD-SC-14 — Risposta a una compromissione.** Se una dipendenza in uso risulta compromessa (advisory di
malware, versione ritirata dal registry, comportamento anomalo in build):
1. avvisa subito SOC/CSIRT (contatti in `sbd-core/references/policy-parameters.md`);
2. blocca la versione nel registry interno e fissa l'ultima versione nota come sicura;
3. individua dove è stata installata (SBOM, cronologia dei lockfile, log di CI) e considera compromessi i
   segreti accessibili in quegli ambienti: revocali e ruotali;
4. ricostruisci gli artefatti da una base pulita e verifica l'assenza di persistenza (token creati, workflow
   aggiunti, chiavi SSH registrate, pacchetti pubblicati con le tue credenziali).

## Checklist da riportare nel PR quando cambi dipendenze

```markdown
### Dipendenze
| Pacchetto | Versione | Motivo | Esistenza/identità verificata | Età | Licenza | Vulnerabilità note | Script install |
|---|---|---|---|---|---|---|---|
| example-lib | 2.4.1 | parsing ISO 20022 | sì, repo github.com/example/example-lib | 3 anni / release 21 gg | Apache-2.0 | nessuna (osv) | no |
- Lockfile aggiornato e diff revisionato: sì
- SCA eseguita: <strumento, esito>
```
