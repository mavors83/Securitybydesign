---
name: sbd-infrastructure
description: >
  Sicurezza dell'infrastruttura applicativa Security by Design: cloud (AWS, Azure, GCP), Infrastructure as Code
  (Terraform, OpenTofu, Bicep, CloudFormation, Helm, Kustomize), IAM e identità dei workload, rete e
  segmentazione, TLS e certificati, Docker e immagini container, Kubernetes, gestione dei segreti, pipeline
  CI/CD (GitHub Actions, GitLab CI, Azure DevOps, Jenkins), deploy, logging, monitoraggio, backup e resilienza.
  Usare ogni volta che si scrive o modifica un file .tf, un Dockerfile, un manifest Kubernetes o un chart, un
  workflow CI/CD, una policy IAM, una security group o regola firewall, una configurazione di gateway o
  ingress, o si decide dove e come gira un servizio. Trigger: "terraform", "Dockerfile", "deployment",
  "helm", "kubernetes", "bucket", "IAM", "security group", "pipeline", "GitHub Actions", "segreti",
  "vault", "ingress", "WAF", "backup".
---

# Infrastruttura applicativa

L'infrastruttura è codice e si governa come il codice: versionata, revisionata, testata e scansionata. In più
ha una caratteristica che il codice applicativo non ha: un singolo errore di configurazione (un bucket
pubblico, una policy con `*`, una porta aperta a Internet) espone in un colpo tutto quello che c'è dietro.
Per questo qui il principio guida è **guardrail a più livelli**: il modulo IaC nasce sicuro, la policy as code
blocca le deviazioni in CI, i guardrail dell'organizzazione cloud bloccano ciò che sfugge alla CI.

Per configurazioni concrete leggi i riferimenti: `references/cloud-iac.md`,
`references/containers-kubernetes.md`, `references/cicd-pipelines.md`.

## Governance

**SBD-INFRA-01 — Tutto as code, revisionato e scansionato; niente modifiche manuali.** Ogni risorsa di
ambienti condivisi è definita in IaC, revisionata in PR, scansionata (Trivy config, Checkov, KICS) e validata da
policy as code (OPA/Conftest, Sentinel, Azure Policy, AWS SCP/Config). Il drift tra codice e realtà viene
rilevato e corretto. Le modifiche d'emergenza da console sono eccezionali, tracciate e riportate in IaC entro
24 ore.

**SBD-INFRA-02 — Stato IaC protetto e senza segreti.** Lo state di Terraform/OpenTofu è remoto, cifrato con
chiave gestita, con locking, versioning e accesso limitato alla pipeline e a pochi amministratori. Evita che i
segreti finiscano nello state: generali e conservali nel secret manager e passali per riferimento; con
Terraform ≥ 1.10 usa risorse `ephemeral` e, da 1.11, argomenti write-only dove i provider li supportano.
Mai `terraform.tfstate` o `*.tfvars` con segreti nel repository.

## Identità e accessi

**SBD-INFRA-03 — Nessuna credenziale statica per i workload.** Servizi, job e pipeline si autenticano con
identità federate a vita breve: IAM roles e IRSA/EKS Pod Identity su AWS, Managed Identity e Workload
Identity su Azure, Workload Identity su GCP, OIDC dalla pipeline verso il cloud. Niente access key, service
account key JSON o client secret di lunga durata; dove inevitabili, nel secret manager con rotazione
(SBD-INFRA-15).

**SBD-INFRA-04 — IAM a privilegio minimo, guardrail a livello di organizzazione.** Policy con azioni e risorse
esplicite: niente `"Action": "*"`, `"Resource": "*"` su azioni di scrittura, ruoli `Owner`/`Editor`/
`Contributor` primitivi ai workload, né `iam:PassRole` senza vincoli. Condizioni dove possibile (tag, VPC
endpoint, organizzazione). Guardrail di organizzazione (SCP, Azure Policy, Organization Policy) che negano
almeno: disattivazione dei log di audit, uscita dalle regioni ammesse, risorse pubbliche, creazione di chiavi
statiche. Permessi rivisti periodicamente; quelli inutilizzati rimossi.

**SBD-INFRA-05 — Accesso umano solo con SSO, MFA e privilegi temporanei.** Accesso a cloud, cluster e sistemi
tramite SSO aziendale con MFA resistente al phishing per i ruoli privilegiati. Privilegi amministrativi
just-in-time con approvazione e scadenza (PAM). Account break-glass custoditi, con MFA, monitorati con alert
a ogni uso. Niente utenti locali condivisi.

**SBD-INFRA-06 — Ambienti separati.** Produzione, pre-produzione e sviluppo in account/subscription/project
distinti, con identità, reti, chiavi e segreti distinti. Nessuna credenziale di produzione utilizzabile da
ambienti non di produzione. Nessun dato di produzione fuori dalla produzione (SBD-DATA-11).

## Rete

**SBD-INFRA-07 — Segmentazione e nessuna esposizione diretta di servizi interni.** Reti a livelli: edge
pubblico, servizi applicativi in subnet private, dati in subnet isolate. Database, cache, code, broker e
pannelli amministrativi non hanno IP pubblici né regole da `0.0.0.0/0`. Servizi PaaS raggiunti tramite private
endpoint o private service connect, con accesso pubblico disabilitato. I sistemi nell'ambito PCI stanno in un
segmento dedicato e verificato.

**SBD-INFRA-08 — Ingresso dall'edge controllato, uscita filtrata.** Il traffico da Internet entra solo da load
balancer, API gateway o ingress con TLS, WAF (regole OWASP CRS gestite e regole specifiche), protezione DDoS
e rate limiting. Il traffico in uscita verso Internet passa da NAT/egress gateway o proxy con allowlist di
destinazioni per i workload che trattano dati C2-C3: limita esfiltrazione, SSRF e comunicazione con
infrastrutture di comando e controllo.

**SBD-INFRA-09 — Accesso amministrativo mai esposto.** Nessuna porta SSH, RDP o di gestione aperta a Internet.
Accesso tramite servizi senza bastion esposto (AWS SSM Session Manager, Azure Bastion, GCP IAP) con SSO,
MFA e registrazione della sessione. API server Kubernetes privato o con allowlist ristretta.

**SBD-INFRA-10 — TLS ovunque, gestito automaticamente.** TLS 1.2 minimo, 1.3 preferito, solo cipher suite AEAD;
nessun protocollo in chiaro, anche internamente, per dati C1 e superiori. mTLS tra servizi per flussi C2-C3
(service mesh o librerie). Certificati emessi e rinnovati automaticamente (ACME, cert-manager, servizi
gestiti), CA privata per l'interno, inventario dei certificati con alert di scadenza. Nessun certificato
autofirmato in produzione. Prepara la migrazione post-quantum (`sbd-data-protection/references/crypto-and-keys.md`).

## Calcolo e container

**SBD-INFRA-11 — Immagini minime, fissate, scansionate, firmate, non root.** Immagini base minime e mantenute
(distroless, Chainguard/Wolfi, UBI-micro, Alpine se adeguata) fissate per digest, build multi-stage senza
toolchain nell'immagine finale, utente non root con UID numerico, nessun segreto nei layer (BuildKit
`--mount=type=secret`), immagini ricostruite regolarmente per incorporare le patch, scansione in CI e nel
registry, firma e SBOM (SBD-SC-09, -10).

**SBD-INFRA-12 — Runtime dei container ristretto.** `runAsNonRoot`, `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`; mai
`privileged`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` per i workload applicativi; richieste e limiti di
CPU e memoria definiti. Template in `references/containers-kubernetes.md`.

**SBD-INFRA-13 — Kubernetes in profilo restricted.** Namespace con Pod Security Admission `restricted` in
enforce; NetworkPolicy default-deny in ingresso e in uscita per namespace, con aperture esplicite (incluso il
DNS); RBAC minimo, niente `cluster-admin` ai workload né verbi o risorse wildcard; un ServiceAccount per
applicazione con `automountServiceAccountToken: false` se non serve l'API; secret di Kubernetes cifrati a
riposo con KMS, preferibilmente alimentati da un secret manager esterno (External Secrets Operator, CSI
driver); audit log dell'API server attivo.

**SBD-INFRA-14 — Admission control che impone le policy.** Kyverno, OPA Gatekeeper o ValidatingAdmissionPolicy
bloccano in produzione i pod che violano SBD-INFRA-12/13, le immagini da registry non autorizzati, i tag
mutabili e le immagini non firmate dalla pipeline attesa (verifica cosign).

**SBD-INFRA-15 — Segreti in un secret manager centrale, a vita breve, ruotati.** Segreti solo in Vault, AWS
Secrets Manager, Azure Key Vault, GCP Secret Manager o equivalente approvato; letti a runtime dall'identità
del workload; credenziali dinamiche (database, cloud) dove possibile; rotazione automatica; accessi registrati;
un segreto per servizio e per ambiente. Mai in variabili committate, immagini, ConfigMap, parametri di
pipeline in chiaro o file `.env` versionati. Secret scanning con push protection sul repository, in pre-commit
e in CI.

**SBD-INFRA-16 — Host e VM hardened.** Immagini da baseline hardened (CIS), patching automatico, agent di
sicurezza e logging aziendali, nessun IP pubblico salvo edge, metadata service protetto (IMDSv2 obbligatorio
su AWS con `http_tokens = "required"` e hop limit 1-2; endpoint metadata non raggiungibili dai pod).

**SBD-INFRA-17 — Storage cifrato, privato, accessibile per identità.** Bucket, blob container, dischi, snapshot,
database e backup cifrati con chiavi gestite (CMK per C2-C3, SBD-DATA-04); blocco dell'accesso pubblico a
livello di account; accesso tramite policy di identità o private endpoint, non tramite chiavi condivise o ACL
pubbliche; versioning e protezione dalla cancellazione per dati importanti; URL firmati a durata breve.

## Pipeline e deploy

**SBD-INFRA-18 — Pipeline CI/CD come sistema di produzione.** Branch principali protetti (review obbligatoria
da persona diversa dall'autore, status check obbligatori, niente force push, CODEOWNERS sulle parti critiche
come workflow, IaC e policy); permessi del token di pipeline minimi per job; action e immagini fissate per SHA
o digest (SBD-SC-07); nessuna interpolazione di input non fidati nei comandi shell; nessun workflow privilegiato
su codice di PR esterne; runner effimeri, self-hosted isolati e mai condivisi con repository pubblici; segreti
per ambiente con approvazione per la produzione; autenticazione al cloud via OIDC con vincoli su repository,
branch ed environment. Dettagli in `references/cicd-pipelines.md`.

**SBD-INFRA-19 — Deploy solo di artefatti firmati, tramite pipeline, con rollback.** In produzione si
distribuisce solo ciò che la pipeline ha costruito, testato, scansionato e firmato; la promozione tra ambienti
riusa lo stesso artefatto (stesso digest). Approvazione esplicita per la produzione per i servizi critici.
Strategie progressive (canary, blue/green) e rollback testato.

## Osservabilità e resilienza

**SBD-INFRA-20 — Log centralizzati, integri, conservati.** Log applicativi, di sistema, di rete, di audit del
control plane cloud (CloudTrail, Activity Log, Cloud Audit Logs) e di Kubernetes raccolti centralmente nel
SIEM; archiviazione immutabile o in account separato; retention e sincronizzazione oraria da policy; accesso
ai log limitato e tracciato. I log sono dati C2: niente segreti o dati C3 (SBD-DATA-12).

**SBD-INFRA-21 — Rilevamento e alert.** Alert su eventi di sicurezza: uso di account break-glass, modifiche a
IAM e guardrail, disattivazione di log, risorse rese pubbliche, accessi anomali ai dati, picchi di dinieghi,
esecuzioni anomale nei container (Falco o equivalente per C3). Ogni alert ha un owner e un runbook.

**SBD-INFRA-22 — Backup immutabili, restore testato, resilienza.** Backup automatici cifrati, con almeno una
copia immutabile e isolata dall'account di produzione (protezione da ransomware e da credenziali compromesse);
RPO, RTO e frequenza dei test di restore per tier in `sbd-core/references/policy-parameters.md`.
Distribuzione su più zone per i servizi critici; piani di disaster recovery provati (DORA art. 11-12).

**SBD-INFRA-23 — Protezione da abuso e consumo.** Rate limiting e quote all'edge e nel gateway, protezione
DDoS, autoscaling con limiti massimi, budget e alert di costo: un attacco non deve poter esaurire risorse o
generare costi illimitati.

**SBD-INFRA-24 — Inventario e tagging.** Ogni risorsa ha tag obbligatori: `owner`, `service`, `environment`,
`data-classification`, `criticality`. L'inventario di asset e dipendenze ICT alimenta il registro richiesto da
DORA art. 8 e lo scope PCI.

## Riferimenti

- `references/cloud-iac.md` — pattern Terraform sicuri (storage, KMS, IAM, rete, database, state backend) con
  equivalenti Azure e GCP. Leggilo quando scrivi o revisioni IaC.
- `references/containers-kubernetes.md` — Dockerfile hardened, securityContext, NetworkPolicy, Pod Security
  Admission, RBAC. Leggilo quando scrivi Dockerfile o manifest.
- `references/cicd-pipelines.md` — workflow GitHub Actions hardened, OIDC verso cloud, rischi di injection,
  note per GitLab CI e altri sistemi. Leggilo quando scrivi o modifichi una pipeline.
