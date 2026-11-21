# Mappa di conformità SBD

Usa questa mappa per motivare un controllo con il requisito che lo rende obbligatorio, o per raccogliere
evidenze in vista di un audit. La mappa indica i riferimenti principali: non sostituisce la valutazione di
applicabilità fatta da Compliance, che stabilisce quali normative si applicano a ciascun sistema.

## Standard tecnici di riferimento

| Standard | Uso nel framework |
|---|---|
| OWASP ASVS 5.0 | Requisiti di verifica per applicazioni e API. Livello 2 come minimo per ogni applicazione, livello 3 per sistemi che trattano dati C3 o funzioni critiche |
| OWASP Top 10:2025 | Classi di rischio applicativo che il threat model light deve sempre considerare |
| OWASP API Security Top 10:2023 | Rischi specifici delle API (BOLA, BOPLA, BFLA, consumo di risorse, inventario) |
| OWASP Top 10 for LLM Applications 2025 | Rischi delle funzionalità basate su LLM |
| OWASP MASVS 2.x | Applicazioni mobile |
| NIST SP 800-218 (SSDF) | Ciclo di sviluppo sicuro: PO (prepare), PS (protect software), PW (produce well-secured software), RV (respond to vulnerabilities) |
| NIST SP 800-63B-4 | Autenticazione e gestione delle credenziali |
| SLSA 1.x | Integrità della build e provenance |
| CIS Benchmarks | Hardening di sistemi operativi, container, Kubernetes, servizi cloud |
| Kubernetes Pod Security Standards | Profilo `restricted` per i workload |

## Mappa per dominio

| Dominio SBD | OWASP Top 10:2025 | NIST SSDF | ISO/IEC 27001:2022 Annex A |
|---|---|---|---|
| `sbd-core` | tutte | PO.1, PO.2, PO.5 | 5.8, 8.25, 8.27 |
| `sbd-threat-modeling` | A06 Insecure Design | PW.1 | 5.8, 8.26, 8.27 |
| `sbd-secure-coding` | A01, A04, A05, A06, A07, A10 | PW.5, PW.6, PW.7, PW.8 | 8.26, 8.28, 8.29 |
| `sbd-supply-chain` | A03 Software Supply Chain Failures, A08 | PO.3, PS.1, PS.2, PS.3, PW.4 | 5.19-5.22, 8.30 |
| `sbd-infrastructure` | A02 Security Misconfiguration, A09 | PO.3, PO.5, PS.1 | 8.9, 8.15, 8.16, 8.20-8.22, 8.31, 8.32 |
| `sbd-data-protection` | A04 Cryptographic Failures | PW.1, PS.1 | 5.12, 5.33, 5.34, 8.10, 8.11, 8.12, 8.24 |
| `sbd-ai-security` | A01, A05, A06 | PW.1, PW.4 | 8.26, 8.28 |
| `sbd-security-gate` | tutte | PW.7, PW.8, RV.1, RV.2 | 8.8, 8.29 |

## PCI DSS v4.0.1 (sistemi nell'ambito del Cardholder Data Environment)

| Requisito | Tema | Regole SBD |
|---|---|---|
| 1.2-1.4 | Controlli di sicurezza di rete, segmentazione del CDE | SBD-INFRA-07, -08 |
| 2.2 | Configurazioni sicure e hardening | SBD-INFRA-11, -12, -16 |
| 3.2.1 | Conservazione minima dei dati di carta | SBD-DATA-02, -08 |
| 3.3.1 | Nessuna conservazione di SAD dopo l'autorizzazione | SBD-DATA-06 |
| 3.4.1 | Mascheramento del PAN in visualizzazione | SBD-DATA-06 |
| 3.5.1, 3.5.1.1, 3.5.1.2 | PAN illeggibile ovunque sia memorizzato; hash solo con chiave; cifratura disco non sufficiente da sola | SBD-DATA-04, -06 |
| 3.6, 3.7 | Gestione delle chiavi crittografiche | SBD-DATA-05 |
| 4.2.1 | Crittografia forte per il PAN in transito | SBD-DATA-03, SBD-INFRA-10 |
| 6.2.1-6.2.4 | Sviluppo sicuro, formazione, code review, tecniche contro gli attacchi comuni | `sbd-secure-coding`, `sbd-security-gate` |
| 6.3.1-6.3.3 | Gestione vulnerabilità, inventario dei componenti software, patch | SBD-SC-08, -09 |
| 6.4.1-6.4.3 | Protezione delle applicazioni web pubbliche; script nelle pagine di pagamento | SBD-INFRA-08, SBD-CODE-19 |
| 6.5.1-6.5.6 | Change management, separazione degli ambienti, nessun PAN reale in pre-produzione | SBD-CORE-13, SBD-INFRA-06, SBD-DATA-11 |
| 7.2 | Least privilege | SBD-INFRA-04, SBD-DATA-09 |
| 8.2-8.6 | Identificazione, autenticazione, MFA, account di sistema, nessuna password hardcoded (8.6.2) | SBD-CODE-07, SBD-INFRA-03, -05, SBD-CORE-01 |
| 10.2-10.7 | Log di audit, protezione, revisione, retention, sincronizzazione oraria | SBD-CODE-15, SBD-INFRA-20, -21 |
| 11.3-11.4 | Scansioni di vulnerabilità e penetration test | `sbd-security-gate` |
| 11.6.1 | Rilevamento di modifiche e manomissioni nelle pagine di pagamento | SBD-CODE-19 |
| 12.3.3 | Inventario e revisione di cipher suite e protocolli | SBD-DATA-05 |

## DORA — Regolamento (UE) 2022/2554 (entità finanziarie)

| Riferimento | Tema | Regole SBD |
|---|---|---|
| Art. 8 | Identificazione: inventario di asset e dipendenze ICT | SBD-INFRA-24, SBD-SC-09 |
| Art. 9 | Protezione e prevenzione: sicurezza di reti, dati, accessi, crittografia, change management | `sbd-infrastructure`, `sbd-data-protection` |
| Art. 10 | Rilevamento di attività anomale | SBD-INFRA-21 |
| Art. 11-12 | Risposta, ripristino, politiche di backup e restore | SBD-INFRA-22 |
| Art. 17-19 | Gestione e segnalazione degli incidenti ICT | SBD-DATA-16 |
| Art. 24-27 | Test di resilienza operativa digitale | `sbd-security-gate` |
| Art. 28-30 | Rischio ICT da terze parti | SBD-SC-13 |
| Reg. Delegato (UE) 2024/1774 | RTS sul quadro di gestione del rischio ICT: crittografia e chiavi, sviluppo e manutenzione sicuri, change management, logging, sicurezza di rete | trasversale |

## NIS2 — Direttiva (UE) 2022/2555, recepita in Italia con D.Lgs. 138/2024

| Art. 21(2) | Misura | Regole SBD |
|---|---|---|
| a | Analisi dei rischi e politiche di sicurezza | `sbd-core`, `sbd-threat-modeling` |
| b | Gestione degli incidenti | SBD-INFRA-21, SBD-DATA-16 |
| c | Continuità operativa e backup | SBD-INFRA-22 |
| d | Sicurezza della catena di approvvigionamento | `sbd-supply-chain` |
| e | Sicurezza nell'acquisizione, sviluppo e manutenzione, inclusa gestione e divulgazione delle vulnerabilità | `sbd-secure-coding`, `sbd-security-gate` |
| h | Crittografia e cifratura | SBD-DATA-03, -04, -05 |
| i | Controllo degli accessi e gestione degli asset | SBD-INFRA-04, -05, -24 |
| j | Autenticazione a più fattori e comunicazioni protette | SBD-CODE-07, SBD-INFRA-05, -10 |

## GDPR — Regolamento (UE) 2016/679

| Articolo | Tema | Regole SBD |
|---|---|---|
| 5 | Minimizzazione, limitazione della finalità e della conservazione, integrità e riservatezza | SBD-DATA-02, -08 |
| 25 | Protezione dei dati fin dalla progettazione e per impostazione predefinita | SBD-DATA-07, `sbd-threat-modeling` (LINDDUN) |
| 32 | Sicurezza del trattamento: pseudonimizzazione, cifratura, resilienza, test periodici | `sbd-data-protection`, SBD-INFRA-22 |
| 33-34 | Notifica di violazione entro 72 ore | SBD-DATA-16 |
| 35 | Valutazione d'impatto (DPIA) | SBD-DATA-17 |
| 44-49 | Trasferimenti verso paesi terzi | SBD-DATA-13 |
| 22 | Decisioni automatizzate | SBD-AI-10 |

## Cyber Resilience Act — Regolamento (UE) 2024/2847 (prodotti con elementi digitali immessi sul mercato UE)

Se il sistema è un prodotto distribuito a clienti (app, SDK, firmware, software installabile), si applicano i
requisiti essenziali dell'Allegato I: sicurezza by default, nessuna vulnerabilità sfruttabile nota al
rilascio, protezione di riservatezza e integrità, minimizzazione dei dati e della superficie d'attacco,
logging, aggiornamenti di sicurezza, SBOM e gestione coordinata delle vulnerabilità. Gli obblighi di
segnalazione delle vulnerabilità attivamente sfruttate si applicano dall'11 settembre 2026, gli altri
dall'11 dicembre 2027. Coinvolgi Compliance per la valutazione di applicabilità.
