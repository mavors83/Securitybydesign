# Template — Threat model full

Copia questo template in `docs/security/threat-models/<componente>.md`. Compila tutte le sezioni: se una non
si applica scrivi perché, non lasciarla vuota.

```markdown
# Threat model — <nome componente>

| Campo | Valore |
|---|---|
| Versione | 1.0 |
| Data | AAAA-MM-GG |
| Autori | <team> |
| Revisori | <Security Champion>, <Security Engineering se richiesto> |
| Stato | Bozza / In revisione / Approvato |
| Trigger SBD-TM-02 | <quali> |
| PR / ticket collegati | <link> |

## 1. Contesto

- Scopo del componente e funzionalità coinvolte:
- Utenti e attori (umani e sistemi), con ruoli:
- Ambienti e deployment (cloud, regione, cluster, account):
- Dipendenze esterne (fornitori, SaaS, API, modelli):
- Requisiti normativi applicabili (PCI DSS, DORA, NIS2, GDPR, CRA):
- Criticità per il business (funzione critica o importante DORA? tier di continuità):

## 2. Dati

| Entità dati | Classificazione | Etichette | Dove risiede | Retention | Owner |
|---|---|---|---|---|---|
| es. Transazione | C2 | FIN | DB transazioni (EU) | 10 anni | Payments |
| es. PAN | C3 | PCI-PAN | Mai: tokenizzato dal PSP | — | — |

## 3. Architettura e flussi

Diagramma DFD in Mermaid con trust boundary. Per ogni flusso:

| # | Da | A | Protocollo | Autenticazione | Dati (classificazione) | Attraversa boundary |
|---|---|---|---|---|---|---|
| F1 | Cliente | API Gateway | HTTPS TLS 1.3 | OIDC + MFA | C2 | Internet → Edge |

## 4. Assunzioni e fuori ambito

- Assunzioni di sicurezza su cui il design si basa (es. "il gateway termina TLS e valida il JWT"):
  ognuna è un punto da verificare.
- Cosa è esplicitamente fuori ambito e chi lo copre.

## 5. Minacce

| ID | Elemento/flusso | Categoria (STRIDE/LINDDUN/Abuse) | Scenario | Probabilità | Impatto | Rischio | Decisione | Contromisure (ID regola SBD) | Verifica | Stato |
|---|---|---|---|---|---|---|---|---|---|---|
| T1 | F1 | Spoofing | Furto di token di sessione da XSS | Media | Alto | Alto | Mitigare | Cookie HttpOnly+SameSite, CSP nonce (SBD-CODE-08, -10) | Test e2e header, scansione DAST | Aperta |

## 6. Rischi residui

| ID | Descrizione | Rischio | Owner | Eccezione | Scadenza |
|---|---|---|---|---|---|

## 7. Requisiti di verifica

Elenco di test, policy e scansioni che dimostrano le contromisure, con il punto della pipeline in cui girano.

## 8. Storico revisioni

| Versione | Data | Modifica | Autore |
|---|---|---|---|
```

## Matrice di rischio

| Probabilità \ Impatto | Basso | Medio | Alto | Critico |
|---|---|---|---|---|
| **Alta** | Medium | High | Critical | Critical |
| **Media** | Low | Medium | High | Critical |
| **Bassa** | Low | Low | Medium | High |

Criteri di impatto:

- **Critico**: compromissione di dati C3 o di dati di molti clienti, frode economica, interruzione di una
  funzione critica, violazione notificabile alle autorità.
- **Alto**: compromissione di dati C2 di un insieme di clienti, escalation di privilegi, interruzione
  prolungata di un servizio.
- **Medio**: esposizione limitata di dati C1-C2, degrado del servizio, abuso limitato a un singolo account.
- **Basso**: impatto trascurabile o solo informativo.

Criteri di probabilità:

- **Alta**: sfruttabile da remoto senza autenticazione o con un account ordinario, tecnica nota, nessun
  controllo che la ostacoli.
- **Media**: richiede condizioni specifiche, accesso interno o competenze significative.
- **Bassa**: richiede accesso privilegiato, combinazione di più falle o condizioni improbabili.

Il rischio residuo Critical o High richiede l'approvazione del CISO o di un suo delegato; Medium e Low di
Security Engineering (`sbd-core/references/policy-parameters.md`, sezione 9).
