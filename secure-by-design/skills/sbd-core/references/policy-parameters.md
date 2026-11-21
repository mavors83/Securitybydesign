# Parametri di policy SBD

Questo file raccoglie in un solo punto i valori che il CISO può tarare. Le skill `sbd-*` rimandano qui invece
di ripetere numeri. I valori indicati sono i **default proposti dal team Security Engineering**: prima del
rollout vanno allineati alla policy aziendale vigente. Dove un valore deriva da un requisito normativo
il riferimento è indicato tra parentesi: in quel caso il valore è un minimo e non va ridotto.

## Indice

1. Classificazione delle informazioni
2. Severità dei finding e SLA di remediation
3. Soglie del security gate
4. Autenticazione, sessioni e token
5. Crittografia (rimando)
6. Logging e retention
7. Backup e continuità
8. Dipendenze e supply chain
9. Processo di eccezione
10. Contatti ed escalation

## 1. Classificazione delle informazioni

| Livello | Nome | Esempi |
|---|---|---|
| C0 | Pubblico | Documentazione pubblicata, pagine marketing, API pubbliche documentate |
| C1 | Interno | Documentazione interna, codice sorgente non critico, metriche aggregate |
| C2 | Riservato | Dati personali comuni di clienti e dipendenti, dati contrattuali, configurazioni, log applicativi, codice di sistemi critici |
| C3 | Strettamente Riservato | Dati di pagamento (PAN), credenziali e chiavi, dati personali particolari (art. 9-10 GDPR), dati di autenticazione, dati di frode, informazioni privilegiate |

Etichette aggiuntive (si combinano con il livello e attivano controlli specifici):

| Etichetta | Significato | Livello minimo |
|---|---|---|
| `PII` | Dato personale (GDPR art. 4) | C2 |
| `PII-SPECIAL` | Categorie particolari o dati giudiziari (art. 9-10) | C3 |
| `PCI-PAN` | Primary Account Number | C3 |
| `PCI-SAD` | Sensitive Authentication Data: CVV2/CVC2, traccia completa, PIN/PIN block. Vietata la conservazione dopo l'autorizzazione | C3 |
| `CREDENTIAL` | Password, token, chiavi, segreti, seed OTP | C3 |
| `FIN` | Dati di transazione, saldi, movimenti | C2 |

Un dato non classificato si tratta come **C3** finché il data owner non lo classifica.

## 2. Severità dei finding e SLA di remediation

La severità parte dal CVSS (v4.0 o v3.1) e si corregge con il contesto: esposizione, sfruttabilità, dati
coinvolti. Una vulnerabilità presente nel catalogo CISA KEV o con exploit pubblico raggiungibile si tratta
come **Critical** indipendentemente dal punteggio.

| Severità | Codice nuovo (PR) | Codice/asset già in produzione |
|---|---|---|
| Critical | Blocca il merge | Remediation o mitigazione entro 7 giorni (PCI DSS 6.3.3: patch critiche entro 1 mese, valore massimo) |
| High | Blocca il merge | Entro 30 giorni |
| Medium | Va risolto o accettato formalmente prima del merge | Entro 90 giorni |
| Low | Ticket in backlog | Entro 180 giorni |

Un segreto esposto è sempre **Critical**: va revocato e ruotato subito. Rimuoverlo dal codice non basta.

## 3. Soglie del security gate

- Esito **PASS** solo se nessuna categoria obbligatoria ha finding di severità ≥ High e tutte le categorie
  obbligatorie sono state eseguite.
- Categoria obbligatoria non eseguita (strumento assente o in errore): esito **INCOMPLETE**, mai PASS.
- Finding Medium: ammessi solo se risolti o accettati con eccezione registrata.
- Ogni soppressione inline richiede ID della regola e motivazione; le soppressioni sono elencate nel report.
- Vulnerabilità di dipendenze senza fix disponibile: non bloccano il merge, ma richiedono valutazione
  di raggiungibilità (VEX o nota nel PR) e un ticket di monitoraggio.

## 4. Autenticazione, sessioni e token

| Parametro | Default | Riferimento |
|---|---|---|
| Lunghezza minima password, se unico fattore | 15 caratteri | NIST SP 800-63B-4 |
| Lunghezza minima password con MFA | 12 caratteri | PCI DSS 8.3.6 richiede almeno 12 |
| Lunghezza massima accettata | almeno 64 caratteri | NIST SP 800-63B-4 |
| Regole di composizione, scadenza periodica | Nessuna; rotazione solo su sospetta compromissione | NIST SP 800-63B-4 |
| Verifica contro password compromesse | Obbligatoria | NIST SP 800-63B-4 |
| MFA | Obbligatoria per accessi amministrativi, remoti, all'ambiente dei dati di carta e alle operazioni dispositive dei clienti | PCI DSS 8.4; PSD2 RTS SCA |
| Blocco o rallentamento dopo tentativi falliti | Al massimo 10 tentativi, poi blocco ≥ 30 minuti o verifica dell'identità | PCI DSS 8.3.4 |
| Timeout di inattività della sessione | 15 minuti per console amministrative e utenti con accesso al CDE; 30 minuti per gli altri utenti | PCI DSS 8.2.8 |
| Durata massima assoluta della sessione | 12 ore | |
| Access token (JWT/opaque) | Durata ≤ 15 minuti | |
| Refresh token | Rotazione a ogni uso con rilevamento del riuso; durata ≤ 24 ore per client pubblici | RFC 9700 |
| Token di reset password / link magici | Monouso, ≤ 15 minuti, conservati come hash | |
| Chiavi API per integrazioni machine-to-machine | Preferire credenziali federate a vita breve; se statiche, rotazione ≤ 90 giorni | |

## 5. Crittografia

Algoritmi, lunghezze di chiave, protocolli e rotazione delle chiavi sono in
`sbd-data-protection/references/crypto-and-keys.md`.

## 6. Logging e retention

| Parametro | Default | Riferimento |
|---|---|---|
| Retention log di sicurezza e audit | ≥ 12 mesi, di cui ultimi 3 mesi immediatamente consultabili | PCI DSS 10.5.1 |
| Sincronizzazione oraria | NTP da fonti autorizzate, timestamp UTC ISO-8601 | PCI DSS 10.6 |
| Integrità dei log | Archiviazione immutabile (WORM) o append-only con accesso separato | PCI DSS 10.3 |
| Revisione | Automatica tramite SIEM con alert | PCI DSS 10.4.1.1 |

## 7. Backup e continuità

| Tier del servizio | RPO | RTO | Restore test |
|---|---|---|---|
| Critico (funzioni critiche o importanti DORA) | ≤ 15 minuti | ≤ 2 ore | Trimestrale |
| Alto | ≤ 1 ora | ≤ 8 ore | Semestrale |
| Standard | ≤ 24 ore | ≤ 72 ore | Annuale |

Almeno una copia dei backup è immutabile e logicamente isolata dall'account di produzione.

## 8. Dipendenze e supply chain

| Parametro | Default |
|---|---|
| Età minima di una nuova release prima dell'adozione (cooldown) | 7 giorni, salvo fix di sicurezza valutati |
| Età minima di un pacchetto mai usato prima | 90 giorni dalla prima pubblicazione, salvo approvazione |
| Licenze ammesse senza review | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, MPL-2.0 (solo uso non modificato), PostgreSQL, Zlib |
| Licenze che richiedono review legale | GPL, LGPL, AGPL, SSPL, BUSL, Commons Clause, licenze assenti o custom |
| Formato SBOM | CycloneDX 1.6 (accettato SPDX 2.3+) |
| Livello SLSA minimo per artefatti di produzione | Build L2, obiettivo L3 |

## 9. Processo di eccezione

Un'eccezione è l'accettazione formale e temporanea di un rischio. Senza eccezione approvata una regola SBD
non si deroga.

Campi obbligatori del registro eccezioni:

- **ID** (es. `SBD-EXC-2026-042`) e regola o regole derogate;
- **motivazione** di business e perché il controllo non è applicabile ora;
- **rischio**: scenario di attacco, impatto, probabilità;
- **controlli compensativi** in essere;
- **owner** del rischio (responsabile di business, non lo sviluppatore);
- **approvatore**: Security Engineering per rischi Medium e Low, CISO o suo delegato per High e Critical;
- **scadenza**: massimo 90 giorni, rinnovabile una volta con nuova valutazione;
- **piano di rientro** con ticket collegato.

Nel codice la deviazione è marcata con un commento `SBD-EXCEPTION: <ID> scade <AAAA-MM-GG>` sulla riga o
sul blocco interessato.

## 10. Contatti ed escalation

Da compilare con i riferimenti aziendali prima del rollout:

| Ruolo | Quando | Contatto |
|---|---|---|
| Security Champion del team | Primo riferimento per dubbi e review | `<security-champion>` |
| Security Engineering (CISO) | Escalation, threat model full, eccezioni Medium/Low | `<security-engineering-contact>` |
| CISO o delegato | Eccezioni High/Critical, rischi sistemici | `<ciso-office-contact>` |
| DPO | DPIA, nuove finalità di trattamento, dati art. 9-10, trasferimenti extra-SEE | `<dpo-contact>` |
| SOC / CSIRT | Sospetto incidente, segreto esposto, dipendenza compromessa | `<soc-contact>` |
