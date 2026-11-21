# Dati di carta — regole PCI DSS v4.0.1 per lo sviluppo

Ogni cambiamento che tocca dati di carta richiede escalation a Security Engineering (`sbd-core`). Queste
regole non sostituiscono la valutazione di scope PCI: servono a non introdurre errori nel codice.

## Definizioni

- **CHD (Cardholder Data)**: PAN, nome del titolare, data di scadenza, service code. Il PAN è l'elemento che
  determina lo scope.
- **SAD (Sensitive Authentication Data)**: dati della traccia o del chip completi, CVV2/CVC2/CID, PIN e PIN
  block.
- **CDE (Cardholder Data Environment)**: persone, processi e sistemi che memorizzano, elaborano o trasmettono
  CHD o SAD, più i sistemi connessi senza segmentazione.

## Regole

1. **Riduci lo scope prima di tutto.** Preferisci campi di inserimento ospitati dal PSP (iframe, hosted fields,
   pagina di pagamento ospitata) o SDK che tokenizzano sul dispositivo: il PAN non transita né si ferma nei tuoi
   sistemi. Ogni sistema che vede il PAN entra nel CDE.
2. **Mai conservare SAD dopo l'autorizzazione** (PCI DSS 3.3.1), in nessuna forma: database, file, log, code,
   cache, analytics, dump di memoria, ticket, email. Nemmeno cifrati. Il CVV si trasmette al processore e si
   scarta.
3. **Se devi conservare il PAN, rendilo illeggibile** (3.5.1) con uno di: tokenizzazione (preferita), cifratura
   forte di campo con chiavi gestite (3.6-3.7), troncamento, hash crittografico **con chiave** dell'intero PAN
   (3.5.1.1: hash semplici non sono ammessi). La cifratura del disco o del database da sola non basta per
   storage non rimovibile (3.5.1.2).
4. **Maschera in visualizzazione** (3.4.1): al massimo BIN (prime 6 o 8 cifre) e ultime 4, solo per i ruoli con
   necessità documentata; per tutti gli altri ultime 4 cifre. La copia o lo spostamento del PAN completo tramite
   tecnologie di accesso remoto è impedito salvo necessità autorizzata (3.4.2).
5. **Il PAN non compare mai** in URL, query string, header non necessari, log applicativi, messaggi di errore,
   eventi di analytics, nomi di file, chiavi di cache, metriche e tracce. Aggiungi test che lo verificano.
6. **Trasmissione cifrata** (4.2.1): TLS 1.2+ con certificati validi e verificati su ogni rete; mTLS verso i
   processori dove supportato; mai PAN via email o chat non cifrate (4.2.2).
7. **Niente PAN reali fuori dalla produzione** (6.5.5): usa i numeri di test dei circuiti o del PSP.
8. **Retention minima** (3.2.1): conserva i dati di carta solo per il tempo giustificato dalla finalità, con
   cancellazione automatica e verificata almeno trimestralmente.
9. **Pagine di pagamento** (6.4.3, 11.6.1): inventario degli script caricati con giustificazione, autorizzazione
   e verifica di integrità di ciascuno; rilevamento delle modifiche non autorizzate di script e header HTTP
   della pagina di pagamento; CSP restrittiva.
10. **Accesso** (7, 8): need-to-know per ruolo; MFA per ogni accesso al CDE (8.4.2); account di sistema e
    applicativi senza password hardcoded (8.6.2) e con privilegi minimi.
11. **Log** (10): ogni accesso ai dati di carta e ogni azione amministrativa nel CDE è registrato, i log sono
    protetti e conservati secondo `sbd-core/references/policy-parameters.md`.

## Pattern di codice

```text
Insicuro                                          Sicuro
-----------------------------------------------   ------------------------------------------------------
log.info("payment card=" + pan)                    log.info("payment token={} last4={}", token, last4)
db.save(cvv)                                       // CVV inoltrato al PSP e mai persistito
sha256(pan) come chiave di deduplicazione          HMAC-SHA-256(chiave dal KMS, pan) o token del PSP
GET /cards?pan=4111...                             POST /cards/lookup con body; meglio: lookup per token
"****" + pan.substring(12) calcolato nel client    mascheramento calcolato server-side, il client non riceve il PAN
```

## Rilevare PAN nel codice e nei dati

- Lo script `sbd-security-gate/scripts/sbd_patterns.py` segnala sequenze di 13-19 cifre che superano il
  controllo di Luhn (esclusi i numeri di test pubblici più comuni).
- Nei dati (log, export, bucket) usa strumenti DLP aziendali con lo stesso criterio.
