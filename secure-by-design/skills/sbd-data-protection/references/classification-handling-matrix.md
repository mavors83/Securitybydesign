# Matrice di trattamento per classificazione

Ogni colonna indica il **minimo** richiesto. Un livello superiore eredita tutti i controlli dei livelli
inferiori. Le etichette (sezione 2) aggiungono controlli al livello.

## 1. Controlli per livello

| Controllo | C0 Pubblico | C1 Interno | C2 Riservato | C3 Strettamente Riservato |
|---|---|---|---|---|
| Cifratura in transito | TLS verso l'esterno | TLS ovunque | TLS ovunque, mTLS tra servizi | TLS 1.2+ (1.3 preferito) e mTLS su tutti i flussi |
| Cifratura a riposo | Facoltativa | Chiave gestita dal provider | CMK in KMS | CMK in KMS/HSM + cifratura di campo o tokenizzazione |
| Autenticazione per l'accesso | — | SSO | SSO + MFA per accessi umani | SSO + MFA resistente al phishing, accesso just-in-time |
| Autorizzazione | — | Per ruolo | Per ruolo e per oggetto, need-to-know | Need-to-know per record o campo, approvazione per accessi umani |
| Accesso umano in produzione | — | Su richiesta | JIT approvato e tracciato | JIT approvato, a tempo, tracciato a livello di query, dati mascherati di default |
| Log di accesso ai dati | — | Accessi amministrativi | Accessi amministrativi e operazioni di scrittura | Ogni accesso in lettura e scrittura, con alert su anomalie |
| Presenza nei log applicativi | Ammessa | Ammessa | Solo identificativi o pseudonimi | Mai (solo token o riferimenti) |
| Ambienti non di produzione | Ammesso | Ammesso | Solo sintetici o mascherati irreversibilmente | Solo sintetici |
| Export e condivisione | Libera | Interna | Funzione autorizzata, cifrato, tracciato | Solo con approvazione del data owner, cifrato, link ≤ 24 h, tracciato |
| Email e chat | Ammesso | Interne | Solo interne, minimizzate | Vietato |
| Trasferimento a terze parti | Libero | Con accordo | Con contratto, valutazione fornitore, DPA se personali | Con contratto, valutazione fornitore approvata dal CISO, cifratura end-to-end |
| Residenza | — | — | Regioni UE approvate | Regioni UE approvate, nessuna replica extra-SEE |
| Retention | Libera | Definita | Definita e cancellazione automatica | Minima possibile, cancellazione automatica verificata |
| Backup | Facoltativo | Cifrato | Cifrato con CMK, accesso separato | Cifrato con CMK dedicata, copia immutabile, restore testato |
| Cancellazione sicura | — | Standard | Cancellazione logica e fisica entro la retention | Crypto-shredding o cancellazione verificata, incluse le copie |
| Stampa e screenshot (client) | — | — | Sconsigliati | Bloccati dove tecnicamente possibile (mobile `FLAG_SECURE`, campi mascherati) |
| Revisione di sicurezza | — | — | Security Champion | Security Champion + Security Engineering |

## 2. Controlli aggiuntivi per etichetta

| Etichetta | Controlli aggiuntivi |
|---|---|
| `PII` | Finalità e base giuridica documentate; registro dei trattamenti aggiornato; supporto ai diritti degli interessati; pseudonimizzazione negli usi secondari (analytics, test); informativa coerente con il trattamento |
| `PII-SPECIAL` | Livello C3; DPIA valutata con il DPO; accesso ristretto a ruoli nominati; cifratura di campo; nessun uso per analytics senza approvazione |
| `PCI-PAN` | Livello C3; preferire la tokenizzazione; se conservato, illeggibile (PCI DSS 3.5.1); mascheramento in visualizzazione; sistemi nel CDE segmentato; chiavi gestite secondo PCI DSS 3.6-3.7; vedi `payment-card-data.md` |
| `PCI-SAD` | Conservazione vietata dopo l'autorizzazione, in qualsiasi forma e luogo (DB, log, code, file, cache, dump di memoria persistiti); in transito solo verso il processore, cifrato |
| `CREDENTIAL` | Livello C3; solo nel secret manager o come hash (password); mai in log, codice, ticket, chat; rotazione e revoca immediata in caso di esposizione |
| `FIN` | Integrità rafforzata: audit trail append-only, riconciliazioni, vincoli di database; retention secondo gli obblighi contabili e antiriciclaggio |

## 3. Come applicarla nel codice

1. Annota la classificazione nello schema: commento SQL sulla colonna, annotazione sull'entità
   (`@Classification("C3", tags = {"PII"})` o equivalente del progetto), metadati nello schema Avro/Protobuf
   dell'evento.
2. Fai derivare i controlli dalla classificazione dove possibile: filtri di redazione dei log basati
   sull'annotazione, serializzatori che mascherano i campi C3, policy IaC che richiedono CMK per risorse con tag
   `data-classification` = C2 o C3.
3. Aggiungi test che verificano che i campi C3 non compaiano nei log e nelle risposte delle API non autorizzate.
