---
name: sbd-data-protection
description: >
  Protezione dei dati Security by Design: classificazione, minimizzazione, cifratura in transito e a riposo,
  gestione delle chiavi, dati di pagamento PCI DSS (PAN, CVV, tokenizzazione, mascheramento), dati personali
  GDPR (privacy by design, pseudonimizzazione, diritti degli interessati, DPIA), retention e cancellazione,
  accesso ai dati di produzione, dati di test, log e telemetria, export e trasferimenti, backup, data lake e
  vector DB. Usare ogni volta che si progetta o modifica uno schema, una tabella, una migrazione, un modello
  dati, una query su dati di clienti, un evento o messaggio con dati, un log, un export, un report, un job di
  ETL, una cache, oppure si sceglie un algoritmo crittografico o si gestiscono chiavi. Trigger: "schema",
  "migrazione", "tabella", "dati personali", "PII", "GDPR", "PAN", "carta", "cifratura", "encryption",
  "KMS", "hash", "retention", "anonimizzare", "dati di test", "export CSV", "data lake".
---

# Protezione dei dati

I controlli sui dati discendono dalla loro **classificazione**: prima si stabilisce che cosa si tratta, poi si
applicano i controlli corrispondenti nella matrice in `references/classification-handling-matrix.md`.
Il miglior controllo resta non avere il dato: un dato che non si raccoglie, che si tokenizza o che si
cancella appena non serve non può essere violato.

## Regole

**SBD-DATA-01 — Classifica ogni dato prima di trattarlo.** Per ogni entità, campo, file, evento o store
nuovo o modificato indica livello (C0-C3) ed etichette (`PII`, `PII-SPECIAL`, `PCI-PAN`, `PCI-SAD`,
`CREDENTIAL`, `FIN`) secondo `sbd-core/references/policy-parameters.md`. Registra la classificazione dove
vive il dato: commenti o annotazioni dello schema, tag delle risorse cloud (`data-classification`), catalogo
dati. Un dato non classificato si tratta come C3.

**SBD-DATA-02 — Minimizza raccolta, copie e durata.** Raccogli solo i campi necessari alla finalità dichiarata;
evita campi di testo libero dove possono finire dati sensibili non previsti; non duplicare dati in cache,
analytics, log, ticket o ambienti di test senza necessità e senza la stessa protezione. Per i dati personali la
finalità e la base giuridica sono definite con il DPO prima dello sviluppo.

**SBD-DATA-03 — Cifra tutti i dati in transito.** TLS per ogni connessione che trasporta dati C1 e superiori,
anche interna; mTLS per i flussi C2-C3 tra servizi; verifica del certificato e del nome host sempre attiva
(per PostgreSQL `sslmode=verify-full`, per MySQL `ssl-mode=VERIFY_IDENTITY`, per MongoDB `tls=true` con
verifica, per Redis TLS con verifica). Parametri TLS in `references/crypto-and-keys.md`.

**SBD-DATA-04 — Cifra tutti i dati a riposo; per C3 aggiungi cifratura applicativa.** Ogni storage (database,
dischi, bucket, code, cache, backup, snapshot, log) è cifrato con chiavi gestite in KMS; per C2-C3 con chiavi
gestite dal cliente (CMK). Per i campi C3 (PAN se conservato, segreti, dati `PII-SPECIAL`, documenti
d'identità) usa in aggiunta cifratura a livello di campo o applicativa con envelope encryption, oppure
tokenizzazione: la cifratura del disco protegge dal furto del supporto, non da chi accede al database con
credenziali valide.

**SBD-DATA-05 — Gestisci le chiavi con un KMS o HSM.** Chiavi generate e custodite in KMS o HSM (HSM FIPS 140-3
livello 3 o equivalente per le chiavi che proteggono dati di pagamento); envelope encryption con data key
per oggetto o per record; chiavi separate per finalità, ambiente e tenant; rotazione e versioning (la versione
della chiave è salvata con il ciphertext); separazione dei compiti tra chi amministra e chi usa le chiavi;
nessuna esportazione di chiavi in chiaro; inventario di chiavi, algoritmi e certificati. Dettagli in
`references/crypto-and-keys.md`.

**SBD-DATA-06 — Dati di pagamento: tokenizza, non conservare SAD, maschera.** Non conservare il PAN se non è
indispensabile: usa i token del PSP o del vault di tokenizzazione aziendale. I dati sensibili di
autenticazione (CVV2/CVC2, traccia completa, PIN e PIN block) non si conservano mai dopo l'autorizzazione,
nemmeno cifrati, nemmeno in log o code. Il PAN visualizzato è mascherato (al massimo BIN, prime 6 o 8, e ultime 4
cifre, solo per chi ne ha necessità). Regole complete in `references/payment-card-data.md`; ogni cambiamento
che tocca dati di carta richiede escalation (`sbd-core`).

**SBD-DATA-07 — Dati personali: privacy by design e by default.** Impostazioni di default più protettive
(visibilità minima, consensi non preselezionati, condivisioni disattivate); pseudonimizzazione per analytics,
test e ricerca (token o hash con chiave segreta, non hash semplici di email o telefono, che si invertono per
forza bruta); progettazione che permetta di esercitare i diritti degli interessati (accesso, rettifica,
cancellazione, portabilità, opposizione) individuando tutte le copie di un dato personale, incluse quelle
derivate; registrazione del consenso quando è la base giuridica. L'anonimizzazione vera è difficile: un dataset
è anonimo solo se la reidentificazione non è ragionevolmente possibile, e la valutazione spetta al DPO.

**SBD-DATA-08 — Retention definita e cancellazione automatica.** Ogni store ha un periodo di conservazione
documentato per tipo di dato, allineato agli obblighi di legge e al registro dei trattamenti. La cancellazione
è automatica (TTL, lifecycle policy, job schedulati con log) e copre le copie derivate. Per i backup, dove la
cancellazione selettiva non è praticabile, usa scadenza dei backup coerente con la retention o crypto-shredding
(cancellazione della chiave). Supporta il legal hold quando richiesto.

**SBD-DATA-09 — Accesso applicativo ai dati a privilegio minimo.** Account di database distinti per runtime
(solo DML sulle tabelle necessarie), migrazioni (DDL, usato solo dalla pipeline) e reporting (sola lettura,
preferibilmente su repliche o viste con dati minimizzati); niente account condivisi tra servizi; credenziali
dinamiche o autenticazione IAM dove disponibile; row-level security o filtri obbligatori per tenant nei sistemi
multi-tenant; viste o colonne cifrate per limitare l'accesso ai campi C3.

**SBD-DATA-10 — Accesso umano ai dati di produzione: eccezionale, approvato, tracciato.** Nessun accesso
permanente di sviluppatori ai dati di produzione. L'accesso per supporto o incidenti è just-in-time, approvato,
limitato nel tempo e nell'ambito, registrato a livello di query per i dati C3. Gli strumenti di supporto
mostrano dati mascherati di default.

**SBD-DATA-11 — Nessun dato di produzione fuori dalla produzione.** Sviluppo e test usano dati sintetici. Se
serve realismo, dati derivati dalla produzione con mascheramento irreversibile eseguito dentro la produzione,
approvato dal data owner e dal DPO per dati personali. Mai dump di produzione su laptop, ambienti di test,
ticket o servizi esterni. Mai PAN reali in pre-produzione (PCI DSS 6.5.5): usa i numeri di test dei circuiti.

**SBD-DATA-12 — Log, metriche e tracce senza dati sensibili.** Non finiscono in log, tracce, metriche, eventi di
analytics, messaggi di errore o strumenti di error reporting: password, token, chiavi, cookie, header
`Authorization`, PAN, SAD, dati `PII-SPECIAL`, documenti d'identità, contenuti completi di richieste e
risposte con dati C2-C3. Usa identificativi tecnici o pseudonimi al posto dei dati personali. Applica filtri di
redazione centralizzati nel logger e negli SDK di telemetria (allowlist dei campi loggabili, non solo
blocklist) e configura lo scrubbing negli strumenti di error reporting. I log stessi sono dati C2.

**SBD-DATA-13 — Export, condivisione e trasferimenti controllati.** Export di dati C2-C3 solo tramite
funzionalità autorizzate, tracciate, con file cifrati e link a scadenza breve; niente invio di dati C3 via email
o chat. Ogni trasferimento di dati personali fuori dallo Spazio Economico Europeo, incluso l'uso di servizi
SaaS o API con elaborazione extra-SEE, richiede la valutazione del DPO (GDPR art. 44-49): fermati ed escala.
I dati restano nelle regioni UE approvate salvo decisione diversa.

**SBD-DATA-14 — Le copie derivate ereditano la classificazione.** Cache, code e topic, indici di ricerca, data
lake e warehouse, feature store, embedding e vector DB, file temporanei, export e backup hanno almeno la
stessa classificazione e gli stessi controlli della sorgente: cifratura, accesso, retention, cancellazione.
Gli embedding derivati da dati personali sono dati personali.

**SBD-DATA-15 — Integrità e tracciabilità dei dati critici.** Vincoli di integrità a livello di database
(chiavi, unicità, check, foreign key) e non solo nel codice; per dati finanziari un audit trail append-only
delle modifiche (chi, cosa, quando, valore precedente) protetto da modifiche; checksum o firme per file
scambiati con terze parti; riconciliazioni automatiche dove applicabile.

**SBD-DATA-16 — Preparati alle violazioni.** Rileva accessi anomali ai dati (volumi, orari, origini insoliti);
mantieni la capacità di determinare rapidamente quali record e quali interessati sono stati coinvolti; i tempi
di notifica sono stretti (GDPR: 72 ore all'autorità; DORA: notifica iniziale di incidente grave nell'ordine di
ore). In caso di sospetta violazione avvisa subito il SOC/CSIRT.

**SBD-DATA-17 — Coinvolgi DPO e CISO quando serve.** Fermati ed escala prima di: introdurre un nuovo trattamento
o una nuova finalità di dati personali; trattare dati `PII-SPECIAL`, dati di minori o dati di geolocalizzazione
continua; profilazione o decisioni automatizzate su persone; trasferimenti extra-SEE; nuovi fornitori che
ricevono dati personali; trattamenti su larga scala. Sono casi tipici di DPIA (GDPR art. 35).

## Checklist per uno schema o una migrazione

```markdown
### Dati
| Entità/campo | Classificazione | Etichette | Cifratura | Accesso | Retention | Log/telemetria |
|---|---|---|---|---|---|---|
| customer.email | C2 | PII | storage CMK | runtime RW, reporting no | durata rapporto + 10 anni | mai in chiaro |
| card_token | C2 | — (token PSP) | storage CMK | runtime R | come transazione | sì (token) |
- Nessun PAN/SAD conservato: sì/no (se no, escalation fatta: <link>)
- Copie derivate (cache, eventi, analytics) e loro controlli: <...>
- Cancellazione automatica implementata: <meccanismo>
- Dati di test sintetici: sì
```

## Riferimenti

- `references/classification-handling-matrix.md` — controlli obbligatori per livello di classificazione ed
  etichetta. Leggilo per sapere cosa applicare a un dato classificato.
- `references/crypto-and-keys.md` — algoritmi approvati e vietati, parametri, TLS, gestione e rotazione delle
  chiavi, preparazione post-quantum. Leggilo quando scegli o configuri crittografia.
- `references/payment-card-data.md` — regole per PAN e dati sensibili di autenticazione secondo PCI DSS
  v4.0.1. Leggilo per qualsiasi codice che tocca dati di carta.
