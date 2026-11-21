# Crittografia e gestione delle chiavi

Regola generale: usa librerie di alto livello che scelgono parametri sicuri al posto tuo (Google Tink, AWS
Encryption SDK, libsodium, le API crittografiche del KMS). Le primitive di basso livello (`Cipher`,
`createCipheriv`, `cryptography.hazmat`) si usano solo quando non c'è alternativa e con i parametri qui sotto.

## Indice

1. Algoritmi approvati
2. Algoritmi e pratiche vietati
3. Password e segreti a bassa entropia
4. Envelope encryption
5. Ricerca su dati cifrati
6. TLS
7. Ciclo di vita delle chiavi
8. Preparazione post-quantum

## 1. Algoritmi approvati

| Uso | Approvato | Note |
|---|---|---|
| Cifratura simmetrica | AES-256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV | Nonce di 96 bit unico per chiave; con nonce casuali non superare 2³² messaggi per chiave (usa data key per oggetto o record) |
| Cifratura deterministica (solo se serve) | AES-SIV | Rivela l'uguaglianza tra valori: usala solo con motivazione |
| Key wrapping | KMS/HSM, AES-KW o AES-KWP (RFC 3394, 5649) | |
| Hash | SHA-256, SHA-384, SHA-512, SHA3-256/512 | |
| MAC | HMAC-SHA-256/384/512, KMAC | Verifica in tempo costante |
| Derivazione di chiavi | HKDF-SHA-256/512 | Solo da materiale ad alta entropia |
| Firma digitale | Ed25519, ECDSA P-256/P-384, RSA-PSS ≥ 3072 bit | RSA PKCS#1 v1.5 per firme ammesso solo per compatibilità (es. JWT RS256) |
| Cifratura asimmetrica | RSA-OAEP con SHA-256 ≥ 3072 bit, HPKE (RFC 9180) | Mai RSA PKCS#1 v1.5 per cifratura |
| Scambio di chiavi | X25519, ECDH P-256/P-384, ibrido X25519MLKEM768 | |
| Numeri casuali | CSPRNG del sistema operativo | `secrets`, `SecureRandom`, `crypto.randomBytes`, `crypto/rand`, `RandomNumberGenerator` |

## 2. Algoritmi e pratiche vietati

- MD5 e SHA-1 per qualsiasi uso di sicurezza (firme, integrità, password, token, HMAC di nuova introduzione).
  Per usi non di sicurezza (chiavi di cache, deduplicazione) dichiaralo esplicitamente nel codice.
- DES, 3DES, RC4, Blowfish, IDEA, RC2.
- Modalità ECB; CBC senza autenticazione (per sistemi legacy solo encrypt-then-MAC con HMAC).
- IV o nonce fissi, riutilizzati, derivati da contatori non persistenti tra riavvii.
- RSA < 2048 bit; per le nuove chiavi RSA < 3072 bit, con la sola eccezione dei certificati TLS foglia a breve
  durata (vedi §6, dove RSA ≥ 2048 è ammesso per il certificato foglia); DSA; curve non standard.
- Chiavi o salt hardcoded, chiavi derivate da password senza KDF per password, chiavi nel codice o nei file di
  configurazione versionati.
- Algoritmi o protocolli inventati, "offuscamento" (base64, XOR) presentato come cifratura.
- Generatori non crittografici (`Math.random`, `java.util.Random`, `random` di Python, `math/rand` di Go) per
  token, ID di sessione, OTP, password temporanee, nonce, chiavi.
- TLS < 1.2, SSL, cipher NULL, EXPORT, anonime, RC4, CBC in TLS 1.2 dove evitabile, scambio chiavi RSA statico.

## 3. Password e segreti a bassa entropia

| Algoritmo | Parametri minimi |
|---|---|
| Argon2id (preferito) | m = 19 MiB, t = 2, p = 1 (minimo OWASP); raccomandato m = 64 MiB, t = 3, p = 4 (RFC 9106) |
| scrypt | N = 2¹⁷, r = 8, p = 1 |
| bcrypt | cost ≥ 12; attenzione: considera solo i primi 72 byte, rifiuta password più lunghe o pre-hash con HMAC |
| PBKDF2 (solo se serve conformità FIPS) | HMAC-SHA-256 ≥ 600.000 iterazioni, HMAC-SHA-512 ≥ 210.000 |

- Salt casuale per password, gestito dalla libreria.
- Pepper opzionale (HMAC con chiave nel secret manager o HSM) come difesa aggiuntiva.
- Rehash trasparente al login quando i parametri vengono rafforzati.
- Per segreti brevi da confrontare (OTP, codici di recupero) usa hash con chiave e limita i tentativi: lo spazio è
  troppo piccolo per resistere alla forza bruta offline.

## 4. Envelope encryption

Schema per cifrare campi o oggetti C3:

1. Richiedi al KMS una data key (`GenerateDataKey`): ottieni la chiave in chiaro e la stessa cifrata con la CMK.
2. Cifra il dato con AES-256-GCM usando la data key, un nonce casuale di 96 bit e come dati associati (AAD) il
   contesto del record (es. `tenant_id|tabella|id_record|nome_campo`): così il ciphertext non può essere
   spostato su un altro record senza che la decifratura fallisca.
3. Salva insieme: identificativo e versione della CMK, data key cifrata, nonce, ciphertext con tag.
4. Elimina la data key in chiaro dalla memoria appena possibile; se la metti in cache, limita durata e numero di
   utilizzi (le librerie come AWS Encryption SDK e Tink lo gestiscono).
5. Per decifrare: chiedi al KMS di decifrare la data key (operazione registrata nei log di audit e soggetta a
   IAM), poi decifra il dato verificando l'AAD.

Vantaggi: la CMK non esce mai dal KMS, ogni decifratura è autorizzata e tracciata, la rotazione della CMK non
richiede di ricifrare tutti i dati, la cancellazione della chiave rende illeggibili i dati (crypto-shredding).

## 5. Ricerca su dati cifrati

- Per cercare per uguaglianza un campo cifrato (es. email, codice fiscale) salva accanto al ciphertext un
  **indice cieco**: `HMAC-SHA-256(chiave_indice, valore_normalizzato)` con chiave dedicata nel KMS o secret
  manager. Mai `SHA-256(valore)` senza chiave: per dati a bassa entropia si inverte con un dizionario.
- Le ricerche per prefisso o intervallo su dati cifrati rivelano informazioni: valutale con Security
  Engineering.

## 6. TLS

- Versioni: TLS 1.3 preferito, TLS 1.2 ammesso; tutto il resto disabilitato.
- Cipher suite TLS 1.2 ammesse: `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`,
  `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-CHACHA20-POLY1305`,
  `ECDHE-RSA-CHACHA20-POLY1305`. TLS 1.3: suite di default della libreria.
- Certificati: ECDSA P-256 o RSA ≥ 2048 bit per il certificato foglia a breve durata (≥ 3072 per CA e chiavi a
  lunga durata). La durata massima dei
  certificati pubblici si riduce progressivamente (200 giorni da marzo 2026, 100 da marzo 2027, 47 da marzo
  2029, secondo il CA/Browser Forum): il rinnovo deve essere automatico.
- Verifica del certificato e del nome host sempre attiva; per CA interne configura il trust store, non
  disattivare la verifica.
- HSTS sui servizi web pubblici; OCSP stapling dove supportato.
- L'inventario di protocolli e cipher suite in uso è rivisto annualmente (PCI DSS 12.3.3).

## 7. Ciclo di vita delle chiavi

| Fase | Requisito |
|---|---|
| Generazione | In KMS o HSM, mai su postazioni di lavoro; entropia del modulo certificato |
| Custodia | Nel KMS/HSM; chiavi applicative mai in chiaro su disco, in configurazione o in variabili versionate |
| Uso | Una chiave per finalità (cifratura dati, firma, MAC, indice cieco), per ambiente e, dove serve, per tenant; permessi IAM separati per amministrazione e uso |
| Rotazione | CMK/KEK: automatica annuale; data key: per oggetto o record; chiavi di firma: secondo durata dei certificati; immediata su sospetta compromissione |
| Versioning | La versione della chiave è salvata con il ciphertext per permettere rotazione e ricifratura graduale |
| Revoca e distruzione | Procedura documentata con periodo di attesa; verifica preventiva dei dati ancora cifrati con la chiave |
| Separazione dei compiti | Chi amministra le chiavi non accede ai dati e viceversa; per chiavi PCI controllo duale e conoscenza frazionata dove richiesto |
| Audit | Ogni operazione sulle chiavi registrata e inviata al SIEM; alert su uso anomalo |
| Inventario | Registro di chiavi, certificati e algoritmi (CBOM): finalità, owner, algoritmo, lunghezza, scadenza, sistemi che le usano |

## 8. Preparazione post-quantum

Gli standard NIST sono pubblicati (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) e la roadmap
coordinata UE prevede di avviare la transizione entro il 2026 e completarla per i casi ad alto rischio entro il
2030. Il rischio immediato è "harvest now, decrypt later": dati C3 con riservatezza di lunga durata catturati
oggi possono essere decifrati in futuro.

Azioni richieste ora:
- **Agilità crittografica**: algoritmi e parametri configurabili, non cablati nel codice; versione
  dell'algoritmo salvata con i dati e le firme.
- **Inventario**: mantieni il CBOM aggiornato, così sai cosa migrare.
- **Scambio di chiavi ibrido** (X25519MLKEM768) in TLS dove client, server e librerie lo supportano, a partire
  dai flussi che trasportano dati C3 a lunga durata.
- **Simmetrico a 256 bit** (AES-256) per i nuovi sviluppi: margine adeguato anche in scenario quantistico.
- Coinvolgi Security Engineering per firme a lunga durata e PKI interne.
