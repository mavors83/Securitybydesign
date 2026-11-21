---
name: sbd-secure-coding
description: >
  Regole di secure coding Security by Design per codice applicativo, API, frontend web e mobile. Usare ogni volta
  che si scrive, modifica o revisiona codice che gestisce input, query, comandi, file, autenticazione, sessioni,
  token JWT/OAuth, autorizzazione, multi-tenancy, CORS/CSRF, header di sicurezza, chiamate HTTP in uscita,
  deserializzazione, XML, upload, errori, logging, importi e pagamenti, concorrenza, limiti di risorse, in
  qualunque linguaggio (Java/Spring, Kotlin, TypeScript/Node, Python, Go, C#/.NET, C/C++, Swift).
  Copre OWASP Top 10:2025, OWASP API Security Top 10 e ASVS 5.0. Trigger: "endpoint", "controller",
  "API", "login", "autenticazione", "permessi", "query", "form", "upload", "webhook", "JWT", "OAuth",
  "React", "Spring", "FastAPI", "Express", "fix vulnerabilità", "SQL injection", "XSS", "IDOR".
---

# Secure coding

Queste regole valgono per tutto il codice applicativo. Ogni regola ha un ID da citare nel PR e nelle review.
Per gli esempi concreti per linguaggio leggi `references/language-patterns.md`; per i valori di configurazione
web e API (header, cookie, CORS, JWT, OAuth, SSRF, upload) leggi `references/web-api-controls.md`.

Due idee guidano tutto il resto. **Il server decide**: qualsiasi cosa arrivi dal client (o da un altro sistema)
può essere stata manipolata, quindi validazione, autorizzazione, prezzi e stati si decidono server-side.
**I dati non diventano mai codice**: un input non deve poter cambiare la struttura di una query, di un comando,
di una pagina HTML o di un oggetto deserializzato.

## Input e output

**SBD-CODE-01 — Valida ogni input al trust boundary con uno schema allowlist.** Definisci tipo, formato,
lunghezza, intervallo e insieme di valori ammessi (OpenAPI/JSON Schema, Bean Validation, Pydantic, zod,
FluentValidation). Rifiuta i campi sconosciuti invece di ignorarli. Canonicalizza (Unicode NFC, decodifica
URL, percorsi) prima di validare. Applica limiti di dimensione a body, stringhe, array e profondità di
annidamento. La validazione lato client è solo UX.

**SBD-CODE-02 — Codifica l'output per il contesto di destinazione.** Usa l'auto-escaping del framework di
template (React, Angular, Thymeleaf, Jinja2 con autoescape, Razor). Non costruire HTML concatenando stringhe.
Le API di bypass (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust*`, `mark_safe`,
`|safe`, `Html.Raw`, `innerHTML =`) si usano solo con contenuto passato da un sanitizer approvato (DOMPurify o
equivalente server-side) e con CSP attiva. Per JSON incorporato in pagina usa la serializzazione sicura del
framework.

## Injection

**SBD-CODE-03 — Query sempre parametrizzate.** SQL, HQL/JPQL, NoSQL, LDAP, XPath, GraphQL verso backend:
mai concatenazione o interpolazione di input. Con gli ORM evita i metodi raw con stringhe costruite.
Identificatori dinamici (nome colonna per l'ordinamento, nome tabella) passano da una mappa allowlist, mai
dall'input diretto. In MongoDB e simili rifiuta oggetti dove ti aspetti scalari (blocca operatori come `$ne`,
`$where`) e non usare `$where` né JavaScript lato server.

**SBD-CODE-04 — Nessuna shell.** Preferisci API native a comandi esterni. Se un comando è indispensabile,
invocalo con eseguibile fisso e argomenti in array (`subprocess.run([...], shell=False)`, `ProcessBuilder`,
`execFile`, `exec.Command`), con input validato su allowlist e preceduto da `--` quando il programma lo
supporta. Mai `shell=True`, `os.system`, `Runtime.exec(String)`, `child_process.exec` con input,
`sh -c` con interpolazione.

**SBD-CODE-05 — Nessuna valutazione o deserializzazione nativa di dati non fidati.** Vietati su input non fidato:
`eval`, `exec`, `new Function`, `pickle`/`dill`/`joblib`, `yaml.load` non safe, `ObjectInputStream`,
`XMLDecoder`, `BinaryFormatter`, `NetDataContractSerializer`, `TypeNameHandling` diverso da `None`,
polymorphic typing di Jackson basato su classe, `unserialize` PHP, `Marshal.load` Ruby. Usa formati di dati
(JSON, Protobuf) mappati su tipi espliciti. Template engine: mai template forniti dall'utente (SSTI).

**SBD-CODE-06 — Parser XML sicuri.** Disabilita DTD ed entità esterne (XXE) su ogni parser; in Python usa
`defusedxml`. Limita dimensione ed espansione. Preferisci JSON quando puoi scegliere.

## Autenticazione e sessioni

**SBD-CODE-07 — Autenticazione delegata e credenziali protette.** Gli utenti si autenticano tramite l'Identity
Provider aziendale (OIDC/SAML); non scrivere sistemi di login in proprio se non richiesto esplicitamente e
approvato. Quando servono password locali: hash con Argon2id (o scrypt, bcrypt, PBKDF2 secondo
`sbd-data-protection/references/crypto-and-keys.md`), politica da `sbd-core/references/policy-parameters.md`,
controllo contro password compromesse, MFA per i casi previsti. Protezione da brute force e credential
stuffing: rate limiting per account e per origine, blocco progressivo. Messaggi e tempi di risposta identici
per utente inesistente e password errata (anti-enumerazione), anche in registrazione e recupero password.
Token di recupero monouso, a scadenza breve, conservati come hash. Per servizi machine-to-machine usa mTLS o
OAuth client credentials con credenziali federate o a vita breve. I webhook in ingresso si autenticano con
firma HMAC (o mTLS) verificata in tempo costante, con timestamp e finestra anti-replay.

**SBD-CODE-08 — Sessioni e token gestiti in modo sicuro.**
- Sessioni web: identificativo casuale ad alta entropia generato dal framework, rigenerato al login e a ogni
  cambio di privilegio, invalidato server-side al logout; timeout di inattività e assoluto da policy.
- Cookie: `Secure`, `HttpOnly`, `SameSite=Lax` (o `Strict`), prefisso `__Host-`, nessun attributo `Domain`.
- Nel browser i token non vanno in `localStorage` o `sessionStorage`: usa cookie `HttpOnly` o il pattern
  Backend-for-Frontend.
- JWT: algoritmo fissato lato verificatore (mai preso dall'header, mai `none`), verifica di firma, `iss`,
  `aud`, `exp`, `nbf`; chiavi da JWKS con cache e rotazione; durata breve; nessun dato sensibile nel payload
  (è solo codificato, non cifrato).
- OAuth 2.x/OIDC secondo RFC 9700: Authorization Code con PKCE per tutti i client, niente implicit né password
  grant, redirect URI con corrispondenza esatta, `state` e `nonce` verificati, token sender-constrained
  (DPoP o mTLS) per API ad alto rischio.

## Autorizzazione

**SBD-CODE-09 — Autorizzazione server-side su ogni richiesta, a livello di oggetto, deny by default.**
- Ogni endpoint richiede autenticazione, salvo eccezioni esplicite e motivate (health check pubblici, asset).
  Configura il framework in modo che il default sia "nega" e l'apertura sia esplicita.
- Centralizza la logica in un layer di policy (middleware, annotation, policy engine) invece di spargere `if`.
- **Object-level (BOLA/IDOR)**: per ogni accesso a una risorsa tramite ID verifica che il chiamante ne abbia
  diritto (ownership, tenant, ruolo). Filtra le query per tenant o owner a livello di repository, non solo nel
  controller. ID non enumerabili (UUID) sono difesa in profondità, non autorizzazione.
- **Function-level (BFLA)**: le funzioni amministrative e privilegiate verificano il ruolo server-side;
  nascondere un pulsante non è un controllo.
- **Property-level (BOPLA)**: in ingresso accetta solo i campi modificabili da quel ruolo (DTO espliciti, niente
  binding diretto su entità: mass assignment); in uscita restituisci solo i campi che il chiamante può vedere.
- **Multi-tenancy**: il tenant viene dal token o dalla sessione autenticata, mai da un parametro della richiesta.
- Ogni regola di autorizzazione ha test positivi e negativi (accesso orizzontale e verticale negato).

## Protezioni web e chiamate in uscita

**SBD-CODE-10 — CSRF, CORS e header di sicurezza configurati.** Protezione CSRF per ogni richiesta che
modifica stato autenticata via cookie (token sincronizzato o double-submit firmato, più `SameSite`). CORS con
allowlist esplicita di origin: mai `*` con credenziali, mai riflettere l'header `Origin` ricevuto. Header di
sicurezza (CSP con nonce, HSTS, `X-Content-Type-Options`, `frame-ancestors`, `Referrer-Policy`,
`Permissions-Policy`) con i valori in `references/web-api-controls.md`. Redirect solo verso destinazioni in
allowlist o percorsi relativi (open redirect).

**SBD-CODE-11 — Nessuna SSRF.** Le richieste verso URL influenzati dall'input vanno solo verso destinazioni
in allowlist (schema, host, porta). Risolvi il DNS e rifiuta IP privati, loopback, link-local (incluso
`169.254.169.254` dei metadata cloud) e IPv6 equivalenti; connettiti all'IP validato per evitare DNS
rebinding; non seguire redirect automaticamente; applica timeout e limite di dimensione della risposta.
A livello di rete, egress filtrato (SBD-INFRA-08).

**SBD-CODE-12 — File e percorsi gestiti in sicurezza.** Upload: limite di dimensione, tipo verificato sul
contenuto (magic bytes) e su allowlist di estensioni, nome generato dal server, archiviazione fuori dalla web
root (preferibilmente object storage privato), scansione antimalware per file destinati ad altri utenti,
ri-codifica delle immagini, niente SVG/HTML caricati e serviti dallo stesso dominio. Download: header
`Content-Disposition: attachment` e `Content-Type` corretto. Percorsi: mai concatenare input in un path;
risolvi il percorso canonico e verifica che stia dentro la directory base. Archivi: controlla zip slip e zip
bomb (numero di file, dimensione decompressa).

## Crittografia, errori, log

**SBD-CODE-13 — Usa la crittografia correttamente.** Numeri casuali per token, ID di sessione, OTP, nonce e
chiavi solo da CSPRNG (`secrets`, `SecureRandom`, `crypto.randomBytes`/`randomUUID`, `crypto/rand`,
`RandomNumberGenerator`). Confronto di segreti, firme e MAC in tempo costante. Cifratura simmetrica solo AEAD
(AES-GCM, ChaCha20-Poly1305) con nonce unici. Verifica TLS mai disabilitata, nemmeno "solo in sviluppo": per
CA interne aggiungi la CA al trust store. Algoritmi e parametri in
`sbd-data-protection/references/crypto-and-keys.md`.

**SBD-CODE-14 — Gestione degli errori fail closed e senza leakage.** Intercetta le eccezioni in un handler
centrale che restituisce messaggi generici con un ID di correlazione e registra i dettagli nei log. Mai stack
trace, query, percorsi, versioni o messaggi del database al client. Su eccezione in un controllo di sicurezza
il risultato è "negato". Non inghiottire le eccezioni (`catch {}` vuoti), rilascia le risorse, fai rollback
delle transazioni. Gestisci esplicitamente i casi limite: valori nulli, overflow, timeout di dipendenze,
risposte parziali.

**SBD-CODE-15 — Log degli eventi di sicurezza, senza dati sensibili.** Registra in formato strutturato
(JSON) con timestamp UTC, ID di correlazione, identità del chiamante, azione, risorsa ed esito: login riusciti e
falliti, MFA, logout, cambi di password e di dati di contatto, dinieghi di autorizzazione, errori di
validazione ripetuti, azioni amministrative, accesso a dati C3, modifiche di configurazione e di permessi.
Non loggare mai password, token, chiavi, cookie di sessione, header `Authorization`, PAN, CVV, dati personali
completi (SBD-DATA-12). Neutralizza CR/LF e caratteri di controllo nei valori loggati (log injection).

## Logica di business e risorse

**SBD-CODE-16 — Logica di business robusta.**
- Importi, prezzi, commissioni, sconti e totali si calcolano server-side da dati autorevoli; il valore inviato
  dal client si confronta, non si usa.
- Importi monetari come interi in unità minime o tipi decimali (`BigDecimal`, `Decimal`), mai `float`/`double`;
  arrotondamenti espliciti; valute ISO 4217.
- Operazioni non idempotenti (pagamenti, rimborsi, payout, ordini) accettano una chiave di idempotenza e
  rifiutano i duplicati.
- Saldi, limiti e contatori si aggiornano in transazione con il livello di isolamento adeguato o con locking
  (`SELECT … FOR UPDATE`, optimistic locking con versione, vincoli di unicità e di check a DB).
- Le transizioni di stato seguono una macchina a stati imposta server-side.
- Limiti di velocity e soglie per utente, merchant e strumento di pagamento.

**SBD-CODE-17 — Limiti su ogni risorsa.** Timeout su ogni chiamata di rete e query; limiti su dimensione del
body, numero di elementi, profondità di JSON/XML/GraphQL, paginazione con massimo imposto server-side,
dimensione decompressa; rate limiting e quote per identità; circuit breaker verso dipendenze. Espressioni
regolari applicate a input non fidato: evita il backtracking catastrofico o usa un motore lineare (RE2).

## API

**SBD-CODE-18 — API progettate per essere sicure.** Contratto OpenAPI o schema GraphQL versionato e validato
a runtime. Inventario: ogni API pubblicata è registrata con owner, versione, esposizione e dati trattati;
versioni dismesse vengono rimosse, non lasciate attive. Nessun dato sensibile in URL o query string (finisce
nei log): usa body o header. GraphQL: introspection disabilitata in produzione, limiti di profondità e
complessità, autorizzazione per resolver. Consumo di API di terze parti: tratta le risposte come input non
fidato (SBD-CODE-01), verifica TLS, timeout, gestione degli errori e dei limiti.

## Client

**SBD-CODE-19 — Frontend e mobile senza segreti e con integrità dei contenuti.** Nessun segreto nei bundle
JavaScript, nelle app mobile o nelle variabili esposte al client (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`):
tutto ciò che è nel client è pubblico. Script di terze parti solo da allowlist, con Subresource Integrity e
CSP. Pagine di pagamento: inventario degli script autorizzati con giustificazione, verifica di integrità e
rilevamento delle modifiche (PCI DSS 6.4.3 e 11.6.1); preferisci campi ospitati dal PSP (iframe o hosted
fields) così che il PAN non transiti dal tuo dominio. Mobile (OWASP MASVS): segreti e token nel Keychain o
Keystore, nessun dato sensibile in log, screenshot, backup o clipboard, TLS verificato e certificate pinning
valutato per le app di pagamento, WebView con JavaScript e accesso ai file disabilitati se non necessari,
controlli anti-tampering e anti-root solo come difesa aggiuntiva.

## Linguaggi e build

**SBD-CODE-20 — Memory safety.** Per nuovo codice preferisci linguaggi memory-safe. In C/C++: niente funzioni
non sicure (`gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`), flag di hardening del compilatore
(`-D_FORTIFY_SOURCE=3`, `-fstack-protector-strong`, PIE, RELRO, `-Wall -Wextra -Werror`), sanitizer (ASan,
UBSan) e fuzzing in CI. In Rust ogni blocco `unsafe` è motivato in un commento e revisionato.

## Qualità e verifica

**SBD-CODE-21 — Test di sicurezza insieme al codice.** Per ogni controllo scrivi almeno un test negativo:
accesso a risorsa di un altro utente o tenant negato, ruolo insufficiente negato, input malevolo (injection,
path traversal, payload troppo grande) rifiutato, token scaduto o con firma errata rifiutato, errore della
dipendenza gestito senza leakage. Per parser e funzioni che elaborano input complessi aggiungi test
property-based o fuzzing.

**SBD-CODE-22 — Configurazione sicura di default e niente scorciatoie in produzione.** Niente endpoint di
debug, console, backdoor, utenti di test, bypass di autenticazione o feature flag che disattivano controlli nel
codice che va in produzione. Debug mode, stack trace verbosi, actuator, profiler e Swagger UI disattivati o
protetti in produzione. Ogni flag di sicurezza ha come default il valore sicuro: l'assenza di configurazione
non deve aprire nulla.

## Come usare queste regole durante il lavoro

1. Prima di scrivere il codice individua quali regole si applicano (di solito 01, 03, 09, 14, 15, 17 sempre;
   le altre secondo la funzionalità) e scegli pattern e librerie conformi.
2. Mentre scrivi, consulta `references/language-patterns.md` per lo stack in uso.
3. Scrivi i test negativi (SBD-CODE-21) prima di dichiarare completato il lavoro.
4. Elenca nel PR gli ID delle regole applicate e passa a `sbd-security-gate`.

## Riferimenti

- `references/web-api-controls.md` — valori di riferimento per header HTTP, cookie, CORS, CSRF, JWT, OAuth/OIDC,
  SSRF, upload e rate limiting. Leggilo quando configuri un'applicazione web o un'API.
- `references/language-patterns.md` — pattern insicuro → sicuro per Java/Spring, TypeScript/Node, Python, Go,
  C#/.NET. Leggi la sezione dello stack in uso.
