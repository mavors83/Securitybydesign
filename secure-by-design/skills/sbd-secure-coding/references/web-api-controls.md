# Controlli web e API — valori di riferimento

## Indice

1. Header HTTP di sicurezza
2. Cookie di sessione
3. CORS
4. CSRF
5. JWT
6. OAuth 2.x e OIDC
7. Webhook in ingresso
8. SSRF
9. Upload di file
10. Rate limiting e limiti
11. GraphQL
12. Risposte di errore

## 1. Header HTTP di sicurezza

Pagine HTML:

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-<RANDOM_PER_RISPOSTA>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
```

API JSON:

```http
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Cache-Control: no-store
Content-Type: application/json; charset=utf-8
```

Note:
- Il nonce CSP è casuale (≥ 128 bit, da CSPRNG) e diverso a ogni risposta. Niente `'unsafe-inline'` né
  `'unsafe-eval'` in `script-src`. Avvia una nuova CSP in modalità `Content-Security-Policy-Report-Only` con un
  endpoint di report, poi passa in enforcement.
- `preload` su HSTS solo dopo aver verificato che tutti i sottodomini supportano HTTPS.
- `Cache-Control: no-store` su ogni risposta autenticata che contiene dati C2 o C3.
- Rimuovi `Server`, `X-Powered-By` e header che rivelano versioni.
- Non impostare `X-XSS-Protection` (deprecato): omettilo o impostalo a `0`.
- Se una pagina deve essere incorporata da un partner, sostituisci `frame-ancestors 'none'` con l'elenco esplicito
  degli origin e rimuovi `X-Frame-Options`.

## 2. Cookie di sessione

```http
Set-Cookie: __Host-session=<ID_OPACO>; Path=/; Secure; HttpOnly; SameSite=Lax
```

- Prefisso `__Host-`: impone `Secure`, `Path=/` e assenza di `Domain`, così il cookie non è condivisibile con
  sottodomini.
- `SameSite=Strict` per applicazioni che non ricevono navigazioni da altri siti; `Lax` come minimo.
- `SameSite=None` solo per integrazioni cross-site motivate, sempre con `Secure` e protezione CSRF.
- Nessun dato nel cookie oltre all'identificativo; se serve stato lato client, firmalo e cifralo con chiavi gestite.

## 3. CORS

- Allowlist esplicita di origin per ambiente, in configurazione. Confronto esatto della stringa
  (schema + host + porta), mai `endsWith`, `contains` o regex non ancorate.
- `Access-Control-Allow-Credentials: true` solo insieme a un origin esplicito, mai con `*`.
- Mai riflettere l'header `Origin` ricevuto senza confronto con l'allowlist; aggiungi `Vary: Origin`.
- Metodi e header consentiti limitati a quelli necessari; `Access-Control-Max-Age` ≤ 600 secondi.
- `Access-Control-Allow-Origin: *` è ammesso solo per risorse C0 senza credenziali (asset pubblici, API
  pubbliche anonime), dichiarate nel PR.

## 4. CSRF

- Richiesto per ogni richiesta che modifica stato e si autentica con cookie.
- Usa il meccanismo del framework (Spring Security CSRF, Django CSRF, ASP.NET antiforgery). Per SPA: token
  in un cookie `__Host-csrf` leggibile più header custom (`X-CSRF-Token`) confrontato server-side, oppure
  token sincronizzato in sessione.
- Difesa in profondità: rifiuta richieste che modificano stato con `Sec-Fetch-Site: cross-site` (salvo
  integrazioni previste) e verifica `Origin` contro l'allowlist.
- Le API autenticate solo con `Authorization: Bearer` (nessun cookie) non sono esposte a CSRF classico: è
  l'unico caso in cui la protezione si può omettere, dichiarandolo nel PR.
- Mai operazioni che modificano stato con `GET`.

## 5. JWT

Checklist del verificatore:
- [ ] Algoritmi ammessi fissati in configurazione: `ES256`, `EdDSA`, `PS256` o `RS256` (RSA ≥ 3072 bit per
      nuove chiavi). `HS256` solo se emittente e verificatore sono lo stesso sistema, con segreto ≥ 256 bit
      dal secret manager.
- [ ] `alg: none` rifiutato; l'algoritmo non si legge dall'header del token.
- [ ] Chiave scelta tramite `kid` solo da un JWKS attendibile configurato; ignorati `jku`, `x5u`, `jwk`
      presenti nel token.
- [ ] Verificati firma, `iss`, `aud`, `exp`, `nbf`, `iat`; tolleranza di clock ≤ 60 secondi.
- [ ] Verificato `typ` quando il profilo lo prevede (`at+jwt`, RFC 9068), per evitare confusione tra token
      di tipo diverso (ID token usato come access token).
- [ ] Durata dell'access token da policy (≤ 15 minuti); revoca gestita con durata breve più rotazione dei
      refresh token, o introspection per operazioni ad alto rischio.
- [ ] Nessun dato personale o sensibile nel payload; se indispensabile, JWE.

## 6. OAuth 2.x e OIDC

Riferimento: RFC 9700 (OAuth 2.0 Security Best Current Practice). Per API finanziarie aperte a terzi valuta
il profilo FAPI 2.0.

- Authorization Code + PKCE (`S256`) per tutti i client, anche confidenziali.
- Vietati implicit grant e Resource Owner Password Credentials.
- Redirect URI registrati con corrispondenza esatta; nessun wildcard.
- `state` legato alla sessione per il CSRF del flusso; `nonce` verificato nell'ID token.
- Autenticazione dei client confidenziali con `private_key_jwt` o mTLS, preferiti a `client_secret`.
- Scope minimi; access token con audience ristretta alla singola API.
- Refresh token per client pubblici: rotazione a ogni uso con rilevamento del riuso.
- Token sender-constrained (DPoP, RFC 9449, o mTLS, RFC 8705) per API dispositive.
- Pushed Authorization Requests (RFC 9126) per flussi ad alta sicurezza.
- Il backend valida sempre il token: non fidarti delle claim inoltrate da un componente a monte senza firma.

## 7. Webhook in ingresso

- Firma HMAC-SHA256 calcolata su `timestamp + "." + body grezzo`, con segreto per mittente dal secret manager.
- Confronto della firma in tempo costante.
- Rifiuta eventi con timestamp fuori da una finestra di 5 minuti; registra gli ID evento già elaborati per
  impedire replay.
- Elabora l'evento in modo idempotente; considera il contenuto come input non fidato e, per eventi che
  cambiano stato economico, rileggi lo stato dalla API del mittente.
- In alternativa o in aggiunta: mTLS con certificato del mittente; allowlist IP solo come difesa aggiuntiva.

## 8. SSRF

Procedura per ogni chiamata in uscita verso un URL influenzato dall'input:

1. Fai il parsing dell'URL con la libreria standard; ammetti solo `https` (e `http` solo se motivato).
2. Confronta host e porta con un'allowlist. Se l'allowlist non è possibile (es. webhook configurati dai
   clienti), procedi con i passi successivi e isola la funzione su un egress proxy dedicato.
3. Risolvi il DNS e rifiuta se *uno qualsiasi* degli indirizzi non è globale: loopback, privati RFC 1918,
   CGNAT `100.64.0.0/10`, link-local `169.254.0.0/16` e `fe80::/10`, ULA `fc00::/7`, multicast, riservati,
   IPv4-mapped IPv6 e NAT64 che incapsulano indirizzi vietati. Usa le funzioni della libreria standard
   (`ipaddress.ip_address(x).is_global` in Python, `netip.Addr` in Go) invece di liste scritte a mano.
4. Connettiti all'indirizzo validato (non risolvere di nuovo il nome) per evitare il DNS rebinding.
5. Disabilita i redirect automatici; se servono, ripeti la validazione per ogni salto.
6. Timeout di connessione e lettura, dimensione massima della risposta, nessuna risposta grezza
   restituita al chiamante.
7. In cloud richiedi IMDSv2 o equivalente (SBD-INFRA-16) e filtra l'egress (SBD-INFRA-08).

## 9. Upload di file

- [ ] Dimensione massima imposta dal server e dal reverse proxy.
- [ ] Allowlist di estensioni e verifica del tipo reale sui magic bytes.
- [ ] Nome file generato dal server (UUID); il nome originale, se serve, è un metadato sanificato.
- [ ] Archiviazione su object storage privato o fuori dalla web root, mai eseguibile.
- [ ] Scansione antimalware prima che il file sia disponibile ad altri utenti o sistemi.
- [ ] Immagini ri-codificate (rimuove payload e metadati EXIF con dati personali).
- [ ] Niente SVG, HTML, XML serviti inline dallo stesso origin dell'applicazione; servili da un dominio
      separato senza cookie o come `attachment`.
- [ ] Archivi: limite su numero di voci e dimensione decompressa, rifiuto di percorsi assoluti e `..`.
- [ ] Download tramite URL firmati a scadenza breve (≤ 15 minuti) o endpoint autorizzato.
- [ ] Documenti con macro, PDF con JavaScript: blocca o converti se non necessari.

## 10. Rate limiting e limiti

| Risorsa | Default proposto |
|---|---|
| Login, verifica OTP, recupero password | 5 richieste/minuto per account e 20/minuto per IP, poi blocco progressivo |
| API autenticate | Quota per identità e per client, adeguata al caso d'uso |
| API pubbliche anonime | Limite per IP più protezione anti-bot all'edge |
| Dimensione body JSON | 1 MB salvo necessità motivate |
| Paginazione | `limit` massimo 100 imposto server-side |
| Timeout chiamate in uscita | Connessione 2-5 s, lettura 5-30 s secondo dipendenza |

Rispondi con `429 Too Many Requests` e `Retry-After`. I limiti si applicano server-side e all'edge
(API gateway, WAF): l'uno non sostituisce l'altro.

## 11. GraphQL

- Introspection e suggerimenti di campo disabilitati in produzione.
- Limiti di profondità (≤ 10), di complessità o costo della query, di alias e di batching.
- Persisted queries (allowlist delle query) per client pubblici.
- Autorizzazione a livello di resolver e di campo, non solo all'ingresso.
- Paginazione obbligatoria sulle liste.

## 12. Risposte di errore

Formato uniforme, ad esempio RFC 9457 (Problem Details):

```json
{ "type": "about:blank", "title": "Richiesta non valida", "status": 400, "correlationId": "c1d2e3f4" }
```

- Nessun dettaglio interno; i dettagli vanno nei log associati al `correlationId`.
- Stesso messaggio e codice per "risorsa inesistente" e "risorsa non autorizzata" quando la sola esistenza è
  un'informazione sensibile (rispondi `404` in entrambi i casi).
