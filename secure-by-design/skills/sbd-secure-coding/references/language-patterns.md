# Pattern per linguaggio: insicuro → sicuro

Leggi solo la sezione dello stack in uso. Gli esempi mostrano il pattern; adatta nomi e configurazioni al
progetto. Le librerie indicate sono scelte mantenute e diffuse: se il progetto ne usa altre equivalenti,
applica lo stesso principio.

## Indice

1. Java / Kotlin — Spring Boot 3, Spring Security 6
2. TypeScript / Node.js — Express, NestJS, React
3. Python — FastAPI, Django, Flask
4. Go
5. C# / .NET 8+

---

## 1. Java / Kotlin — Spring Boot 3, Spring Security 6

**Deny by default (SBD-CODE-09)**

```java
@Bean
SecurityFilterChain api(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health").permitAll()
            .anyRequest().authenticated())                  // tutto il resto richiede autenticazione
        .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
        .headers(h -> h
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
            .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(63072000)));
    return http.build();
}
```

Lascia attiva la protezione CSRF di default se l'applicazione usa cookie di sessione.

**Autorizzazione object-level e tenant (SBD-CODE-09)**

```java
// Insicuro: chiunque conosca l'ID legge l'ordine
Order o = orderRepository.findById(id).orElseThrow();

// Sicuro: il tenant viene dal token, la query lo impone
Order o = orderRepository.findByIdAndTenantId(id, currentUser.tenantId())
        .orElseThrow(NotFoundException::new);
```

**Query parametrizzate (SBD-CODE-03)**

```java
// Insicuro
jdbc.queryForList("SELECT * FROM orders WHERE status = '" + status + "'");

// Sicuro
jdbc.queryForList("SELECT * FROM orders WHERE status = ?", status);

// JPA
@Query("select o from Order o where o.id = :id and o.tenantId = :tenantId")
Optional<Order> findOwned(@Param("id") UUID id, @Param("tenantId") UUID tenantId);

// Ordinamento dinamico tramite allowlist
private static final Map<String, String> SORT = Map.of("date", "created_at", "amount", "amount_minor");
String column = Optional.ofNullable(SORT.get(sortParam)).orElse("created_at");
```

**DTO espliciti contro il mass assignment (SBD-CODE-01, -09)**

```java
public record UpdateProfileRequest(
        @NotBlank @Size(max = 100) String displayName,
        @Email @Size(max = 254) String email) {}
```

```yaml
# application.yml: rifiuta i campi sconosciuti
spring:
  jackson:
    deserialization:
      fail-on-unknown-properties: true
```

**Deserializzazione (SBD-CODE-05)**: niente `ObjectInputStream` su dati esterni; con Jackson niente
`activateDefaultTyping` né `@JsonTypeInfo(use = Id.CLASS)`. Per il polimorfismo usa `Id.NAME` con
`@JsonSubTypes` esplicito.

**XML senza XXE (SBD-CODE-06)**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**Comandi (SBD-CODE-04)**

```java
// Insicuro
Runtime.getRuntime().exec("pdftotext " + userFile);

// Sicuro: eseguibile fisso, argomenti separati, input validato
Process p = new ProcessBuilder(List.of("/usr/bin/pdftotext", "-layout", input.toString(), output.toString()))
        .redirectErrorStream(true).start();
```

**Percorsi (SBD-CODE-12)**

```java
Path base = Paths.get("/srv/app/files").toRealPath();
Path target = base.resolve(fileName).normalize();
if (!target.startsWith(base)) throw new AccessDeniedException("path");
```

**Crittografia e casualità (SBD-CODE-13)**

```java
byte[] token = new byte[32];
new SecureRandom().nextBytes(token);
String value = Base64.getUrlEncoder().withoutPadding().encodeToString(token);

boolean ok = MessageDigest.isEqual(expectedMac, receivedMac);  // confronto in tempo costante

// parametri espliciti (saltLen, hashLen, parallelism, memoryKB, iterations) >= minimo OWASP; richiede BouncyCastle.
// Il factory defaultsForSpringSecurity_v5_8() usa 16 MiB: sotto il minimo di crypto-and-keys.md, non usarlo.
PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);   // m=19 MiB, t=2, p=1
```

**Log (SBD-CODE-15)**: SLF4J con parametri (`log.info("payment authorized id={}", id)`) ed encoder JSON
(es. logstash-logback-encoder) che fa escaping dei valori; mai token, header `Authorization` o PAN.

---

## 2. TypeScript / Node.js — Express, NestJS, React

**Validazione con schema strict (SBD-CODE-01)**

```ts
import { z } from "zod";

const CreatePayment = z.object({
  amountMinor: z.number().int().positive().max(100_000_000),
  currency: z.enum(["EUR"]),
  reference: z.string().max(64).regex(/^[A-Za-z0-9_-]+$/),
}).strict();                                  // rifiuta campi non previsti

const body = CreatePayment.parse(req.body);
```

In NestJS: `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true })`.

**Query parametrizzate (SBD-CODE-03)**

```ts
// Insicuro
await pool.query(`SELECT * FROM orders WHERE id = '${id}'`);

// Sicuro (pg)
await pool.query("SELECT * FROM orders WHERE id = $1 AND tenant_id = $2", [id, user.tenantId]);

// Prisma: $queryRaw con tagged template è parametrizzato; $queryRawUnsafe con input è vietato
await prisma.$queryRaw`SELECT * FROM orders WHERE id = ${id} AND tenant_id = ${user.tenantId}`;
```

**Comandi (SBD-CODE-04)**

```ts
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const run = promisify(execFile);

// Insicuro: exec(`pdftotext ${file}`)
await run("/usr/bin/pdftotext", ["-layout", inputPath, outputPath], { timeout: 30_000 });
```

**Hardening Express (SBD-CODE-10, -17, -22)**

```ts
import helmet from "helmet";
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [(req, res) => `'nonce-${res.locals.cspNonce}'`, "'strict-dynamic'"],
      objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"],
    },
  },
}));
res.cookie("__Host-session", sessionId, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });
```

**JWT con `jose` (SBD-CODE-08)**

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL("https://idp.example.com/.well-known/jwks.json"));

const { payload } = await jwtVerify(token, JWKS, {
  issuer: "https://idp.example.com",
  audience: "payments-api",
  algorithms: ["ES256"],
});
```

Con `jsonwebtoken`: `jwt.verify(token, key, { algorithms: ["ES256"], issuer, audience })`; `jwt.decode()` non
verifica la firma e non va usato per decisioni di sicurezza.

**Casualità e confronto (SBD-CODE-13)**

```ts
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
const token = randomBytes(32).toString("base64url");
const equal = a.length === b.length && timingSafeEqual(a, b);   // a, b: Buffer
```

**Prototype pollution**: non fare merge profondo di oggetti non fidati; valida con schema `.strict()`; usa
`Map` o `Object.create(null)` per dizionari con chiavi esterne; valuta l'avvio di Node con
`--disable-proto=delete`.

**Percorsi (SBD-CODE-12)**

```ts
const base = path.resolve("/srv/app/files");
const target = path.resolve(base, fileName);
const rel = path.relative(base, target);
if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("invalid path");
```

**React (SBD-CODE-02, -19)**: evita `dangerouslySetInnerHTML`; se indispensabile
`{ __html: DOMPurify.sanitize(html) }`. Niente segreti in variabili `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`.
Valida gli URL inseriti in `href`/`src` (blocca `javascript:`).

---

## 3. Python — FastAPI, Django, Flask

**Validazione (SBD-CODE-01)**

```python
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field

class CreatePayment(BaseModel):
    model_config = ConfigDict(extra="forbid")          # rifiuta campi non previsti
    amount_minor: Annotated[int, Field(gt=0, le=100_000_000)]
    currency: Literal["EUR"]
    reference: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
```

**Query parametrizzate (SBD-CODE-03)**

```python
# Insicuro
cur.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")

# Sicuro (psycopg)
cur.execute("SELECT * FROM orders WHERE id = %s AND tenant_id = %s", (order_id, tenant_id))

# SQLAlchemy 2.x
stmt = select(Order).where(Order.id == order_id, Order.tenant_id == tenant_id)
```

**Comandi, YAML, XML, pickle (SBD-CODE-04, -05, -06)**

```python
subprocess.run(["/usr/bin/pdftotext", "-layout", str(src), str(dst)], check=True, timeout=30)  # mai shell=True
data = yaml.safe_load(stream)                       # mai yaml.load senza SafeLoader
from defusedxml.ElementTree import fromstring        # parser XML protetto da XXE e entity expansion
# pickle/joblib/dill solo su file prodotti dal proprio sistema e verificati; per modelli ML usa safetensors
```

**Password, casualità, confronto (SBD-CODE-07, -13)**

```python
from argon2 import PasswordHasher                  # argon2-cffi, parametri di default RFC 9106
ph = PasswordHasher()
stored = ph.hash(password)
ph.verify(stored, candidate)                       # solleva eccezione se non corrisponde
if ph.check_needs_rehash(stored): stored = ph.hash(candidate)

token = secrets.token_urlsafe(32)
ok = hmac.compare_digest(expected_sig, received_sig)
```

**HTTP in uscita (SBD-CODE-11, -13, -17)**: `requests.get(url, timeout=(3, 10))` o `httpx` con timeout;
mai `verify=False`; per CA interne `verify="/path/ca-bundle.pem"`.

**Percorsi (SBD-CODE-12)**

```python
base = Path("/srv/app/files").resolve()
target = (base / file_name).resolve()
if not target.is_relative_to(base):
    raise PermissionError("invalid path")
```

**Django (SBD-CODE-10, -22)**

```python
DEBUG = False
ALLOWED_HOSTS = ["payments.example.com"]
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # solo dietro proxy fidato
```

Non usare `@csrf_exempt`, `mark_safe` su input, `.raw()`/`.extra()` con stringhe costruite.

**FastAPI (SBD-CODE-09)**: applica l'autenticazione a livello di router, così i nuovi endpoint nascono protetti.

```python
router = APIRouter(dependencies=[Depends(require_authenticated_user)])
```

**Flask / Jinja2**: `Environment(autoescape=select_autoescape())`; mai `render_template_string` con input;
mai `app.run(debug=True)` fuori dallo sviluppo locale.

---

## 4. Go

```go
// Query parametrizzate (SBD-CODE-03)
row := db.QueryRowContext(ctx, "SELECT amount FROM orders WHERE id = $1 AND tenant_id = $2", id, tenantID)

// Comandi (SBD-CODE-04): niente "sh -c"
cmd := exec.CommandContext(ctx, "/usr/bin/pdftotext", "-layout", src, dst)

// JSON strict e limite di dimensione (SBD-CODE-01, -17)
r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()

// Server con timeout (SBD-CODE-17)
srv := &http.Server{
    Addr: ":8443", Handler: mux,
    ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
    WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
    TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
}
client := &http.Client{Timeout: 10 * time.Second}   // mai InsecureSkipVerify

// Casualità e confronto (SBD-CODE-13)
b := make([]byte, 32)
if _, err := rand.Read(b); err != nil { return err }   // crypto/rand, non math/rand
ok := subtle.ConstantTimeCompare(expected, received) == 1

// Percorsi (SBD-CODE-12): Go 1.24+ confina l'accesso alla directory
root, err := os.OpenRoot("/srv/app/files")
f, err := root.Open(fileName)
```

Per HTML usa `html/template`, mai `text/template`. Esegui `gosec` e `govulncheck` (che verifica la
raggiungibilità delle vulnerabilità) nel gate.

---

## 5. C# / .NET 8+

```csharp
// Deny by default (SBD-CODE-09)
builder.Services.AddAuthorization(o =>
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

// Query parametrizzate (SBD-CODE-03)
var orders = await db.Orders.Where(o => o.Id == id && o.TenantId == tenantId).ToListAsync();
// FromSql con stringa interpolata è parametrizzato; FromSqlRaw con concatenazione è vietato
var rows = db.Orders.FromSql($"SELECT * FROM Orders WHERE Id = {id}");

// Comandi (SBD-CODE-04)
var psi = new ProcessStartInfo("/usr/bin/pdftotext") { UseShellExecute = false };
psi.ArgumentList.Add("-layout"); psi.ArgumentList.Add(src); psi.ArgumentList.Add(dst);

// XML (SBD-CODE-06)
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };

// Casualità e confronto (SBD-CODE-13)
byte[] token = RandomNumberGenerator.GetBytes(32);
bool ok = CryptographicOperations.FixedTimeEquals(expected, received);

// Password con ASP.NET Core Identity (PBKDF2-HMAC-SHA512)
builder.Services.Configure<PasswordHasherOptions>(o => o.IterationCount = 210_000);
```

Deserializzazione (SBD-CODE-05): usa `System.Text.Json`; con Newtonsoft.Json lascia
`TypeNameHandling.None`; mai `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`. CSRF: antiforgery
abilitato (`[ValidateAntiForgeryToken]`, `app.UseAntiforgery()` per minimal API con form). Cookie:
`CookieSecurePolicy.Always`, `HttpOnly = true`, `SameSite = SameSiteMode.Lax`.
