#!/usr/bin/env python3
"""sbd_patterns.py - scanner deterministico di pattern insicuri (Security by Design).

Primo livello del security gate SBD: cerca pattern noti come pericolosi (segreti, PAN, crittografia debole,
TLS disattivato, injection, deserializzazione, configurazioni insicure di container, Kubernetes, IaC e CI).
Non sostituisce SAST, SCA e secret scanner dedicati: li affianca con regole allineate alle linee guida SBD.

Uso:
  sbd_patterns.py [PATH ...]           analizza file e directory (default: directory corrente)
  sbd_patterns.py --diff BASE [PATH]   analizza solo le righe aggiunte rispetto a BASE (git) e i file non tracciati
  sbd_patterns.py --list-rules         elenca le regole

Opzioni:
  --fail-on {critical,high,medium,low} severita minima che fa fallire il controllo (default: high)
  --json                               output JSON
  --exclude GLOB                       esclude percorsi (ripetibile); vedi anche il file .sbdignore

Soppressione di un finding (sulla stessa riga o sulla riga precedente), con motivazione obbligatoria:
  # sbd-ignore: P-CRYPTO-01 hash usato solo come chiave di cache, nessun uso di sicurezza

Exit code: 0 nessun finding sopra soglia, 1 finding sopra soglia, 2 errore d'uso o di esecuzione.
Richiede solo la libreria standard di Python 3.10+.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_FILE_BYTES = 2 * 1024 * 1024
SNIPPET_MAX = 160

# --------------------------------------------------------------------------------------------------------------
# Gruppi di file
# --------------------------------------------------------------------------------------------------------------
PY = ("*.py",)
JS = ("*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.mts", "*.cts", "*.tsx", "*.vue", "*.svelte")
JAVA = ("*.java", "*.kt", "*.kts", "*.scala", "*.groovy")
GO = ("*.go",)
CS = ("*.cs",)
C = ("*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hh", "*.hpp")
PHP_RB = ("*.php", "*.rb")
TEMPLATES = ("*.html", "*.htm", "*.hbs", "*.handlebars", "*.mustache", "*.ejs", "*.jinja", "*.jinja2", "*.j2",
             "*.njk", "*.twig", "*.liquid", "*.vue", "*.svelte", "*.cshtml", "*.razor", "*.erb")
CODE = PY + JS + JAVA + GO + CS + C + PHP_RB + ("*.rs", "*.swift", "*.ps1") + TEMPLATES
DOCKER = ("Dockerfile", "*.Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile")
YAML = ("*.yml", "*.yaml")
SHELLISH = ("*.sh", "*.bash", "*.zsh", "Makefile", "*.mk", "Jenkinsfile", "*.ps1", "package.json") + YAML + DOCKER
CONFIG = ("*.env", ".env", ".env.*", "*.ini", "*.cfg", "*.conf", "*.properties", "*.toml", "*.json", "*.xml",
          "*.config", ".npmrc", "*.npmrc", ".gitconfig", "pip.conf", "requirements*.txt", "*.gradle") + YAML
ENVLIKE = ("*.env", ".env", ".env.*", "*.ini", "*.cfg", "*.conf", "*.properties")
IAC = ("*.tf", "*.tf.json", "*.hcl", "*.tfvars", "*.json", "*.bicep")
GHA = (".github/workflows/*.yml", ".github/workflows/*.yaml", "action.yml", "action.yaml")
ANY = ("*",)

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "bower_components", "vendor", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "target", "out", ".next", ".nuxt", ".svelte-kit", "coverage",
    ".gradle", ".idea", ".vscode", ".terraform", ".terragrunt-cache", "Pods", "DerivedData", ".sbd-gate",
}
DEFAULT_EXCLUDED_FILES = (
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "uv.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "packages.lock.json", "*.min.js",
    "*.min.css", "*.map", "*.svg",
)
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".jar", ".war", ".class", ".so", ".dll", ".dylib", ".exe", ".bin", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".pptx", ".docx", ".xlsx", ".mp4", ".mp3", ".wav", ".avi", ".mov", ".sqlite", ".db",
    ".parquet", ".pkl", ".pt", ".onnx", ".safetensors", ".keystore", ".jks", ".p12", ".pfx",
}

# --------------------------------------------------------------------------------------------------------------
# Modello delle regole
# --------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    ref: str
    fix: str
    files: tuple = ANY
    pattern: Optional[re.Pattern] = None
    context: Optional[re.Pattern] = None
    exclude: Optional[re.Pattern] = None
    check: Optional[Callable[[re.Match], bool]] = None
    redact: bool = False
    file_check: Optional[Callable[[list], list]] = None  # restituisce [(numero_riga, testo)]


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    ref: str
    fix: str
    path: str
    line: int
    snippet: str
    suppressed: bool = False
    suppression_reason: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", None) or k in ("snippet",)}


def rx(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


# ---- validatori -------------------------------------------------------------------------------------------------

TEST_PANS = {
    "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556", "4222222222222",
    "5555555555554444", "5105105105105100", "5200828282828210", "2223003122003222", "2222400070000005",
    "378282246310005", "371449635398431", "378734493671000", "6011111111111117", "6011000990139424",
    "3530111333300000", "3566002020360505", "6200000000000005", "4917610000000000", "4988080000000000",
}


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def pan_check(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if not 13 <= len(digits) <= 19 or digits in TEST_PANS:
        return False
    if re.search(r"(\d)\1{5,}", digits):  # sequenze ripetute: numeri di test o segnaposto
        return False
    return luhn_ok(digits)


FIELD_NAME_VALUES = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "accesstoken", "authtoken", "clientsecret",
    "newpassword", "currentpassword", "confirmpassword", "privatekey", "passwordconfirmation", "oldpassword",
}
PLACEHOLDER_RX = rx(r"(?i)^(?:\$\{.*\}|\$\(.*\)|\$[A-Z_][A-Z0-9_]*|\{\{.*\}\}|<[^>]*>|%\(.*\)s?|x{3,}|\*{3,}|\.{3,})$"
                    r"|example|placeholder|dummy|redacted|replace[_-]?me|your[_-]")


def secret_value_check(m: re.Match) -> bool:
    val = m.group("val")
    if PLACEHOLDER_RX.search(val):
        return False
    if re.sub(r"[#._-]", "", val).lower() in FIELD_NAME_VALUES:
        return False
    return True


def conn_string_check(m: re.Match) -> bool:
    val = m.group("val")
    return val.lower() not in {"password", "pass", "pwd", "secret", "xxx", "xxxx", "****"} and not PLACEHOLDER_RX.search(val)


DOCKER_SECRET_KEY_RX = rx(r"(?i)_(?:FILE|PATH|DIR|NAME|URL|ENDPOINT|ID)$")


def docker_env_secret_check(m: re.Match) -> bool:
    if DOCKER_SECRET_KEY_RX.search(m.group("key")):
        return False
    val = m.group("val").strip("\"'")
    return not (val.startswith("$") or val.startswith("/run/secrets") or PLACEHOLDER_RX.search(val))


# ---- controlli a livello di file ----------------------------------------------------------------------------------

FROM_RX = rx(r"(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?")
USER_RX = rx(r"(?i)^\s*USER\s+\S+")
NONROOT_BASE_RX = rx(r"(?i)(?::nonroot\b|cgr\.dev/|/chainguard/|distroless/.*nonroot)")


def dockerfile_no_user(lines: list) -> list:
    last_from, user_after = None, False
    for i, text in enumerate(lines, 1):
        m = FROM_RX.match(text)
        if m:
            last_from, user_after = (i, text, m.group("image")), False
        elif USER_RX.match(text):
            user_after = True
    if last_from and not user_after and not NONROOT_BASE_RX.search(last_from[2]) and last_from[2].lower() != "scratch":
        return [(last_from[0], last_from[1])]
    return []


def dockerfile_unpinned_from(lines: list) -> list:
    aliases, out = set(), []
    for i, text in enumerate(lines, 1):
        m = FROM_RX.match(text)
        if not m:
            continue
        image = m.group("image")
        if (image.lower() != "scratch" and image.lower() not in aliases and "@sha256:" not in image
                and "$" not in image):
            out.append((i, text))
        if m.group("alias"):
            aliases.add(m.group("alias").lower())
    return out


CAP_BLOCK_RX = rx(r"^\s*-?\s*(?P<key>add|drop|cap_add|cap_drop)\s*:\s*(?P<inline>\[.*\])?\s*(?:#.*)?$")
DANGEROUS_CAPS_RX = rx(r"\b(?:CAP_)?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|NET_RAW|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|ALL)\b")


def yaml_dangerous_caps(lines: list) -> list:
    """Capability pericolose sotto 'add:' (Kubernetes) o 'cap_add:' (Compose); 'drop:' e ignorato."""
    out, mode, mode_indent = [], None, -1
    for i, text in enumerate(lines, 1):
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(text) - len(text.lstrip())
        m = CAP_BLOCK_RX.match(text)
        if m:
            mode = "add" if m.group("key").endswith("add") else "drop"
            mode_indent = indent
            if m.group("inline"):
                if mode == "add" and DANGEROUS_CAPS_RX.search(m.group("inline")):
                    out.append((i, text))
                mode = None
            continue
        if mode is not None and (stripped == "-" or stripped.startswith("- ")) and indent >= mode_indent:
            if mode == "add" and DANGEROUS_CAPS_RX.search(stripped):
                out.append((i, text))
            continue
        mode = None
    return out


# --------------------------------------------------------------------------------------------------------------
# Catalogo delle regole
# --------------------------------------------------------------------------------------------------------------

R = Rule
RULES: list = [
    # --- Segreti (SBD-CORE-01) ---------------------------------------------------------------------------------
    R("P-SECRET-01", "critical", "Chiave privata nel repository", "SBD-CORE-01",
      "Rimuovi la chiave, revocala e generane una nuova nel KMS/secret manager.",
      pattern=rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), redact=True),
    R("P-SECRET-02", "critical", "Access key AWS nel codice", "SBD-CORE-01",
      "Revoca la chiave; usa ruoli IAM e identita federate (SBD-INFRA-03).",
      pattern=rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), exclude=rx(r"EXAMPLE"), redact=True),
    R("P-SECRET-03", "critical", "Token GitHub nel codice", "SBD-CORE-01",
      "Revoca il token; in CI usa GITHUB_TOKEN con permessi minimi o OIDC.",
      pattern=rx(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), redact=True),
    R("P-SECRET-04", "critical", "Token Slack nel codice", "SBD-CORE-01",
      "Revoca il token e spostalo nel secret manager.",
      pattern=rx(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), redact=True),
    R("P-SECRET-05", "critical", "Chiave API Google nel codice", "SBD-CORE-01",
      "Revoca la chiave, limitane l'uso e spostala nel secret manager.",
      pattern=rx(r"\bAIza[0-9A-Za-z_\-]{35}\b"), redact=True),
    R("P-SECRET-06", "critical", "Chiave segreta Stripe live nel codice", "SBD-CORE-01",
      "Revoca la chiave dalla dashboard e spostala nel secret manager.",
      pattern=rx(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"), redact=True),
    R("P-SECRET-07", "critical", "Chiave API di un provider LLM nel codice", "SBD-CORE-01",
      "Revoca la chiave; le chiavi dei provider passano dal secret manager e da un gateway (SBD-AI-06).",
      pattern=rx(r"\bsk-(?:ant-[A-Za-z0-9_\-]{20,}|proj-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{40,})"), redact=True),
    R("P-SECRET-08", "high", "JWT letterale nel codice", "SBD-CORE-01",
      "Non committare token: generali nei test con chiavi di test o leggili dal secret manager.",
      pattern=rx(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), redact=True),
    R("P-SECRET-09", "high", "Credenziale hardcoded", "SBD-CORE-01",
      "Leggi il valore dal secret manager o da una variabile iniettata a runtime; negli esempi usa <REPLACE_ME>.",
      pattern=rx(r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
                 r"client[_-]?secret|private[_-]?key)[\w.-]*[\"']?\s*(?::=|=>|:|=)\s*[\"'](?P<val>[^\"'\s]{6,})[\"']"),
      check=secret_value_check, redact=True),
    R("P-SECRET-10", "high", "Credenziale in file di configurazione", "SBD-CORE-01",
      "Non versionare file .env o properties con segreti: committa solo un .env.example con placeholder.",
      files=ENVLIKE,
      pattern=rx(r"(?i)^\s*(?:export\s+)?[\w.-]*(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)[\w.-]*"
                 r"\s*[=:]\s*(?P<val>[^\s\"'#$<{][^\s#]{5,})\s*$"),
      check=secret_value_check, redact=True),
    R("P-SECRET-11", "high", "Credenziali in URL di connessione", "SBD-CORE-01",
      "Separa le credenziali dall'URL e leggile dal secret manager o usa autenticazione IAM.",
      pattern=rx(r"\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@'\"]{1,64}:(?P<val>[^/\s:@'\"]{3,})@[^\s'\"]+"),
      exclude=rx(r"(?i)@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|\[::1\])\b"),
      check=conn_string_check, redact=True),
    # --- Dati di carta (SBD-DATA-06) ---------------------------------------------------------------------------
    R("P-PAN-01", "high", "Possibile numero di carta (PAN) in chiaro", "SBD-DATA-06",
      "Mai PAN reali nel codice o nei dati di test: usa i numeri di test dei circuiti o token del PSP.",
      pattern=rx(r"(?<![\w.])(?:[2-6]\d{12,18}|[2-6]\d{3}(?P<sep>[ -])\d{4}(?P=sep)\d{4}(?P=sep)\d{1,7})(?![\w.])"),
      check=pan_check, redact=True),
    # --- Crittografia (SBD-CODE-13) ----------------------------------------------------------------------------
    R("P-CRYPTO-01", "medium", "Hash debole (MD5/SHA-1)", "SBD-CODE-13",
      "Usa SHA-256 o superiore; per password Argon2id. Se non e un uso di sicurezza, dichiaralo con sbd-ignore.",
      files=CODE,
      pattern=rx(r"(?i)(?:\bhashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|"
                 r"createHash\(\s*['\"](?:md5|sha1)['\"]|\bDigestUtils\.(?:md5|sha1)(?:Hex)?\s*\(|"
                 r"\b(?:MD5|SHA1)\.Create\s*\(|\b(?:md5|sha1)\.(?:New|Sum)\s*\(|(?<![\w.])(?:md5|sha1)\s*\()"),
      exclude=rx(r"usedforsecurity\s*=\s*False")),
    R("P-CRYPTO-02", "high", "Cifratura in modalita ECB", "SBD-CODE-13",
      "Usa AES-GCM o ChaCha20-Poly1305 tramite libreria di alto livello (Tink, libsodium).",
      files=CODE,
      pattern=rx(r"(?i)(?:\b(?:AES|DESede|DES)/ECB\b|\bMODE_ECB\b|['\"]aes-\d+-ecb['\"]|CipherMode\.ECB\b|"
                 r"modes\.ECB\s*\()")),
    R("P-CRYPTO-03", "high", "Cifrario obsoleto (DES/3DES/RC4/Blowfish)", "SBD-CODE-13",
      "Usa AES-256-GCM o ChaCha20-Poly1305.",
      files=CODE,
      pattern=rx(r"(?:Cipher\.getInstance\(\s*\"(?:DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2)\b|"
                 r"createCipheriv\(\s*['\"](?:des|des-ede3|des-ede|rc4|bf|blowfish|rc2)[-'\"]|"
                 r"\b(?:DES|TripleDES|RC2)\.Create\s*\(|\b(?:ARC4|DES3?|Blowfish)\.new\s*\(|"
                 r"algorithms\.(?:TripleDES|Blowfish|ARC4|IDEA)\s*\()")),
    R("P-CRYPTO-04", "high", "Generatore casuale non crittografico per un valore di sicurezza", "SBD-CODE-13",
      "Usa il CSPRNG: secrets, SecureRandom, crypto.randomBytes, crypto/rand, RandomNumberGenerator.",
      files=CODE,
      pattern=rx(r"(?:\bMath\.random\s*\(|\bnew\s+Random\s*\(|\brandom\.(?:random|randint|choice|choices|randrange|"
                 r"getrandbits|sample)\s*\(|\brand\.(?:Intn|Int63n?|Int31n?|Float64|Uint32|Perm)\s*\()"),
      context=rx(r"(?i)(?:token|secret|passw|nonce|otp|salt|session|api_?key|csrf|reset|verif|\bpin\b|\biv\b|"
                 r"\bkey\b|_key\b|\bkey_|\bcode\b)")),
    # --- TLS (SBD-CODE-13) -------------------------------------------------------------------------------------
    R("P-TLS-01", "critical", "Verifica TLS disattivata nel codice", "SBD-CODE-13",
      "Mai disattivare la verifica: aggiungi la CA interna al trust store.",
      files=CODE + CONFIG,
      pattern=rx(r"(?:\bverify\s*=\s*False\b|ssl\._create_unverified_context|\bssl\.CERT_NONE\b|"
                 r"\bcheck_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false|"
                 r"NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0|InsecureSkipVerify\s*:\s*true|"
                 r"\bNoopHostnameVerifier\b|ALLOW_ALL_HOSTNAME_VERIFIER|\bTrustAllStrategy\b|\bTrustSelfSignedStrategy\b|"
                 r"setHostnameVerifier\s*\(\s*\(?[^()]*\)?\s*->\s*true|"
                 r"ServerCertificateCustomValidationCallback\s*=.*=>\s*true|DangerousAcceptAnyServerCertificateValidator)")),
    R("P-TLS-02", "high", "Verifica TLS disattivata in uno strumento da riga di comando", "SBD-CODE-13",
      "Rimuovi -k/--insecure/--trusted-host/sslVerify=false e configura il trust store.",
      files=SHELLISH + CONFIG,
      pattern=rx(r"(?:\bcurl\b[^|\n]*\s(?:-[A-Za-z]*k[A-Za-z]*|--insecure)\b|\bwget\b[^|\n]*--no-check-certificate|"
                 r"\bsslVerify\s*=?\s*false\b|\bGIT_SSL_NO_VERIFY\b|\bstrict-ssl\s*[=:]?\s*false\b|--trusted-host\b|"
                 r"--disable-ssl-verif|\bhttp\.sslVerify\s+false)")),
    # --- Esecuzione di codice e comandi (SBD-CODE-04, SBD-CODE-05) ----------------------------------------------
    R("P-EXEC-01", "high", "Valutazione dinamica di codice (eval/exec)", "SBD-CODE-05",
      "Non valutare stringhe come codice; usa parser di dati o una mappa di funzioni consentite.",
      files=PY + JS + PHP_RB,
      pattern=rx(r"(?<![\w.$])(?:eval|exec)\s*\(")),
    R("P-EXEC-02", "high", "new Function o timer con stringa di codice", "SBD-CODE-05",
      "Passa funzioni, non stringhe; non costruire codice da input.",
      files=JS,
      pattern=rx(r"\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]")),
    R("P-EXEC-03", "high", "Comando eseguito tramite shell (Python)", "SBD-CODE-04",
      "Usa subprocess.run([...]) con argomenti in lista e shell=False.",
      files=PY,
      pattern=rx(r"\bshell\s*=\s*True\b|\bos\.(?:system|popen)\s*\(|\bcommands\.getoutput\s*\(")),
    R("P-EXEC-04", "high", "Comando eseguito tramite shell (Node.js)", "SBD-CODE-04",
      "Usa execFile/spawn con argomenti in array e senza shell: true.",
      files=JS,
      pattern=rx(r"\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\(|\bexecSync\s*\(|"
                 r"\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true")),
    R("P-EXEC-05", "high", "Comando eseguito tramite shell (Java)", "SBD-CODE-04",
      "Usa ProcessBuilder con eseguibile fisso e argomenti separati, senza sh -c.",
      files=JAVA,
      pattern=rx(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(\s*(?:List\.of\(|Arrays\.asList\()?\s*"
                 r"\"(?:/bin/)?(?:sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)\"")),
    R("P-EXEC-06", "high", "Comando eseguito tramite shell (Go)", "SBD-CODE-04",
      "Usa exec.Command con eseguibile e argomenti separati, senza sh -c.",
      files=GO,
      pattern=rx(r"exec\.Command(?:Context)?\s*\([^)]*\"(?:/bin/)?(?:ba)?sh\"\s*,\s*\"-c\"")),
    R("P-EXEC-07", "high", "Comando eseguito tramite shell (C/C++/PHP/.NET)", "SBD-CODE-04",
      "Usa API che accettano eseguibile e argomenti separati, senza interprete di shell.",
      files=C + PHP_RB + CS,
      pattern=rx(r"(?<![\w.>])(?:system|popen|shell_exec|passthru|proc_open)\s*\(|"
                 r"ProcessStartInfo\s*\(\s*\"(?:cmd(?:\.exe)?|powershell(?:\.exe)?|/bin/(?:ba)?sh)\"")),
    # --- Deserializzazione e XML (SBD-CODE-05, SBD-CODE-06) -----------------------------------------------------
    R("P-DESER-01", "high", "Deserializzazione nativa Python (pickle e simili)", "SBD-CODE-05",
      "Usa JSON o formati di dati; per modelli ML safetensors. Pickle solo su file propri e verificati.",
      files=PY,
      pattern=rx(r"\b(?:pickle|cPickle|_pickle|dill|marshal)\.loads?\s*\(|\bjoblib\.load\s*\(|\bshelve\.open\s*\(")),
    R("P-DESER-02", "high", "YAML caricato senza SafeLoader", "SBD-CODE-05",
      "Usa yaml.safe_load o Loader=yaml.SafeLoader.",
      files=PY,
      pattern=rx(r"\byaml\.(?:unsafe_load|unsafe_load_all|load|load_all)\s*\("),
      exclude=rx(r"SafeLoader|CSafeLoader")),
    R("P-DESER-03", "high", "Deserializzazione insicura (Java)", "SBD-CODE-05",
      "Niente ObjectInputStream/XMLDecoder su dati esterni; con Jackson niente default typing.",
      files=JAVA,
      pattern=rx(r"new\s+ObjectInputStream\s*\(|\bXMLDecoder\b|\.(?:enableDefaultTyping|activateDefaultTyping)\s*\(|"
                 r"JsonTypeInfo\.Id\.CLASS\b")),
    R("P-DESER-04", "high", "Deserializzazione insicura (.NET)", "SBD-CODE-05",
      "Usa System.Text.Json; con Newtonsoft TypeNameHandling.None.",
      files=CS,
      pattern=rx(r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter)\b|"
                 r"TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b")),
    R("P-DESER-05", "high", "Deserializzazione insicura (PHP/Ruby)", "SBD-CODE-05",
      "Usa json_decode / JSON.parse; mai unserialize o Marshal.load su dati esterni.",
      files=PHP_RB,
      pattern=rx(r"(?<![\w.>])unserialize\s*\(|\bMarshal\.load\s*\(|\bYAML\.load\s*\(")),
    R("P-XXE-01", "high", "Parser XML con entita esterne o DTD abilitati", "SBD-CODE-06",
      "Disabilita DTD ed entita esterne; in Python usa defusedxml.",
      files=CODE,
      pattern=rx(r"\bresolve_entities\s*=\s*True|XMLInputFactory\.SUPPORT_DTD\s*,\s*(?:true|Boolean\.TRUE)|"
                 r"DtdProcessing\s*=\s*DtdProcessing\.Parse|\bXmlResolver\s*=\s*new\s+XmlUrlResolver|"
                 r"setExpandEntityReferences\s*\(\s*true|external-general-entities\"\s*,\s*true")),
    # --- Injection (SBD-CODE-03) -------------------------------------------------------------------------------
    R("P-SQLI-01", "high", "Query SQL costruita con concatenazione o interpolazione", "SBD-CODE-03",
      "Usa query parametrizzate; identificatori dinamici tramite allowlist.",
      files=CODE,
      pattern=rx(r"[\"'`]\s*(?:SELECT\s.*?\sFROM\s|INSERT\s+INTO\s|UPDATE\s+[\w.\"`\[\]]+\s+SET\s|DELETE\s+FROM\s|"
                 r"select\s.*?\sfrom\s.*?\swhere\s|insert\s+into\s.*?\svalues\b|update\s+[\w.]+\s+set\s+\w+\s*=|"
                 r"delete\s+from\s+[\w.]+\s+where\s)"),
      context=rx(r"(?:[\"'`]\s*\+\s*[\w(]|[\w)]\s*\+\s*[\"'`]|\$\{|\bf[\"'][^\"']*\{|[\"']\s*%\s*[\w(]|"
                 r"\.format\s*\(|#\{|String\.format\s*\(|fmt\.Sprintf\s*\(|\$\"[^\"]*\{)"),
      exclude=rx(r"\$queryRaw\s*`|\bsql\s*`|Prisma\.sql\s*`|\bFromSql\s*\(\s*\$\"")),
    R("P-SQLI-02", "medium", "Metodo SQL raw o non parametrizzato", "SBD-CODE-03",
      "Usa API parametrizzate (PreparedStatement, $queryRaw con tagged template, FromSql interpolato).",
      files=CODE,
      pattern=rx(r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(|\.raw\s*\(\s*f[\"']|\bFromSqlRaw\s*\(\s*\$\"|"
                 r"\bFromSqlRaw\s*\([^)]*\"\s*\+|\.extra\s*\(\s*(?:where|select)\s*=|\bcreateStatement\s*\(\s*\)")),
    R("P-NOSQL-01", "medium", "Operatore $where in query NoSQL", "SBD-CODE-03",
      "Non usare $where/JavaScript lato server; rifiuta oggetti dove ti aspetti scalari.",
      files=CODE,
      pattern=rx(r"[\"']\$where[\"']")),
    # --- XSS e output (SBD-CODE-02) ----------------------------------------------------------------------------
    R("P-XSS-01", "high", "Inserimento di HTML non sanificato", "SBD-CODE-02",
      "Usa l'escaping del framework; se serve HTML, passa da un sanitizer (DOMPurify) e attiva la CSP.",
      files=CODE,
      pattern=rx(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|"
                 r"\bdangerouslySetInnerHTML\b|\bv-html\s*=|\[innerHTML\]\s*=|"
                 r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(|\bmark_safe\s*\(|"
                 r"\bHtml\.Raw\s*\(|(?<![\w.])Markup\s*\(|\$sce\.trustAsHtml\s*\(|\bth:utext\b"),
      exclude=rx(r"(?i)(?:DOMPurify\.sanitize|\bsanitize(?:Html)?\s*\(|bleach\.clean|"
                 r"(?:inner|outer)HTML\s*=\s*([\"'`])\1)")),
    R("P-XSS-02", "high", "Output non codificato nel template", "SBD-CODE-02",
      "Usa l'interpolazione con escaping del template engine; il filtro safe solo su HTML sanificato.",
      files=TEMPLATES,
      pattern=rx(r"\{\{\{|<%-|\|\s*safe\b|\{%-?\s*autoescape\s+(?:false|off)\b|\{!!")),
    # --- Web, autenticazione, sessioni (SBD-CODE-08, -10, -22) -------------------------------------------------
    R("P-WEB-01", "high", "CORS aperto a qualsiasi origine", "SBD-CODE-10",
      "Configura un'allowlist esplicita di origin per ambiente.",
      files=CODE + CONFIG,
      pattern=rx(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']|\borigins?[\"']?\s*[:=]\s*[\"']\*[\"']|"
                 r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|"
                 r"@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?[\"']\*[\"']|\.AllowAnyOrigin\s*\(\s*\)|"
                 r"allowedOrigin(?:Pattern)?s\s*\(\s*[\"']\*[\"']|(?<![\w.])cors\s*\(\s*\)")),
    R("P-WEB-02", "high", "Protezione CSRF disattivata", "SBD-CODE-10",
      "Mantieni la protezione CSRF per richieste autenticate via cookie; omettila solo per API Bearer-only dichiarate nel PR.",
      files=CODE + CONFIG,
      pattern=rx(r"\bcsrf\s*\(\s*\)\s*\.\s*disable\s*\(|\bcsrf\s*\(\s*(?:AbstractHttpConfigurer::disable|"
                 r"\w+\s*->\s*\w+\.disable\(\))\s*\)|@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|\bcsrf\s*:\s*false\b|"
                 r"\[IgnoreAntiforgeryToken|\.DisableAntiforgery\s*\(|csrf_protection\s*=\s*False")),
    R("P-WEB-03", "medium", "Modalita debug attiva", "SBD-CODE-22",
      "Disattiva il debug fuori dallo sviluppo locale e leggilo da configurazione con default sicuro.",
      files=CODE + CONFIG + DOCKER,
      pattern=rx(r"^\s*DEBUG\s*=\s*True\b|\.run\s*\([^)]*\bdebug\s*=\s*True|\bFLASK_DEBUG\s*[=:]\s*[\"']?1\b|"
                 r"\bapp\.debug\s*=\s*True|ASPNETCORE_ENVIRONMENT[\"']?\s*[=:]\s*[\"']?Development")),
    R("P-WEB-04", "high", "Cookie di sessione senza Secure o HttpOnly", "SBD-CODE-08",
      "Imposta Secure, HttpOnly e SameSite sui cookie di sessione e CSRF.",
      files=CODE + CONFIG,
      pattern=rx(r"(?i)(?:SESSION_COOKIE_(?:SECURE|HTTPONLY)|CSRF_COOKIE_SECURE)\s*=\s*False|"
                 r"\b(?:secure|httpOnly)\s*:\s*false\b|\.set(?:Secure|HttpOnly)\s*\(\s*false\s*\)|"
                 r"\b(?:HttpOnly|Secure)\s*=\s*false\b"),
      context=rx(r"(?i)cookie|session|csrf|setSecure|setHttpOnly")),
    R("P-WEB-05", "medium", "ALLOWED_HOSTS aperto a qualsiasi host", "SBD-CODE-22",
      "Elenca esplicitamente gli host ammessi.",
      files=PY,
      pattern=rx(r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']")),
    R("P-AUTH-01", "critical", "Verifica del token JWT disattivata o algoritmo none", "SBD-CODE-08",
      "Verifica sempre firma, iss, aud, exp con algoritmi fissati lato verificatore.",
      files=CODE + CONFIG,
      pattern=rx(r"(?i)\balgorithms?[\"']?\s*[:=]\s*\[?\s*[\"']none[\"']|[\"']?verify_signature[\"']?\s*:\s*False|"
                 r"\bjwt\.decode\s*\([^)]*verify\s*=\s*False|\bignoreExpiration\s*:\s*true|"
                 r"[\"']?verify_exp[\"']?\s*:\s*False|\.parseUnsecured(?:Claims)?\s*\(|"
                 r"\b(?:RequireSignedTokens|ValidateIssuerSigningKey|ValidateLifetime|ValidateAudience|ValidateIssuer)"
                 r"\s*=\s*false\b")),
    R("P-AUTH-02", "medium", "Decodifica JWT senza verifica della firma (Node.js)", "SBD-CODE-08",
      "Usa jwt.verify / jwtVerify con algoritmi, issuer e audience; decode non verifica nulla.",
      files=JS,
      pattern=rx(r"\bjwt\.decode\s*\(|\bdecodeJwt\s*\(")),
    # --- Log (SBD-CODE-15, SBD-DATA-12) ------------------------------------------------------------------------
    R("P-LOG-01", "medium", "Possibile dato sensibile nei log", "SBD-DATA-12",
      "Logga identificativi o valori mascherati; applica filtri di redazione centralizzati.",
      files=CODE,
      pattern=rx(r"(?i)\b(?:log(?:ger)?|console|logging|slog|zap|log4j|Log)\.\w+\s*\(.*\b(?:password|passwd|pwd|"
                 r"secret|access_?token|refresh_?token|id_?token|auth_?token|bearer|authorization|api_?key|cvv2?|cvc2?|"
                 r"card_?number|cardnumber|\bpan\b|iban|ssn|codice_?fiscale)"),
      exclude=rx(r"(?i)mask|redact|\*\*\*|sanitiz|token_type|tokeniz")),
    # --- Dockerfile (SBD-INFRA-11) ------------------------------------------------------------------------------
    R("P-DOCKER-01", "high", "Container eseguito come root (USER root)", "SBD-INFRA-11",
      "Usa un utente non root con UID numerico nell'ultimo stage.",
      files=DOCKER,
      pattern=rx(r"(?i)^\s*USER\s+(?:root|0)(?::\S+)?\s*$")),
    R("P-DOCKER-02", "high", "Nessuna istruzione USER: il container gira come root", "SBD-INFRA-11",
      "Aggiungi USER con UID non zero nell'ultimo stage o usa un'immagine base nonroot.",
      files=DOCKER, file_check=dockerfile_no_user),
    R("P-DOCKER-03", "medium", "Immagine base non fissata per digest", "SBD-SC-07",
      "Fissa l'immagine con @sha256:<digest> e lascia il tag in commento.",
      files=DOCKER, file_check=dockerfile_unpinned_from),
    R("P-DOCKER-04", "medium", "ADD da URL remoto senza checksum", "SBD-SC-07",
      "Scarica con verifica del checksum o usa ADD --checksum=sha256:...",
      files=DOCKER,
      pattern=rx(r"(?i)^\s*ADD\s+(?:--\S+\s+)*https?://"), exclude=rx(r"--checksum=")),
    R("P-DOCKER-05", "high", "Segreto in ENV o ARG del Dockerfile", "SBD-INFRA-11",
      "I segreti restano nei layer: usa RUN --mount=type=secret o iniettali a runtime.",
      files=DOCKER,
      pattern=rx(r"(?i)^\s*(?:ENV|ARG)\s+(?P<key>\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)\w*)"
                 r"(?:\s*=\s*|\s+)(?P<val>\S+)"),
      check=docker_env_secret_check, redact=True),
    # --- Shell, script e pacchetti (SBD-CORE-02, SBD-CORE-10, SBD-SC-06) ----------------------------------------
    R("P-SHELL-01", "high", "Download eseguito direttamente da un interprete (curl | sh)", "SBD-CORE-10",
      "Scarica a versione fissata, verifica checksum o firma, poi esegui.",
      files=SHELLISH,
      pattern=rx(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da)?sh|python3?|perl|ruby|node)\b|"
                 r"\b(?:ba)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)|\b(?:ba)?sh\s+<\(\s*(?:curl|wget)")),
    R("P-SHELL-02", "high", "Permessi 777 su file o directory", "SBD-INFRA-12",
      "Concedi i permessi minimi al solo utente o gruppo necessario.",
      files=SHELLISH + CODE,
      pattern=rx(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|ugo\+rwx)\b|\bos\.chmod\s*\([^)]*0o?777\b")),
    R("P-SHELL-03", "high", "Hook di git aggirati (--no-verify)", "SBD-CORE-02",
      "Non saltare i controlli di pre-commit/pre-push: correggi la causa del fallimento.",
      files=SHELLISH + CODE,
      pattern=rx(r"\bgit\s+(?:commit|push|merge|rebase|am|cherry-pick)\b[^\n]*\s--no-verify\b|"
                 r"\bgit\s+commit\b[^\n]*\s-n\b")),
    R("P-PKG-01", "high", "Indice di pacchetti aggiuntivo (dependency confusion)", "SBD-SC-06",
      "Usa un solo --index-url verso il registry/proxy interno.",
      files=SHELLISH + CONFIG,
      pattern=rx(r"--extra-index-url\b|^\s*extra-index-url\s*=")),
    # --- Kubernetes e Compose (SBD-INFRA-12, SBD-INFRA-13, SBD-INFRA-15) ----------------------------------------
    R("P-K8S-01", "critical", "Container privilegiato", "SBD-INFRA-12",
      "Rimuovi privileged: true; concedi solo le capability strettamente necessarie.",
      files=YAML, pattern=rx(r"^\s*privileged\s*:\s*true\b")),
    R("P-K8S-02", "high", "Escalation dei privilegi consentita", "SBD-INFRA-12",
      "Imposta allowPrivilegeEscalation: false.",
      files=YAML, pattern=rx(r"^\s*allowPrivilegeEscalation\s*:\s*true\b")),
    R("P-K8S-03", "high", "Esecuzione come root nel container", "SBD-INFRA-12",
      "Imposta runAsNonRoot: true e un runAsUser diverso da 0.",
      files=YAML,
      pattern=rx(r"^\s*(?:runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false\b|user\s*:\s*[\"']?(?:root|0)(?::0)?[\"']?\s*$)")),
    R("P-K8S-04", "high", "Namespace dell'host condivisi con il container", "SBD-INFRA-12",
      "Rimuovi hostNetwork/hostPID/hostIPC o network_mode/pid host.",
      files=YAML,
      pattern=rx(r"^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b|^\s*(?:network_mode|pid|ipc)\s*:\s*[\"']?host\b")),
    R("P-K8S-05", "medium", "Volume hostPath o socket Docker montato", "SBD-INFRA-12",
      "Usa volumi gestiti; il socket Docker equivale a root sull'host.",
      files=YAML, pattern=rx(r"^\s*hostPath\s*:|/var/run/docker\.sock")),
    R("P-K8S-06", "high", "Capability Linux pericolose aggiunte al container", "SBD-INFRA-12",
      "Usa capabilities.drop: [ALL] e aggiungi solo capability indispensabili e motivate.",
      files=YAML, file_check=yaml_dangerous_caps),
    R("P-K8S-07", "medium", "File system root del container scrivibile", "SBD-INFRA-12",
      "Imposta readOnlyRootFilesystem: true e monta emptyDir per le directory scrivibili.",
      files=YAML, pattern=rx(r"^\s*readOnlyRootFilesystem\s*:\s*false\b")),
    R("P-K8S-08", "medium", "Immagine container non fissata per digest", "SBD-SC-07",
      "Fissa l'immagine per digest (@sha256:...) e lascia il tag in commento.",
      files=YAML,
      pattern=rx(r"^\s*-?\s*image\s*:\s*[\"']?[^\s\"'{}$#]+[\"']?\s*(?:#.*)?$"), exclude=rx(r"@sha256:")),
    R("P-K8S-09", "high", "Secret Kubernetes con valori nel manifest", "SBD-INFRA-15",
      "Non versionare Secret: usa External Secrets/CSI driver con il secret manager.",
      files=YAML, pattern=rx(r"^\s*kind\s*:\s*Secret\s*(?:#.*)?$")),
    R("P-K8S-10", "high", "RBAC con wildcard", "SBD-INFRA-13",
      "Elenca verbi, risorse e apiGroups necessari.",
      files=YAML,
      pattern=rx(r"^\s*-?\s*(?:verbs|resources|apiGroups)\s*:\s*\[\s*[\"']?\*[\"']?\s*\]")),
    R("P-K8S-11", "medium", "Wildcard in una lista YAML (RBAC, origin, host)", "SBD-CORE-03",
      "Sostituisci il wildcard con valori espliciti.",
      files=YAML, pattern=rx(r"^\s*-\s*[\"']\*[\"']\s*(?:#.*)?$")),
    R("P-K8S-12", "high", "Binding al ruolo cluster-admin", "SBD-INFRA-13",
      "Crea un Role con i soli permessi necessari, limitato al namespace.",
      files=YAML, pattern=rx(r"^\s*name\s*:\s*[\"']?cluster-admin[\"']?\s*$")),
    # --- IaC (SBD-INFRA-04, -07, -10, -16, -17, -20) -------------------------------------------------------------
    R("P-IAC-01", "high", "Storage con accesso pubblico", "SBD-INFRA-17",
      "Blocca l'accesso pubblico e concedi accesso solo tramite identita.",
      files=IAC,
      pattern=rx(r"\bacl\s*=\s*\"public-read(?:-write)?\"|\bpublic_access_prevention\s*=\s*\"inherited\"|"
                 r"\ballow_(?:nested_items_to_be_public|blob_public_access)\s*=\s*true|"
                 r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false|"
                 r"\"(?:allUsers|allAuthenticatedUsers)\"")),
    R("P-IAC-02", "high", "Risorsa esposta con accesso di rete pubblico", "SBD-INFRA-07",
      "Usa subnet private e private endpoint; disabilita l'accesso pubblico.",
      files=IAC,
      pattern=rx(r"\b(?:publicly_accessible|public_network_access_enabled|associate_public_ip_address|ipv4_enabled)"
                 r"\s*=\s*true\b")),
    R("P-IAC-03", "high", "Cifratura disattivata", "SBD-INFRA-17",
      "Abilita la cifratura con chiave gestita (CMK per C2-C3).",
      files=IAC,
      pattern=rx(r"\b(?:storage_encrypted|encrypted|encryption_enabled|enable_encryption|at_rest_encryption_enabled|"
                 r"transit_encryption_enabled|encrypt_at_rest|infrastructure_encryption_enabled|"
                 r"https_traffic_only_enabled|enable_https_traffic_only)\s*=\s*false\b")),
    R("P-IAC-04", "medium", "Rotazione della chiave KMS disattivata", "SBD-DATA-05",
      "Imposta enable_key_rotation = true.",
      files=IAC, pattern=rx(r"\benable_key_rotation\s*=\s*false\b")),
    R("P-IAC-05", "high", "Policy IAM con azioni wildcard (*)", "SBD-INFRA-04",
      "Elenca le azioni necessarie.",
      files=IAC,
      pattern=rx(r"\"Action\"\s*:\s*(?:\"\*\"|\[\s*\"\*\"\s*\])|\bactions\s*=\s*\[\s*\"\*\"\s*\]")),
    R("P-IAC-06", "medium", "Policy IAM con wildcard di servizio o su tutte le risorse", "SBD-INFRA-04",
      "Restringi azioni e risorse; ammesso nelle istruzioni Deny dei guardrail (dichiaralo con sbd-ignore).",
      files=IAC,
      pattern=rx(r"\"Action\"\s*:\s*\"[a-z0-9-]+:\*\"|\bactions\s*=\s*\[[^\]]*\"[a-z0-9-]+:\*\"|"
                 r"\"Resource\"\s*:\s*\"\*\"|\bresources\s*=\s*\[\s*\"\*\"\s*\]")),
    R("P-IAC-07", "high", "Principal pubblico in una policy", "SBD-INFRA-04",
      "Specifica i principal autorizzati o aggiungi condizioni restrittive.",
      files=IAC,
      pattern=rx(r"\"Principal\"\s*:\s*\"\*\"|\"Principal\"\s*:\s*\{\s*\"AWS\"\s*:\s*\"\*\"\s*\}")),
    R("P-IAC-08", "medium", "Regola di rete aperta a qualsiasi indirizzo", "SBD-INFRA-07",
      "Limita le sorgenti; 0.0.0.0/0 solo in ingresso al load balancer pubblico sulla 443.",
      files=IAC,
      pattern=rx(r"\b(?:cidr_blocks|cidr_ipv4|ipv6_cidr_blocks|cidr_ipv6|source_ranges|source_address_prefix(?:es)?)"
                 r"\s*=\s*\[?\s*\"(?:0\.0\.0\.0/0|::/0|\*|Internet|Any)\"")),
    R("P-IAC-09", "high", "Metadata service IMDSv1 consentito", "SBD-INFRA-16",
      "Imposta http_tokens = \"required\".",
      files=IAC, pattern=rx(r"\bhttp_tokens\s*=\s*\"optional\"")),
    R("P-IAC-10", "high", "Versione TLS minima obsoleta", "SBD-INFRA-10",
      "Imposta TLS 1.2 come minimo (TLS 1.3 preferito).",
      files=IAC + YAML,
      pattern=rx(r"\b(?:min(?:imum)?_tls_version|minimal_tls_version|min_tls)\s*=\s*\"(?:TLS1_0|TLS1_1|1\.0|1\.1|"
                 r"TLSv1(?:\.1)?|TLS_1_0|TLS_1_1)\"|ssl_policy\s*=\s*\"ELBSecurityPolicy-(?:2015-05|2016-08|"
                 r"TLS-1-0-2015-04|TLS-1-1-2017-01)\"|\bminTlsVersion\s*:\s*[\"']?(?:TLS1_0|TLS1_1|1\.0|1\.1)")),
    R("P-IAC-11", "medium", "Logging o audit disattivato", "SBD-INFRA-20",
      "Mantieni attivi log di audit e validazione dei log.",
      files=IAC,
      pattern=rx(r"\b(?:enable_logging|logging_enabled|enable_log_file_validation|is_logging)\s*=\s*false\b")),
    # --- CI/CD (SBD-INFRA-18, SBD-SC-07) -------------------------------------------------------------------------
    R("P-CICD-01", "medium", "Action non fissata per SHA", "SBD-SC-07",
      "Usa uses: owner/action@<sha-40-caratteri> # vX.Y.Z.",
      files=GHA,
      pattern=rx(r"^\s*-?\s*uses\s*:\s*[\"']?(?!\.{1,2}/)(?!docker://)[^@\s\"']+@(?![0-9a-f]{40}\b)[^\s\"'#]+")),
    R("P-CICD-02", "high", "Possibile script injection nel workflow", "SBD-INFRA-18",
      "Passa il valore in una variabile env: e usala quotata nello script.",
      files=GHA,
      pattern=rx(r"\$\{\{\s*github\.event\.[\w.\[\]*'\"-]*?\.(?:title|body|message|name|email|label|ref|head_ref|"
                 r"default_branch|page_name|description)\b[^}]*\}\}|\$\{\{\s*github\.head_ref\s*\}\}"),
      exclude=rx(r"^\s*-?\s*(?!run\s*:)[A-Za-z_][\w-]*\s*:(?:\s|$)")),
    R("P-CICD-03", "high", "Trigger pull_request_target", "SBD-INFRA-18",
      "Non eseguire codice della PR con i permessi del repository; separa build non fidata e azioni privilegiate.",
      files=GHA,
      pattern=rx(r"^\s*-?\s*pull_request_target\s*:?|^\s*on\s*:\s*\[?[^\]#\n]*\bpull_request_target\b")),
    R("P-CICD-04", "high", "Permessi write-all nel workflow", "SBD-INFRA-18",
      "Dichiara permissions minimi per job (es. contents: read).",
      files=GHA, pattern=rx(r"^\s*permissions\s*:\s*write-all\b")),
    R("P-CICD-05", "medium", "Tutti i segreti passati al workflow riutilizzabile", "SBD-INFRA-18",
      "Passa solo i segreti necessari al workflow chiamato.",
      files=GHA, pattern=rx(r"^\s*secrets\s*:\s*inherit\b")),
    # --- Memoria e varie ---------------------------------------------------------------------------------------
    R("P-MEM-01", "high", "Funzione C non sicura", "SBD-CODE-20",
      "Usa alternative con limiti (snprintf, strlcpy o API sicure) e abilita hardening e sanitizer.",
      files=C, pattern=rx(r"(?<![\w.>])(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(")),
    R("P-MISC-01", "medium", "File temporaneo creato in modo insicuro", "SBD-CODE-12",
      "Usa tempfile.mkstemp / NamedTemporaryFile.",
      files=PY + C, pattern=rx(r"\btempfile\.mktemp\s*\(|(?<![\w.])(?:mktemp|tmpnam|tempnam)\s*\(")),
    R("P-MISC-02", "medium", "Configurazione insicura di storage o WebView Android", "SBD-CODE-19",
      "Niente file world-readable; WebView con JavaScript e accesso ai file solo se indispensabili.",
      files=JAVA,
      pattern=rx(r"\bMODE_WORLD_(?:READABLE|WRITEABLE)\b|setAllow(?:File|UniversalAccessFromFileURLs|"
                 r"FileAccessFromFileURLs)\w*\s*\(\s*true|setJavaScriptEnabled\s*\(\s*true")),
]

SUPPRESS_RX = rx(r"sbd-ignore:\s*(?P<ids>P-[A-Z0-9]+-\d{2}(?:\s*,\s*P-[A-Z0-9]+-\d{2})*)\s*(?P<reason>.*)$")


# --------------------------------------------------------------------------------------------------------------
# Motore
# --------------------------------------------------------------------------------------------------------------


def match_globs(relpath: str, globs: Iterable) -> bool:
    base = os.path.basename(relpath)
    for g in globs:
        if g == "*" or fnmatch.fnmatch(base, g) or fnmatch.fnmatch(relpath, g) or fnmatch.fnmatch(relpath, "*/" + g):
            return True
    return False


def redact_snippet(text: str, span: tuple) -> str:
    s, e = span
    secret = text[s:e]
    shown = secret[:4] if len(secret) > 8 else ""
    return text[:s] + shown + "…[REDACTED]" + text[e:]


def make_snippet(text: str, span: Optional[tuple], redact: bool) -> str:
    out = text.rstrip("\n")
    if redact and span:
        out = redact_snippet(out, span)
    out = out.strip()
    return out if len(out) <= SNIPPET_MAX else out[:SNIPPET_MAX] + "…"


COMMENT_ONLY_RX = rx(r"^\s*(?:#|//|/\*|<!--|--|;|\{#|<%#|\*)?\s*$")


def parse_suppressions(lines: list) -> dict:
    """Restituisce {numero_riga: {id_regola: motivazione}}.

    Un marker su una riga di solo commento vale per la riga successiva; un marker in coda a una riga di codice
    vale solo per quella riga. La motivazione resta associata alle regole del proprio marker.
    """
    result: dict = {}
    for i, text in enumerate(lines, 1):
        m = SUPPRESS_RX.search(text)
        if not m:
            continue
        ids = {x.strip() for x in m.group("ids").split(",")}
        reason = re.sub(r"(?:\*/|-->|#}|%>)\s*$", "", m.group("reason")).strip(" -:")
        target = i + 1 if COMMENT_ONLY_RX.match(text[:m.start()]) else i
        per_rule = result.setdefault(target, {})
        for rid in ids:
            if len(reason) > len(per_rule.get(rid, "")):
                per_rule[rid] = reason
            else:
                per_rule.setdefault(rid, reason)
    return result


def scan_text(relpath: str, content: str, only_lines: Optional[set] = None) -> list:
    lines = content.splitlines()
    suppress = parse_suppressions(lines)
    findings: list = []
    applicable = [r for r in RULES if match_globs(relpath, r.files)]
    for rule in applicable:
        hits: list = []
        if rule.file_check:
            hits = [(ln, txt, None) for ln, txt in rule.file_check(lines)]
        elif rule.pattern is not None:
            for i, text in enumerate(lines, 1):
                if only_lines is not None and i not in only_lines:
                    continue
                if len(text) > 4000:  # righe minificate: fuori ambito
                    continue
                for m in rule.pattern.finditer(text):
                    if rule.context and not rule.context.search(text):
                        break
                    if rule.exclude and rule.exclude.search(text):
                        break
                    if rule.check and not rule.check(m):
                        continue
                    hits.append((i, text, m.span("val") if "val" in m.re.groupindex else m.span()))
                    break
        for ln, text, span in hits:
            f = Finding(rule.id, rule.severity, rule.title, rule.ref, rule.fix, relpath, ln,
                        make_snippet(text, span, rule.redact))
            reason = suppress.get(ln, {}).get(rule.id)
            if reason is not None:
                if len(reason) >= 10:
                    f.suppressed, f.suppression_reason = True, reason
                else:
                    f.note = "soppressione ignorata: serve una motivazione di almeno 10 caratteri"
            findings.append(f)
    return findings


def read_text(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def load_ignore_file(root: str) -> list:
    path = os.path.join(root, ".sbdignore")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]


SELF_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))  # directory della skill sbd-security-gate


def walk(root: str, excludes: list) -> Iterable:
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            rel = os.path.normpath(os.path.join(rel_dir, d)).replace(os.sep, "/")
            if d in DEFAULT_EXCLUDED_DIRS or os.path.realpath(full) == SELF_DIR:
                continue
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel + "/", g) for g in excludes):
                continue
            keep.append(d)
        dirnames[:] = sorted(keep)
        for fn in sorted(filenames):
            rel = os.path.normpath(os.path.join(rel_dir, fn)).replace(os.sep, "/")
            if os.path.splitext(fn)[1].lower() in BINARY_EXT or match_globs(rel, DEFAULT_EXCLUDED_FILES):
                continue
            if any(fnmatch.fnmatch(rel, g) for g in excludes):
                continue
            yield os.path.join(dirpath, fn), rel


def git(args: list, cwd: str) -> str:
    res = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {res.stderr.strip()}")
    return res.stdout


HUNK_RX = rx(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def diff_targets(root: str, base: str) -> dict:
    """Mappa percorso relativo -> insieme di righe aggiunte (None = file intero, per i file non tracciati)."""
    top = git(["rev-parse", "--show-toplevel"], root).strip()
    out: dict = {}
    current = None
    for line in git(["diff", "--no-color", "--no-ext-diff", "--unified=0", "--diff-filter=ACMR", base, "--", "."],
                    root).splitlines():
        if line.startswith("+++ "):
            current = None if line.strip() == "+++ /dev/null" else line[6:] if line.startswith("+++ b/") else None
            if current:
                out.setdefault(current, set())
            continue
        m = HUNK_RX.match(line)
        if m and current:
            start, count = int(m.group("start")), int(m.group("count") or "1")
            out[current].update(range(start, start + count))
    for rel in git(["ls-files", "--others", "--exclude-standard", "--full-name", "--", "."], root).splitlines():
        out[rel] = None
    # percorsi relativi alla root di git -> relativi alla directory analizzata
    result = {}
    for rel, lines in out.items():
        abs_path = os.path.join(top, rel)
        result[os.path.relpath(abs_path, root).replace(os.sep, "/")] = lines
    return result


def run(paths: list, base: Optional[str], excludes: list) -> tuple:
    findings: list = []
    scanned = 0
    for target in paths:
        if os.path.isfile(target):
            content = read_text(target)
            if content is not None:
                scanned += 1
                findings += scan_text(target.replace(os.sep, "/"), content)
            continue
        if not os.path.isdir(target):
            raise FileNotFoundError(target)
        all_excludes = excludes + load_ignore_file(target)
        if base:
            for rel, only in sorted(diff_targets(target, base).items(), key=lambda kv: kv[0]):
                full = os.path.join(target, rel)
                if not os.path.isfile(full):
                    continue
                base_name = os.path.basename(rel)
                if (os.path.splitext(base_name)[1].lower() in BINARY_EXT or match_globs(rel, DEFAULT_EXCLUDED_FILES)
                        or any(part in DEFAULT_EXCLUDED_DIRS for part in rel.split("/")[:-1])
                        or any(fnmatch.fnmatch(rel, g) for g in all_excludes)
                        or os.path.realpath(full).startswith(SELF_DIR + os.sep)):
                    continue
                content = read_text(full)
                if content is None:
                    continue
                scanned += 1
                findings += scan_text(rel, content, only)
        else:
            for full, rel in walk(target, all_excludes):
                content = read_text(full)
                if content is None:
                    continue
                scanned += 1
                findings += scan_text(rel, content)
    return findings, scanned


def print_rules() -> None:
    for r in RULES:
        print(f"{r.id:<12} {r.severity:<9} {r.ref:<14} {r.title}")
    print(f"\n{len(RULES)} regole.")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Scanner di pattern insicuri Security by Design.", add_help=True)
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--diff", metavar="BASE", help="analizza solo le modifiche rispetto a BASE (ref git)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    ap.add_argument("--list-rules", action="store_true")
    args = ap.parse_args(argv)

    if args.list_rules:
        print_rules()
        return 0
    try:
        findings, scanned = run(args.paths, args.diff, args.exclude)
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        print(f"sbd_patterns: errore: {exc}", file=sys.stderr)
        return 2

    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    threshold = SEV_RANK[args.fail_on]
    failing = [f for f in active if SEV_RANK[f.severity] >= threshold]
    counts = {s: sum(1 for f in active if f.severity == s) for s in reversed(SEVERITIES)}
    verdict = "FAIL" if failing else "PASS"

    if args.json:
        print(json.dumps({
            "verdict": verdict, "fail_on": args.fail_on, "files_scanned": scanned, "counts": counts,
            "findings": [f.as_dict() for f in active], "suppressed": [f.as_dict() for f in suppressed],
        }, ensure_ascii=False, indent=2))
    else:
        order = sorted(active, key=lambda f: (-SEV_RANK[f.severity], f.path, f.line))
        for f in order:
            print(f"[{f.severity.upper()}] {f.rule} {f.path}:{f.line} — {f.title} ({f.ref})")
            print(f"    > {f.snippet}")
            print(f"    Fix: {f.fix}")
            if f.note:
                print(f"    Nota: {f.note}")
        if suppressed:
            print("\nSoppressi (verifica che le motivazioni siano valide):")
            for f in suppressed:
                print(f"  {f.rule} {f.path}:{f.line} — {f.suppression_reason}")
        summary = ", ".join(f"{n} {s}" for s, n in counts.items())
        print(f"\nsbd_patterns: {scanned} file analizzati, {len(active)} finding ({summary}), "
              f"{len(suppressed)} soppressi. Esito: {verdict} (soglia: {args.fail_on})")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
