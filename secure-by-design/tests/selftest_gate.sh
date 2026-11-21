#!/usr/bin/env bash
# Self-test di run_gate.sh con strumenti finti (stub), così l'esito non dipende da cosa è installato.
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../skills/sbd-security-gate/scripts/run_gate.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sbd-gate-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0

fail() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

# stub: registra la chiamata e termina con il codice in STUB_<NOME>_RC (default 0)
STUBS="$WORK/stubs"
mkdir -p "$STUBS"
for tool in gitleaks trufflehog semgrep opengrep trivy osv-scanner checkov zizmor hadolint shellcheck actionlint syft; do
  var="STUB_$(echo "$tool" | tr 'a-z-' 'A-Z_')_RC"
  cat >"$STUBS/$tool" <<STUB
#!/usr/bin/env bash
echo "$tool \$*" >>"$WORK/calls.log"
exit "\${$var:-0}"
STUB
  chmod +x "$STUBS/$tool"
done
ALL_TOOLS="gitleaks,trufflehog,semgrep,opengrep,trivy,osv-scanner,checkov,zizmor,hadolint,shellcheck,actionlint,syft"

expect_exit() {  # expect_exit <atteso> <etichetta> <comando...>
  local want="$1" label="$2" got
  shift 2
  "$@" >"$WORK/out.log" 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    fail "$label: exit atteso $want, ottenuto $got"
    sed 's/^/      /' "$WORK/out.log"
  fi
}

CLEAN="$WORK/clean"
mkdir -p "$CLEAN"
printf 'import secrets\ntoken = secrets.token_urlsafe(32)\n' >"$CLEAN/app.py"
printf '{ "name": "demo", "version": "1.0.0" }\n' >"$CLEAN/package.json"

BAD="$WORK/bad"
mkdir -p "$BAD"
printf 'import requests\nr = requests.get(u, verify=False)\n' >"$BAD/app.py"

echo "[gate] PASS con tutti gli strumenti richiesti disponibili e senza finding"
PATH="$STUBS:$PATH" expect_exit 0 "pass" "$GATE" --out "$WORK/o1" "$CLEAN"
grep -q 'Esito: \*\*PASS\*\*' "$WORK/o1/summary.md" || fail "summary.md senza esito PASS"
grep -q 'trivy fs --scanners vuln --severity HIGH,CRITICAL' "$WORK/calls.log" || fail "SCA non invocata con le soglie di policy"

echo "[gate] FAIL quando lo scanner di pattern trova un problema"
PATH="$STUBS:$PATH" expect_exit 1 "pattern" "$GATE" --out "$WORK/o2" "$BAD"
grep -q 'P-TLS-01' "$WORK/o2/patterns.log" || fail "il log dei pattern non contiene P-TLS-01"

echo "[gate] FAIL quando uno strumento esterno segnala finding"
STUB_SEMGREP_RC=1 PATH="$STUBS:$PATH" expect_exit 1 "sast" "$GATE" --out "$WORK/o3" "$CLEAN"

echo "[gate] INCOMPLETE quando manca uno strumento richiesto"
SBD_GATE_DISABLE_TOOLS="gitleaks,trufflehog" PATH="$STUBS:$PATH" expect_exit 2 "incomplete" "$GATE" --out "$WORK/o4" "$CLEAN"
grep -q 'NOT_RUN' "$WORK/o4/summary.md" || fail "summary.md senza categoria NOT_RUN"

echo "[gate] FAIL prevale su INCOMPLETE"
SBD_GATE_DISABLE_TOOLS="$ALL_TOOLS" expect_exit 1 "fail-precedence" "$GATE" --out "$WORK/o5" "$BAD"

echo "[gate] modalità diff: semgrep riceve i file modificati, non --baseline-commit"
REPO="$WORK/repo"
mkdir -p "$REPO"
( cd "$REPO" && git init -q && git config user.email a@b.c && git config user.name t && git config commit.gpgsign false \
  && printf 'import secrets\n' > app.py && git add -A && git commit -qm base \
  && printf 'extra = 1\n' >> app.py && printf 'y = 2\n' > new.py )
: > "$WORK/calls.log"
SBD_GATE_DISABLE_TOOLS="trufflehog,trivy,osv-scanner,checkov,zizmor,hadolint,shellcheck,actionlint,syft,opengrep" \
  PATH="$STUBS:$PATH" expect_exit 0 "diff-sast" "$GATE" --diff HEAD --out "$WORK/o6" "$REPO"
if grep -q 'baseline-commit' "$WORK/calls.log"; then fail "diff-sast: semgrep usa ancora --baseline-commit"; fi
grep -q 'semgrep .*app.py' "$WORK/calls.log" || fail "diff-sast: semgrep non ha ricevuto il file modificato app.py"
grep -q 'semgrep .*new.py' "$WORK/calls.log" || fail "diff-sast: semgrep non ha ricevuto il nuovo file new.py"

echo "[gate] errori d'uso"
expect_exit 64 "opzione sconosciuta" "$GATE" --boh
expect_exit 64 "directory inesistente" "$GATE" "$WORK/non-esiste"

if [ "$FAILS" -gt 0 ]; then
  echo "selftest_gate: $FAILS errori"
  exit 1
fi
echo "selftest_gate: OK"
