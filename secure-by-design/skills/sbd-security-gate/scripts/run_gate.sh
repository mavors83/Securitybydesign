#!/usr/bin/env bash
# run_gate.sh - Security gate SBD.
#
# Esegue lo scanner di pattern SBD e gli scanner esterni disponibili, per categoria, e produce un esito:
#   PASS        tutte le categorie richieste eseguite, nessun finding bloccante     (exit 0)
#   FAIL        almeno una categoria con finding o con errore dello strumento       (exit 1)
#   INCOMPLETE  nessun FAIL, ma almeno una categoria richiesta non eseguita        (exit 2)
#   errore d'uso                                                                   (exit 64)
#
# Uso: run_gate.sh [--diff BASE] [--out DIR] [PATH]
#   --diff BASE  limita lo scanner di pattern (e semgrep) alle modifiche rispetto al ref git BASE
#   --out DIR    directory per log e summary.md (default: directory temporanea)
#   PATH         progetto da analizzare (default: directory corrente)
#
# Variabili d'ambiente:
#   SBD_SEMGREP_CONFIG       regole semgrep/opengrep (default: p/default; usa il ruleset aziendale se esiste)
#   SBD_GATE_DISABLE_TOOLS   strumenti da considerare assenti, separati da virgola (per i test: una
#                            categoria disabilitata risulta NOT_RUN, mai PASS)

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="."
BASE=""
OUT_DIR=""

usage() { sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --diff)
      [ $# -ge 2 ] || { echo "run_gate: manca il valore di --diff" >&2; exit 64; }
      BASE="$2"; shift 2 ;;
    --out)
      [ $# -ge 2 ] || { echo "run_gate: manca il valore di --out" >&2; exit 64; }
      OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "run_gate: opzione sconosciuta: $1" >&2; usage >&2; exit 64 ;;
    *) TARGET="$1"; shift ;;
  esac
done

[ -d "$TARGET" ] || { echo "run_gate: directory inesistente: $TARGET" >&2; exit 64; }
if [ -z "$OUT_DIR" ]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbd-gate.XXXXXX")" || exit 64
else
  mkdir -p "$OUT_DIR" || exit 64
fi
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
cd "$TARGET" || exit 64
PROJECT="$(pwd)"

# --- risultati (array paralleli, compatibili con bash 3.2) ------------------------------------------------------
R_CAT=(); R_STATUS=(); R_TOOL=(); R_DETAIL=()
record() { R_CAT+=("$1"); R_STATUS+=("$2"); R_TOOL+=("$3"); R_DETAIL+=("$4"); }

has_tool() {
  case ",${SBD_GATE_DISABLE_TOOLS:-}," in *",$1,"*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}

run_check() {  # run_check <categoria> <strumento> <comando...>
  local category="$1" tool="$2" log rc
  shift 2
  log="$OUT_DIR/${category}.log"
  printf '  %-11s %-13s ' "$category" "$tool"
  if "$@" >"$log" 2>&1; then
    echo "PASS"
    record "$category" PASS "$tool" "log: $log"
  else
    rc=$?
    echo "FAIL (exit $rc)"
    record "$category" FAIL "$tool" "exit $rc, log: $log"
  fi
}

not_run() {  # not_run <categoria> <motivo>  (categoria richiesta senza strumento)
  printf '  %-11s %-13s NOT_RUN (%s)\n' "$1" "-" "$2"
  record "$1" NOT_RUN "-" "$2"
}

skipped() {  # skipped <categoria> <motivo>  (non applicabile o consigliata)
  printf '  %-11s %-13s SKIPPED (%s)\n' "$1" "-" "$2"
  record "$1" SKIPPED "-" "$2"
}

# --- rilevamento del contenuto del progetto ---------------------------------------------------------------------
find_files() {  # find_files <espressione find per i nomi>; stampa i percorsi
  find . \( -path ./.git -o -name node_modules -o -name vendor -o -name .venv -o -name venv -o -name dist \
         -o -name build -o -name target -o -name .terraform \) -prune -o \( "$@" \) -type f -print 2>/dev/null
}
has_files() { [ -n "$(find_files "$@" | head -n 1)" ]; }

CODE_EXPR=(-name '*.py' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.jsx' -o -name '*.ts' \
  -o -name '*.tsx' -o -name '*.java' -o -name '*.kt' -o -name '*.scala' -o -name '*.go' -o -name '*.cs' \
  -o -name '*.php' -o -name '*.rb' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.rs' -o -name '*.swift')
MANIFEST_EXPR=(-name package.json -o -name 'requirements*.txt' -o -name pyproject.toml -o -name Pipfile \
  -o -name go.mod -o -name pom.xml -o -name build.gradle -o -name build.gradle.kts -o -name '*.csproj' \
  -o -name Cargo.toml -o -name Gemfile -o -name composer.json)
DOCKER_EXPR=(-name Dockerfile -o -name '*.Dockerfile' -o -name 'Dockerfile.*' -o -name Containerfile)
IAC_EXPR=(-name '*.tf' -o -name '*.bicep' -o -name Chart.yaml -o -name kustomization.yaml "${DOCKER_EXPR[@]}")

has_k8s_manifests() {
  grep -rlqsE --include='*.yaml' --include='*.yml' --exclude-dir=.git --exclude-dir=node_modules \
    '^kind:[[:space:]]*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|Role|ClusterRole|RoleBinding|ClusterRoleBinding|NetworkPolicy|Ingress)([[:space:]]|$)' .
}

echo "Security gate SBD — progetto: $PROJECT${BASE:+ (diff rispetto a $BASE)}"
echo "Log in: $OUT_DIR"
echo

# 1. Pattern SBD (sempre richiesto)
if has_tool python3; then
  if [ -n "$BASE" ]; then
    run_check patterns sbd_patterns python3 "$SCRIPT_DIR/sbd_patterns.py" --diff "$BASE" .
  else
    run_check patterns sbd_patterns python3 "$SCRIPT_DIR/sbd_patterns.py" .
  fi
else
  not_run patterns "python3 non disponibile"
fi

# 2. Segreti (sempre richiesto)
if has_tool gitleaks; then
  if [ -z "$BASE" ] && git rev-parse --git-dir >/dev/null 2>&1; then
    if gitleaks git --help >/dev/null 2>&1; then
      run_check secrets gitleaks gitleaks git --redact --no-banner .
    else
      run_check secrets gitleaks gitleaks detect --redact --no-banner --source .
    fi
  elif gitleaks dir --help >/dev/null 2>&1; then
    run_check secrets gitleaks gitleaks dir --redact --no-banner .
  else
    run_check secrets gitleaks gitleaks detect --redact --no-banner --no-git --source .
  fi
elif has_tool trufflehog; then
  run_check secrets trufflehog trufflehog filesystem . --fail --no-update
else
  not_run secrets "installa gitleaks o trufflehog"
fi

# File modificati rispetto a BASE (assoluti, solo esistenti). In modalità diff passiamo i file a semgrep invece
# di --baseline-commit, che aborta se ci sono modifiche non committate (il gate gira anche prima del commit).
sast_changed_files() {
  local top rel f
  top="$(git rev-parse --show-toplevel 2>/dev/null)" || return 0
  { git diff --name-only --diff-filter=ACMR "$BASE" 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null; } \
    | while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        f="$top/$rel"
        [ -f "$f" ] && printf '%s\n' "$f"
      done
}

# 3. SAST (richiesto se c'è codice)
if has_files "${CODE_EXPR[@]}"; then
  SEMGREP_CONFIG="${SBD_SEMGREP_CONFIG:-p/default}"
  SAST_TOOL=""
  has_tool semgrep && SAST_TOOL=semgrep
  [ -z "$SAST_TOOL" ] && has_tool opengrep && SAST_TOOL=opengrep
  if [ -z "$SAST_TOOL" ]; then
    not_run sast "installa semgrep o opengrep"
  elif [ -n "$BASE" ]; then
    SAST_FILES=()
    while IFS= read -r f; do SAST_FILES+=("$f"); done < <(sast_changed_files)
    if [ "${#SAST_FILES[@]}" -eq 0 ]; then
      skipped sast "nessun file modificato rispetto a $BASE"
    elif [ "$SAST_TOOL" = semgrep ]; then
      run_check sast semgrep semgrep scan --config "$SEMGREP_CONFIG" --error --metrics=off --quiet "${SAST_FILES[@]}"
    else
      run_check sast opengrep opengrep scan --config "$SEMGREP_CONFIG" --error --quiet "${SAST_FILES[@]}"
    fi
  elif [ "$SAST_TOOL" = semgrep ]; then
    run_check sast semgrep semgrep scan --config "$SEMGREP_CONFIG" --error --metrics=off --quiet .
  else
    run_check sast opengrep opengrep scan --config "$SEMGREP_CONFIG" --error --quiet .
  fi
else
  skipped sast "nessun file di codice"
fi

# 4. SCA (richiesto se ci sono manifest di dipendenze)
if has_files "${MANIFEST_EXPR[@]}"; then
  if has_tool trivy; then
    run_check sca trivy trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --quiet .
  elif has_tool osv-scanner; then
    # osv-scanner -r . funziona su v1 e v2 (in v2 il default command risolve "scan source"); diversamente da
    # trivy, osv-scanner blocca su qualsiasi finding, anche Low o senza fix: fallback più severo (vedi SKILL.md).
    run_check sca osv-scanner osv-scanner -r .
  else
    not_run sca "installa trivy o osv-scanner"
  fi
else
  skipped sca "nessun manifest di dipendenze"
fi

# 5. IaC e container (richiesto se ci sono IaC, Dockerfile o manifest Kubernetes)
if has_files "${IAC_EXPR[@]}" || has_k8s_manifests; then
  if has_tool trivy; then
    run_check iac trivy trivy config --severity HIGH,CRITICAL --exit-code 1 --quiet .
  elif has_tool checkov; then
    # checkov blocca su qualsiasi finding (anche Low), diversamente da trivy config (HIGH,CRITICAL): più severo.
    run_check iac checkov checkov -d . --quiet --compact
  else
    not_run iac "installa trivy o checkov"
  fi
else
  skipped iac "nessun file IaC, Dockerfile o manifest"
fi

# 6. Workflow CI (richiesto se ci sono workflow GitHub Actions)
if [ -d .github/workflows ]; then
  if has_tool zizmor; then
    run_check workflows zizmor zizmor --offline --min-severity medium .github/workflows
  else
    not_run workflows "installa zizmor"
  fi
else
  skipped workflows "nessun workflow GitHub Actions"
fi

# 7. Controlli consigliati (non bloccano se lo strumento manca)
DOCKERFILES=()
while IFS= read -r f; do DOCKERFILES+=("$f"); done < <(find_files "${DOCKER_EXPR[@]}")
if [ "${#DOCKERFILES[@]}" -gt 0 ]; then
  if has_tool hadolint; then
    run_check dockerfile hadolint hadolint --failure-threshold warning "${DOCKERFILES[@]}"
  else
    skipped dockerfile "consigliato: hadolint"
  fi
fi

SHELLS=()
while IFS= read -r f; do SHELLS+=("$f"); done < <(find_files -name '*.sh' -o -name '*.bash')
if [ "${#SHELLS[@]}" -gt 0 ]; then
  if has_tool shellcheck; then
    run_check shell shellcheck shellcheck -S warning "${SHELLS[@]}"
  else
    skipped shell "consigliato: shellcheck"
  fi
fi

if [ -d .github/workflows ] && has_tool actionlint; then
  run_check actionlint actionlint actionlint
fi

if has_tool syft; then
  printf '  %-11s %-13s ' sbom syft
  if syft "dir:." -o "cyclonedx-json=$OUT_DIR/sbom.cdx.json" >"$OUT_DIR/sbom.log" 2>&1; then
    echo "OK ($OUT_DIR/sbom.cdx.json)"
    record sbom INFO syft "SBOM: $OUT_DIR/sbom.cdx.json"
  else
    echo "WARN (generazione SBOM fallita)"
    record sbom WARN syft "log: $OUT_DIR/sbom.log"
  fi
fi

# --- esito ------------------------------------------------------------------------------------------------------
VERDICT=PASS
for s in "${R_STATUS[@]}"; do
  if [ "$s" = FAIL ]; then VERDICT=FAIL; fi
  if [ "$s" = NOT_RUN ] && [ "$VERDICT" = PASS ]; then VERDICT=INCOMPLETE; fi
done

SUMMARY="$OUT_DIR/summary.md"
{
  echo "### Security gate SBD"
  echo
  echo "- Progetto: \`$PROJECT\`${BASE:+ — diff rispetto a \`$BASE\`}"
  echo "- Esito: **$VERDICT**"
  echo
  echo "| Categoria | Esito | Strumento | Dettaglio |"
  echo "|---|---|---|---|"
  i=0
  while [ "$i" -lt "${#R_CAT[@]}" ]; do
    echo "| ${R_CAT[$i]} | ${R_STATUS[$i]} | ${R_TOOL[$i]} | ${R_DETAIL[$i]} |"
    i=$((i + 1))
  done
} >"$SUMMARY"

echo
echo "Esito: $VERDICT"
echo "Riepilogo per il PR: $SUMMARY"
case "$VERDICT" in
  PASS) exit 0 ;;
  FAIL) echo "Apri i log delle categorie in FAIL, correggi i finding e riesegui il gate." ; exit 1 ;;
  *) echo "Verifica incompleta: installa gli strumenti mancanti o dichiaralo nel PR come limite della verifica."; exit 2 ;;
esac
