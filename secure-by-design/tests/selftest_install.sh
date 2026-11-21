#!/usr/bin/env bash
# Self-test di install-into-project.sh.
set -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="$HERE/../scripts/install-into-project.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sbd-install-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
fail() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

printf '# Progetto demo\n' >"$WORK/CLAUDE.md"
bash "$INSTALL" "$WORK" >/dev/null || fail "prima installazione fallita"
for s in sbd-core sbd-threat-modeling sbd-secure-coding sbd-supply-chain sbd-infrastructure sbd-data-protection \
         sbd-ai-security sbd-security-gate; do
  [ -f "$WORK/.claude/skills/$s/SKILL.md" ] || fail "skill $s non installata"
done
[ -x "$WORK/.claude/skills/sbd-security-gate/scripts/run_gate.sh" ] || fail "run_gate.sh non eseguibile"
grep -q '^# Progetto demo' "$WORK/CLAUDE.md" || fail "contenuto originale di CLAUDE.md perso"
[ "$(grep -c '<!-- sbd:start -->' "$WORK/CLAUDE.md")" -eq 1 ] || fail "blocco SBD assente o duplicato"

if bash "$INSTALL" "$WORK" >/dev/null 2>&1; then fail "la reinstallazione senza --force deve fallire"; fi
bash "$INSTALL" --force "$WORK" >/dev/null || fail "reinstallazione con --force fallita"
[ "$(grep -c '<!-- sbd:start -->' "$WORK/CLAUDE.md")" -eq 1 ] || fail "blocco SBD duplicato dopo --force"

python3 "$WORK/.claude/skills/sbd-security-gate/scripts/sbd_patterns.py" "$WORK" >/dev/null \
  || fail "lo scanner segnala finding sulle skill installate nel progetto"

if [ "$FAILS" -gt 0 ]; then echo "selftest_install: $FAILS errori"; exit 1; fi
echo "selftest_install: OK"
