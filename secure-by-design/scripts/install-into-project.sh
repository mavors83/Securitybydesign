#!/usr/bin/env bash
# install-into-project.sh - installa le skill secure-by-design in un progetto come skill di progetto Claude Code.
#
# Uso: install-into-project.sh [--force] <directory-progetto>
#   copia skills/sbd-* in <progetto>/.claude/skills/ e aggiunge a <progetto>/CLAUDE.md il blocco SBD
#   (delimitato da <!-- sbd:start --> e <!-- sbd:end -->) se non è già presente.
#   --force  sostituisce le skill sbd-* già presenti nel progetto (il blocco in CLAUDE.md non viene toccato)
set -eo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE=0
DEST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "opzione sconosciuta: $1" >&2; exit 64 ;;
    *) DEST="$1"; shift ;;
  esac
done
[ -n "$DEST" ] || { echo "uso: install-into-project.sh [--force] <directory-progetto>" >&2; exit 64; }
[ -d "$DEST" ] || { echo "directory inesistente: $DEST" >&2; exit 64; }

TARGET="$DEST/.claude/skills"
mkdir -p "$TARGET"
for src in "$HERE"/skills/sbd-*; do
  name="$(basename "$src")"
  if [ -e "$TARGET/$name" ]; then
    if [ "$FORCE" -ne 1 ]; then
      echo "esiste già $TARGET/$name: usa --force per sostituirla" >&2
      exit 1
    fi
    rm -rf "${TARGET:?}/$name"
  fi
  cp -R "$src" "$TARGET/$name"
  find "$TARGET/$name" -name '__pycache__' -type d -prune -exec rm -rf {} +
  echo "installata $name"
done

CLAUDE_MD="$DEST/CLAUDE.md"
if [ -f "$CLAUDE_MD" ] && grep -q '<!-- sbd:start -->' "$CLAUDE_MD"; then
  echo "CLAUDE.md contiene già il blocco SBD: non modificato"
else
  { [ -f "$CLAUDE_MD" ] && [ -s "$CLAUDE_MD" ] && echo; cat "$HERE/templates/CLAUDE.md.snippet"; } >>"$CLAUDE_MD"
  echo "aggiunto il blocco SBD a $CLAUDE_MD: compila classificazione dei dati e Security Champion"
fi
