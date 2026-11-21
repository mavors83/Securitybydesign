#!/usr/bin/env python3
"""Lint del plugin secure-by-design.

Controlla:
  - plugin.json: JSON valido, nome kebab-case, versione semver;
  - ogni skills/<nome>/SKILL.md: frontmatter con name uguale alla directory e description <= 1024 caratteri,
    corpo sotto le 500 righe;
  - ogni riferimento a references/... o scripts/... (anche tra skill diverse) punta a un file esistente;
  - ogni regola SBD (**SBD-XXX-NN —) è definita una sola volta e ogni ID SBD citato nei documenti è definito;
  - la numerazione delle regole di ogni dominio è continua (01, 02, ...).
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict

PLUGIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(PLUGIN, "skills")
errors: list = []


def err(msg: str) -> None:
    errors.append(msg)
    print(f"  ERROR {msg}")


def check_manifest() -> None:
    path = os.path.join(PLUGIN, ".claude-plugin", "plugin.json")
    try:
        m = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        err(f"plugin.json non valido: {exc}")
        return
    if not re.fullmatch(r"[a-z][a-z0-9-]*[a-z0-9]", m.get("name", "")):
        err("plugin.json: name non kebab-case")
    if not re.fullmatch(r"\d+\.\d+\.\d+", m.get("version", "")):
        err("plugin.json: version non semver")
    print(f"  plugin {m.get('name')} {m.get('version')}")


def parse_frontmatter(text: str) -> tuple:
    if not text.startswith("---\n"):
        return None, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return None, text
    fm, body = text[4:end], text[end + 5:]
    data, key = {}, None
    for line in fm.splitlines():
        m = re.match(r"^([a-z][\w-]*):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            data[key] = "" if val in (">", "|", ">-", "|-") else val
        elif key and line.startswith((" ", "\t")):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data, body


REF_RX = re.compile(r"(?<![\w./-])(?:(sbd-[a-z-]+)/)?((?:references|scripts)/[\w.-]+\.(?:md|py|sh))")


def check_refs(md_path: str, skill_dir: str, text: str) -> None:
    for m in REF_RX.finditer(text):
        target = os.path.join(SKILLS, m.group(1), m.group(2)) if m.group(1) else os.path.join(skill_dir, m.group(2))
        if not os.path.isfile(target):
            err(f"{os.path.relpath(md_path, PLUGIN)}: riferimento inesistente {m.group(0)}")


def check_skills() -> dict:
    texts = {}
    for name in sorted(os.listdir(SKILLS)):
        sdir = os.path.join(SKILLS, name)
        if not os.path.isdir(sdir):
            continue
        skill_md = os.path.join(sdir, "SKILL.md")
        if not os.path.isfile(skill_md):
            err(f"{name}: SKILL.md mancante")
            continue
        text = open(skill_md, encoding="utf-8").read()
        fm, body = parse_frontmatter(text)
        if fm is None:
            err(f"{name}: frontmatter YAML mancante o malformato")
            continue
        if fm.get("name") != name:
            err(f"{name}: name nel frontmatter ({fm.get('name')!r}) diverso dalla directory")
        desc = fm.get("description", "")
        if not desc:
            err(f"{name}: description mancante")
        elif len(desc) > 1024:
            err(f"{name}: description di {len(desc)} caratteri (massimo 1024)")
        lines = body.count("\n")
        if lines > 500:
            err(f"{name}: corpo di {lines} righe (massimo 500)")
        print(f"  {name}: description {len(desc)} caratteri, corpo {lines} righe")
        for dirpath, _, filenames in os.walk(sdir):
            for fn in filenames:
                if fn.endswith(".md"):
                    p = os.path.join(dirpath, fn)
                    t = open(p, encoding="utf-8").read()
                    texts[p] = t
                    check_refs(p, sdir, t)
    return texts


def check_rule_ids(texts: dict) -> None:
    def_rx = re.compile(r"\*\*(SBD-([A-Z]+)-(\d{2})) —")
    use_rx = re.compile(r"\bSBD-([A-Z]+)-(\d{2})\b")
    defined: dict = defaultdict(list)
    by_domain: dict = defaultdict(set)
    for path, text in texts.items():
        for m in def_rx.finditer(text):
            defined[m.group(1)].append(os.path.relpath(path, PLUGIN))
            by_domain[m.group(2)].add(int(m.group(3)))
    for rid, where in defined.items():
        if len(where) > 1:
            err(f"regola {rid} definita più volte: {where}")
    for domain, nums in by_domain.items():
        expected = set(range(1, max(nums) + 1))
        if nums != expected:
            err(f"dominio SBD-{domain}: numerazione con buchi {sorted(expected - nums)}")
    for path, text in texts.items():
        for m in use_rx.finditer(text):
            rid = f"SBD-{m.group(1)}-{m.group(2)}"
            if rid not in defined:
                err(f"{os.path.relpath(path, PLUGIN)}: cita {rid}, non definita")
    total = sum(len(v) for v in by_domain.values())
    print(f"  {total} regole SBD in {len(by_domain)} domini: "
          + ", ".join(f"{d}={len(n)}" for d, n in sorted(by_domain.items())))


def main() -> int:
    print("[lint] manifest")
    check_manifest()
    print("[lint] skill")
    texts = check_skills()
    print("[lint] ID delle regole")
    check_rule_ids(texts)
    if errors:
        print(f"\nlint_skills: {len(errors)} errori")
        return 1
    print("\nlint_skills: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
