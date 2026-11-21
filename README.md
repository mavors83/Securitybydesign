# Securitybydesign

Skill Claude del team di ingegneria CISO per sviluppare e verificare software in modalità **Security by Design**.
Il repository contiene due plugin autonomi, ciascuno con il proprio `.claude-plugin/plugin.json`:

| Plugin | Per chi | Contenuto |
|---|---|---|
| [`secure-by-design/`](secure-by-design/README.md) | Agenti di sviluppo | 8 skill, 116 regole `SBD-*`: principi e regole non negoziabili, threat modeling, secure coding, supply chain, infrastruttura applicativa, protezione dei dati, AI/LLM, security gate eseguibile (scanner di pattern con 84 regole + orchestratore degli scanner esterni) |
| [`pentest/`](pentest/README.md) | Agenti che eseguono security testing autorizzato | 6 skill, 58 regole `PT-*`: gate di autorizzazione e Rules of Engagement, ricognizione, web, API, rete/cloud/container, reporting; guardrail di scope eseguibile `scope_check.py` |

I due plugin si parlano: i finding del pentest si collegano alla regola `SBD-*` che li avrebbe prevenuti, e il
lint del pentest verifica che ogni riferimento incrociato esista davvero in `secure-by-design`.

## Uso rapido

```bash
# installa le skill in un progetto (Claude Code): copia in .claude/skills/ e aggiorna CLAUDE.md
secure-by-design/scripts/install-into-project.sh /percorso/progetto
pentest/scripts/install-into-project.sh /percorso/workspace-pentest

# security gate su un progetto
bash secure-by-design/skills/sbd-security-gate/scripts/run_gate.sh --diff origin/main /percorso/progetto
```

## Sviluppo

```bash
make lint      # lint di entrambi i plugin (frontmatter, riferimenti, ID delle regole, shellcheck)
make test      # self-test di entrambi i plugin
make package   # dist/secure-by-design-v<x>.plugin e dist/pentest-v<x>.plugin
```

Requisiti: Python ≥ 3.10, bash, `zip`; `shellcheck` consigliato. La CI esegue lint e test su ogni PR verso `main`.

## Prima del rollout

Compila i parametri e i contatti in `secure-by-design/skills/sbd-core/references/policy-parameters.md` e adatta
gli snippet in `*/templates/CLAUDE.md.snippet`. I limiti di ciascun plugin sono descritti nel rispettivo README.
