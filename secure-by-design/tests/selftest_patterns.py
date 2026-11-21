#!/usr/bin/env python3
"""Self-test di sbd_patterns.py.

Verifica che:
  1. ogni riga marcata `sbd-expect-next: <ID>` nelle fixture `bad/` produca esattamente i finding attesi;
  2. le fixture `good/` non producano finding attivi (falsi positivi);
  3. segreti e PAN, generati a runtime, siano rilevati e non compaiano mai in chiaro nell'output;
  4. la modalita --diff analizzi solo righe aggiunte e file non tracciati;
  5. le soppressioni richiedano una motivazione;
  6. exit code e soglie funzionino;
  7. ogni regola sia coperta da almeno una fixture e citi una regola SBD definita nelle skill.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.dirname(HERE)
SCRIPT = os.path.join(PLUGIN, "skills", "sbd-security-gate", "scripts", "sbd_patterns.py")
FIXTURES = os.path.join(HERE, "fixtures")
EXPECT_RX = re.compile(r"sbd-expect-next:\s*([A-Z0-9,\s-]+?)\s*(?:-->|\*/)?\s*$")

spec = importlib.util.spec_from_file_location("sbd_patterns", SCRIPT)
sbd = importlib.util.module_from_spec(spec)
sys.modules["sbd_patterns"] = sbd
spec.loader.exec_module(sbd)

failures: list = []
covered: set = set()


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  FAIL {msg}")


def expectations(content: str) -> set:
    exp = set()
    for i, line in enumerate(content.splitlines(), 1):
        m = EXPECT_RX.search(line)
        if m:
            for rid in m.group(1).split(","):
                if rid.strip():
                    exp.add((i + 1, rid.strip()))
    return exp


def check_tree(base: str, label: str) -> None:
    for dirpath, _, filenames in os.walk(base):
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, os.path.dirname(base)).replace(os.sep, "/")
            content = open(full, encoding="utf-8").read()
            exp = expectations(content)
            act = {(f.line, f.rule) for f in sbd.scan_text(rel, content) if not f.suppressed}
            covered.update(r for _, r in act)
            for item in sorted(exp - act):
                fail(f"{label}: {rel}:{item[0]} atteso {item[1]} non trovato")
            for item in sorted(act - exp):
                fail(f"{label}: {rel}:{item[0]} finding inatteso {item[1]}")


def run_cli(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, cwd=cwd, check=False)


# ---- segreti generati a runtime (nessuna stringa con forma di credenziale nel repository) ------------------------

def luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        if sbd.luhn_ok(prefix + d):
            return prefix + d
    raise AssertionError


def generated_secrets() -> tuple:
    alnum = "Q7x2Kp9LmZ4vR8nT3wYb6cHd5fJg1sAe"
    values = {
        "P-SECRET-01": "-----BEGIN " + "RSA PRIVATE KEY" + "-----",
        "P-SECRET-02": "AK" + "IA" + "Q3MZ7XKD" + "2VBN8HJT",
        "P-SECRET-03": "gh" + "p_" + (alnum + "abcd")[:36],
        "P-SECRET-04": "xo" + "xb-" + "2048193746-" + alnum[:16],
        "P-SECRET-05": "AI" + "za" + (alnum + "Zy9")[:35],
        "P-SECRET-06": "sk" + "_live_" + alnum[:24],
        "P-SECRET-07": "sk" + "-ant-" + alnum[:30],
        "P-SECRET-08": "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + alnum[:22],
        "P-SECRET-09": "Zq8!pLm3" + "wRt7",
        "P-SECRET-11": "Zq8pLm3" + "wRt7",
        "P-PAN-01": luhn_complete("45391488" + "0343646"),
    }
    py = [
        "# Fixture generata dal self-test: valori fittizi",
        "# sbd-expect-next: P-SECRET-01", f'KEY = """{values["P-SECRET-01"]}"""',
        "# sbd-expect-next: P-SECRET-02", f'AWS_ID = "{values["P-SECRET-02"]}"',
        "# sbd-expect-next: P-SECRET-03", f'GH = "{values["P-SECRET-03"]}"',
        "# sbd-expect-next: P-SECRET-04", f'SLACK = "{values["P-SECRET-04"]}"',
        "# sbd-expect-next: P-SECRET-05", f'GKEY = "{values["P-SECRET-05"]}"',
        "# sbd-expect-next: P-SECRET-06", f'STRIPE = "{values["P-SECRET-06"]}"',
        "# sbd-expect-next: P-SECRET-07", f'LLM = "{values["P-SECRET-07"]}"',
        "# sbd-expect-next: P-SECRET-08", f'JWT = "{values["P-SECRET-08"]}"',
        "# sbd-expect-next: P-SECRET-09", f'db_password = "{values["P-SECRET-09"]}"',
        "# sbd-expect-next: P-SECRET-11", f'DSN = "postgres://app:{values["P-SECRET-11"]}@db.internal:5432/app"',
        "# sbd-expect-next: P-PAN-01", f'card = "{values["P-PAN-01"]}"',
        "# Valori che NON devono essere segnalati",
        'LOCAL_DSN = "postgres://app:localpass@localhost:5432/app"',
        'TEST_CARD = "4242424242424242"',
        'AWS_DOC_EXAMPLE = "AKIA' + 'IOSFODNN7EXAMPLE"',
    ]
    env_secret = "Zq8pLm3" + "wRt7Yx"
    env = ["# sbd-expect-next: P-SECRET-10", f"DB_PASSWORD={env_secret}", "DB_PASSWORD_PLACEHOLDER=<REPLACE_ME>",
           "API_TOKEN=${API_TOKEN}"]
    values["P-SECRET-10"] = env_secret
    return "\n".join(py) + "\n", "\n".join(env) + "\n", values


def test_generated_secrets(tmp: str) -> None:
    print("[secrets] segreti e PAN generati")
    py, env, values = generated_secrets()
    gen = os.path.join(tmp, "generated")
    os.makedirs(gen)
    with open(os.path.join(gen, "secrets.py"), "w", encoding="utf-8") as fh:
        fh.write(py)
    with open(os.path.join(gen, ".env"), "w", encoding="utf-8") as fh:
        fh.write(env)
    check_tree(gen, "generated")
    for args in ([gen], [gen, "--json"]):
        res = run_cli(*args)
        if res.returncode != 1:
            fail(f"segreti: exit code atteso 1, ottenuto {res.returncode}")
        for rule, value in values.items():
            if value in res.stdout or value in res.stderr:
                fail(f"segreti: il valore di {rule} compare in chiaro nell'output ({' '.join(args[1:]) or 'testo'})")


def test_diff_mode(tmp: str) -> None:
    print("[diff] modalita --diff")
    if not shutil.which("git"):
        fail("diff: git non disponibile")
        return
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)

    def g(*a: str) -> None:
        subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "selftest@example.invalid")
    g("config", "user.name", "selftest")
    g("config", "commit.gpgsign", "false")
    with open(os.path.join(repo, "app.py"), "w") as fh:
        fh.write("import os\nos.system('ls')\n")  # finding preesistente: fuori dal diff
    g("add", "app.py")
    g("commit", "-q", "-m", "base")
    with open(os.path.join(repo, "app.py"), "a") as fh:
        fh.write("resp = requests.get(url, verify=False)\n")
    with open(os.path.join(repo, "new.py"), "w") as fh:
        fh.write("x = eval(data)\n")
    res = run_cli("--diff", "HEAD", "--json", repo)
    if res.returncode != 1:
        fail(f"diff: exit code atteso 1, ottenuto {res.returncode}: {res.stderr.strip()}")
        return
    got = {(f["path"], f["line"], f["rule"]) for f in json.loads(res.stdout)["findings"]}
    want = {("app.py", 3, "P-TLS-01"), ("new.py", 1, "P-EXEC-01")}
    if got != want:
        fail(f"diff: attesi {sorted(want)}, ottenuti {sorted(got)}")
    res = run_cli("--diff", "riferimento-inesistente", repo)
    if res.returncode != 2:
        fail(f"diff: con BASE inesistente atteso exit 2, ottenuto {res.returncode}")


def test_suppressions() -> None:
    print("[suppress] soppressioni")
    content = ("import hashlib\n"
               "# sbd-ignore: P-CRYPTO-01 hash usato solo per deduplicare file pubblici\n"
               "a = hashlib.md5(x)\n"
               "b = hashlib.md5(y)  # sbd-ignore: P-CRYPTO-01\n"
               "c = hashlib.md5(z)  # sbd-ignore: P-TLS-01 regola diversa, non deve sopprimere\n")
    res = {f.line: f for f in sbd.scan_text("s.py", content)}
    if not (3 in res and res[3].suppressed):
        fail("suppress: la soppressione motivata sulla riga precedente non e stata applicata")
    if not (4 in res and not res[4].suppressed and res[4].note):
        fail("suppress: una soppressione senza motivazione non deve essere applicata")
    if not (5 in res and not res[5].suppressed):
        fail("suppress: una soppressione per un'altra regola non deve essere applicata")


def test_cli() -> None:
    print("[cli] exit code e soglie")
    bad, good = os.path.join(FIXTURES, "bad"), os.path.join(FIXTURES, "good")
    checks = [
        (run_cli(bad), 1, "bad con soglia di default"),
        (run_cli(good), 0, "good con soglia di default"),
        (run_cli(good, "--fail-on", "low"), 0, "good con soglia low"),
        (run_cli(os.path.join(bad, "app.js"), "--fail-on", "critical"), 1, "app.js contiene un critical"),
        (run_cli(os.path.join(bad, "compose.yaml"), "--fail-on", "critical"), 0, "compose.yaml non contiene critical"),
        (run_cli("--list-rules"), 0, "--list-rules"),
        (run_cli("/percorso/inesistente"), 2, "percorso inesistente"),
    ]
    for res, want, label in checks:
        if res.returncode != want:
            fail(f"cli: {label}: exit atteso {want}, ottenuto {res.returncode}")
    data = json.loads(run_cli(bad, "--json").stdout)
    if data["verdict"] != "FAIL" or not data["findings"]:
        fail("cli: output JSON inatteso")


def test_ignore_file(tmp: str) -> None:
    print("[ignore] .sbdignore ed esclusioni")
    proj = os.path.join(tmp, "ignore")
    os.makedirs(os.path.join(proj, "legacy"))
    os.makedirs(os.path.join(proj, "node_modules", "pkg"))
    for rel in ("legacy/old.py", "node_modules/pkg/index.py", "src.py"):
        os.makedirs(os.path.dirname(os.path.join(proj, rel)), exist_ok=True)
        with open(os.path.join(proj, rel), "w") as fh:
            fh.write("x = eval(data)\n")
    with open(os.path.join(proj, ".sbdignore"), "w") as fh:
        fh.write("# codice legacy fuori ambito, ticket SEC-123\nlegacy/*\n")
    data = json.loads(run_cli(proj, "--json").stdout)
    paths = {f["path"] for f in data["findings"]}
    if paths != {"src.py"}:
        fail(f"ignore: attesi finding solo su src.py, ottenuti {sorted(paths)}")


def defined_sbd_rules() -> set:
    rx = re.compile(r"\*\*(SBD-[A-Z]+-\d{2}) —")
    found = set()
    for dirpath, _, filenames in os.walk(os.path.join(PLUGIN, "skills")):
        for fn in filenames:
            if fn.endswith(".md"):
                found.update(rx.findall(open(os.path.join(dirpath, fn), encoding="utf-8").read()))
    return found


def test_catalog() -> None:
    print("[catalog] coerenza del catalogo")
    ids = [r.id for r in sbd.RULES]
    if len(ids) != len(set(ids)):
        fail("catalog: ID di regola duplicati")
    defined = defined_sbd_rules()
    for r in sbd.RULES:
        if r.severity not in sbd.SEVERITIES:
            fail(f"catalog: {r.id} severita non valida")
        if r.ref not in defined:
            fail(f"catalog: {r.id} cita {r.ref}, non definita nelle skill")
        if (r.pattern is None) == (r.file_check is None):
            fail(f"catalog: {r.id} deve avere esattamente uno tra pattern e file_check")
    for rid in sorted(set(ids) - covered):
        fail(f"catalog: la regola {rid} non e coperta da alcuna fixture")


def main() -> int:
    print("[fixtures] bad/ e good/")
    check_tree(os.path.join(FIXTURES, "bad"), "bad")
    check_tree(os.path.join(FIXTURES, "good"), "good")
    tmp = tempfile.mkdtemp(prefix="sbd-selftest-")
    try:
        test_generated_secrets(tmp)
        test_diff_mode(tmp)
        test_ignore_file(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    test_suppressions()
    test_cli()
    test_catalog()
    if failures:
        print(f"\nselftest_patterns: {len(failures)} errori")
        return 1
    print(f"\nselftest_patterns: OK ({len(sbd.RULES)} regole, tutte coperte)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
