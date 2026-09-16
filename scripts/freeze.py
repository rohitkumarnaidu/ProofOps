"""ProofOps dependency-lock enforcer (M00.7 CI foundation, stdlib only).

Two commands (see ADR-010 for why the lock exists):

  python scripts/freeze.py --check
    Strict, host-safe, no network: proves backend/requirements.lock covers
    every name in backend/requirements.txt with an exact `==` pin whose
    version satisfies the declared range. Missing lock, uncovered name,
    unpinned line, duplicate, or out-of-range pin all FAIL with an actionable,
    value-free message (only package NAMES are printed — versions never leak
    anything, but names suffice to act).

  python scripts/freeze.py --generate
    Regenerates the lock from the CURRENT interpreter via `pip freeze`.
    REFUSES unless running on CPython 3.12 (the container source of truth):
    freezing the drifted 3.13/3.14 host would bake wrong wheels into the lock.
    Canonical regeneration (needs a daemon):
      docker run --rm -v .:/work -w /work python:3.12-slim \
        sh -c "pip install -r backend/requirements.txt && python scripts/freeze.py --generate"
    then drop win32-only edges (pip evaluates markers for the RUNNING
    interpreter: on 3.12-slim there are none to drop) and open a human-review
    PR — a lock diff is a dependency-change review, never a drive-by.

Scope notes (deliberate, tested):
- Name normalization is PEP 503 (`re.sub(r"[-_.]+", "-", name).lower()`).
- Range checking covers the shapes this repo uses (`>=X`, `<Y`, comma-joined,
  extras like `pkg[extra]`, `;` markers stripped). Anything exotic (wheels
  URLs, `~=`, `===`, pre-releases) FAILS LOUD asking for human review instead
  of being silently approved.
- Transitive traceability (is every lock line reachable?) is NOT checked here:
  it needs resolver metadata. The generator's resolve report is the evidence;
  the checker pins coverage + range-satisfaction + shape.

Usage: python scripts/freeze.py (--check | --generate) [--requirements F] [--lock F]
Exit 0 = ok, 1 = findings, 2 = wrong-interpreter refusal (--generate only).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUIREMENTS = ROOT / "backend" / "requirements.txt"
DEFAULT_LOCK = ROOT / "backend" / "requirements.lock"

LOCKED_PYTHON = (3, 12)

PIN_RE = re.compile(r"([A-Za-z0-9_.\-]+)==([^=\s;]+)")
RANGE_SPLIT_RE = re.compile(r"\s*,\s*")
NUMERIC_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _strip_inline_comment(line: str) -> str:
    # pip semantics: a `#` preceded by whitespace (or at line start) opens a
    # comment (e.g. the starlette upper-bound rationale). A bare `#` inside a
    # URL fragment is exotic for this repo and fails loud downstream instead.
    return re.sub(r"\s+#.*$", "", line).strip()


def base_name(req_line: str) -> str:
    """`uvicorn[standard]>=0.30,<0.32` -> `uvicorn`; markers stripped."""
    line = _strip_inline_comment(req_line.split(";", 1)[0].strip())
    m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)", line)
    if not m:
        raise ValueError(f"unparseable requirement line: {req_line!r}")
    return m.group(1)


def spec_of(req_line: str) -> str:
    line = _strip_inline_comment(req_line.split(";", 1)[0].strip())
    m = re.match(r"[A-Za-z0-9_.\-]+(?:\[[^\]]*\])?\s*(.*)", line)
    return (m.group(1) if m else "").strip()


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Non-comment lines -> (normalized-name, range-spec) preserving order."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append((normalize(base_name(line)), spec_of(line)))
    return out


def parse_lock(text: str) -> dict[str, str]:
    """Lock text -> {normalized-name: version}. Duplicates raise."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = PIN_RE.fullmatch(line)
        if not m:
            raise ValueError(f"lock line is not an exact pin: {raw!r}")
        key = normalize(m.group(1))
        if key in out:
            raise ValueError(f"duplicate lock entry: {key}")
        out[key] = m.group(2)
    return out


def _numeric_parts(version: str) -> list[int]:
    if not NUMERIC_VERSION_RE.match(version):
        raise ValueError(f"non-numeric version needs human review: {version!r}")
    return [int(p) for p in version.split(".")]


def version_satisfies(version: str, spec: str) -> bool:
    """Check `>=X` / `<Y` (comma-joined) with zero-dependency int compare."""
    if not spec:
        return True
    v = _numeric_parts(version)
    for clause in RANGE_SPLIT_RE.split(spec):
        clause = clause.strip()
        if clause.startswith(">="):
            floor = _numeric_parts(clause[2:].strip())
            if (v + [0] * len(floor))[:len(floor)] < floor:
                return False
        elif clause.startswith("<") and not clause.startswith("<="):
            ceil = _numeric_parts(clause[1:].strip())
            if (v + [0] * len(ceil))[:len(ceil)] >= ceil:
                return False
        else:
            raise ValueError(f"unsupported range clause needs human review: {clause!r}")
    return True


def check_lock(req_text: str, lock_text: str) -> list[str]:
    """Pure check: returns finding strings (package names only), [] when ok."""
    findings: list[str] = []
    try:
        locked = parse_lock(lock_text)
    except ValueError as exc:
        return [f"lock malformed: {exc}"]
    for name, spec in parse_requirements(req_text):
        if name not in locked:
            findings.append(f"{name}: in requirements but not locked")
            continue
        try:
            if not version_satisfies(locked[name], spec):
                findings.append(f"{name}: locked version outside declared range")
        except ValueError as exc:
            findings.append(f"{name}: {exc}")
    return findings


def cmd_check(requirements: Path, lock: Path) -> int:
    if not requirements.is_file():
        print(f"LOCK CHECK FAIL: missing {requirements} (redacted)")
        return 1
    if not lock.is_file():
        print(f"LOCK CHECK FAIL: missing {lock} — resolve on python:3.12-slim "
              f"and commit it (see scripts/freeze.py docstring, ADR-010)")
        return 1
    findings = check_lock(requirements.read_text(encoding="utf-8"),
                          lock.read_text(encoding="utf-8"))
    if findings:
        print(f"LOCK CHECK FAIL: {len(findings)} finding(s)")
        for entry in findings:
            print(f"  - {entry}")
        return 1
    print(f"LOCK CHECK PASS: {lock.name} covers {requirements.name} "
          f"({len(parse_requirements(requirements.read_text(encoding='utf-8')))} "
          f"requirements, exact pins, ranges satisfied)")
    return 0


def cmd_generate(lock: Path) -> int:
    if sys.version_info[:2] != LOCKED_PYTHON or \
            sys.implementation.name != "cpython":
        print(f"FREEZE REFUSED (exit 2): lock must be generated on CPython "
              f"{LOCKED_PYTHON[0]}.{LOCKED_PYTHON[1]} "
              f"(container source of truth), not "
              f"{sys.implementation.name} "
              f"{sys.version_info[0]}.{sys.version_info[1]} — "
              f"freezing here would bake wrong wheels (see ADR-010)")
        return 2
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print("FREEZE FAIL: pip freeze errored (redacted)")
        return 1
    pins = sorted(
        (ln.strip() for ln in proc.stdout.splitlines() if "==" in ln),
        key=str.lower,
    )
    header = (
        "# ProofOps locked dependencies — Linux / CPython 3.12 (container + CI).\n"
        "#\n"
        "# GENERATED, do not edit by hand. Regenerate ONLY on the source of\n"
        "# truth (see scripts/freeze.py docstring). Human-review every diff:\n"
        "# a lock change is a dependency change.\n"
    )
    lock.write_text(header + "".join(p + "\n" for p in pins), encoding="utf-8")
    print(f"FREEZE WROTE: {lock} ({len(pins)} pins) — review the diff, then "
          f"run --check and the full suite before committing")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofOps lock enforcer")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--requirements", default=str(DEFAULT_REQUIREMENTS))
    parser.add_argument("--lock", default=str(DEFAULT_LOCK))
    args = parser.parse_args()
    if args.generate and not args.check:
        return cmd_generate(Path(args.lock))
    if args.check and not args.generate:
        return cmd_check(Path(args.requirements), Path(args.lock))
    parser.print_usage()
    return 2


if __name__ == "__main__":
    sys.exit(main())
