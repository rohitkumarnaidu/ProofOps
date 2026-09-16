"""ProofOps secret scanner (M00.7 CI foundation, stdlib only, no deps).

Scans tracked files for high-confidence live-secret shapes and enforces
workflow/secret hygiene. NEVER prints secret values — findings report
file:line + pattern name only (redacted).

Clean-tree allowlist (explicit, narrow):
- `sk-FAKE-*` / `sk-fake*` fixtures in tests + pattern mentions in
  docs/LOGGING.md and the redaction REGEX in backend/app/logging_setup.py are
  documentation or test fixtures, not live keys. Live shapes that fail are
  listed in LIVE_PATTERNS below (clean tree contains ZERO of them, asserted by
  tests/test_secret_scan.py).
- The PEM regex pattern in logging_setup.py (contains `re.compile`) and the
  `MIIFake*hunter2-fake` fixture block in tests/test_logging.py are not keys.
  A PEM block fails only when it looks like real key material.
- Research docs contain prose like `task-with-...` and URLs with `skadden.com`
  etc.; the generic live-key pattern requires 20+ alphanumerics with no
  hyphens (`sk-[A-Za-z0-9]{20,}`), so hyphenated prose never trips it while a
  real leaked key (48 alphanumerics, no hyphens) always does.

Usage: python scripts/secret_scan.py [--root DIR]
Exit 0 = clean, 1 = findings (redacted list).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# High-confidence live shapes only (clean tree contains ZERO of these).
LIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("openai-live-key", re.compile(r"sk-live-[A-Za-z0-9_-]{8,}")),
    ("openai-proj-key", re.compile(r"sk-proj-[A-Za-z0-9_-]{8,}")),
    # Generic leaked key: 20+ alphanumerics, no hyphens (real keys are 48
    # alphanumerics; hyphenated prose like `task-with-...` never matches;
    # hyphenated fixtures like `sk-FAKE-...` never match either).
    ("openai-generic-key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
]

PEM_BEGIN_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
PEM_END_RE = re.compile(
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
# Fixture markers that prove a PEM block is a test/redaction fixture, not a key.
PEM_FIXTURE_MARKERS = ("Fake", "fake", "EXAMPLE", "hunter2", "MIIFake")

# Workflow hygiene: these must NEVER appear in .github/workflows/*.yml.
WORKFLOW_FORBIDDEN: list[tuple[str, re.Pattern[str]]] = [
    ("echo-secret", re.compile(r"echo\s+.*\$\{\{\s*secrets\.")),
    ("echo-env-value", re.compile(r"echo\s+.*\$[A-Z][A-Z0-9_]*")),
    ("printenv", re.compile(r"printenv")),
    # Plain `docker compose config` renders env_file SECRET VALUES to stdout
    # (see .env.example UNSAFE note + docs/COMPOSE.md). Only --quiet
    # (validate-only) and --services (names-only) are safe in CI logs.
    ("compose-config-unsafe",
     re.compile(r"compose\s+config(?!\s+--(?:quiet|services))")),
]

TEXT_SUFFIXES = {
    ".py", ".yml", ".yaml", ".toml", ".sh", ".md", ".txt", ".html",
    ".example", ".gitignore", ".dockerignore",
}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
             ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _tracked_files(root: Path) -> list[Path]:
    # Union of tracked + untracked-but-not-ignored: a PR that ADDS a file
    # with a secret must fail even before that file is committed. Ignored
    # paths (.env, caches) stay out via --exclude-standard.
    seen: dict[str, Path] = {}
    for extra in ([], ["--others", "--exclude-standard"]):
        try:
            proc = subprocess.run(
                ["git", "ls-files", *extra], cwd=root, capture_output=True,
                text=True, timeout=30)
        except Exception:
            proc = None
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.splitlines():
                seen[line] = root / line
    if seen:
        return [seen[k] for k in sorted(seen)]
    # Fallback (no git): walk working tree minus junk dirs.
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return sorted(out)


def _is_text_target(path: Path) -> bool:
    name = path.name
    if name in {"Dockerfile"} or name.startswith("Dockerfile"):
        return True
    if path.suffix in TEXT_SUFFIXES:
        return True
    return False


def _scan_live_patterns(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pname, rx in LIVE_PATTERNS:
            if rx.search(line):
                findings.append(f"{path}:{lineno}: {pname} (redacted)")
    return findings


def _scan_pem_blocks(rel: str, text: str) -> list[str]:
    findings: list[str] = []
    for match in PEM_BEGIN_RE.finditer(text):
        tail = text[match.start():match.start() + 4000]
        end = PEM_END_RE.search(tail)
        if not end:
            continue
        block = tail[:end.end()]
        context = text[max(0, match.start() - 300):match.start()]
        if "re.compile" in context or "re.compile" in block:
            continue  # redaction REGEX, not a key (logging_setup.py)
        if any(marker in block for marker in PEM_FIXTURE_MARKERS):
            continue  # test fixture block (test_logging.py MIIFake/hunter2)
        lineno = text.count("\n", 0, match.start()) + 1
        findings.append(f"{rel}:{lineno}: pem-private-key-block (redacted)")
    return findings


def _check_env_tracking(tracked: list[str]) -> list[str]:
    findings: list[str] = []
    for entry in tracked:
        if entry == ".env" or entry.endswith("/.env"):
            findings.append(f"{entry}: tracked-.env (redacted)")
    return findings


def _check_template(root: Path) -> list[str]:
    findings: list[str] = []
    template = root / ".env.example"
    if not template.is_file():
        return ["missing:.env.example (redacted)"]
    text = template.read_text(encoding="utf-8")
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        pairs[key.strip()] = value.strip()
    if pairs.get("LYZR_API_KEY", "MISSING") != "":
        findings.append(".env.example: LYZR_API_KEY must ship empty (redacted)")
    if pairs.get("LYZR_AGENT_ID", "MISSING") != "":
        findings.append(".env.example: LYZR_AGENT_ID must ship empty (redacted)")
    if "change-me" not in pairs.get("APPROVAL_SECRET", ""):
        findings.append(
            ".env.example: APPROVAL_SECRET must be placeholder (redacted)")
    for pname, rx in LIVE_PATTERNS:
        if rx.search(text):
            findings.append(
                f".env.example: {pname} live shape in template (redacted)")
    return findings


def _check_workflows(root: Path) -> list[str]:
    findings: list[str] = []
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return ["missing:.github/workflows (redacted)"]
    for yml in sorted(workflows.glob("*.yml")):
        text = yml.read_text(encoding="utf-8")
        rel = str(yml.relative_to(root))
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Comments document the bans (e.g. "NEVER runs plain compose
            # config"); only executable code can leak, so check the part
            # before any `#` comment marker.
            code = line.split("#", 1)[0]
            for pname, rx in WORKFLOW_FORBIDDEN:
                if rx.search(code):
                    findings.append(f"{rel}:{lineno}: {pname} (redacted)")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="ProofOps secret scan")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    root = Path(args.root)

    tracked = _tracked_files(root)
    tracked_names = [
        str(p.relative_to(root)).replace("\\", "/")
        for p in tracked if p.is_file()
    ]

    findings: list[str] = []
    findings.extend(_check_env_tracking(tracked_names))
    findings.extend(_check_template(root))
    findings.extend(_check_workflows(root))

    for path in tracked:
        if not path.is_file() or not _is_text_target(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        findings.extend(_scan_live_patterns(Path(rel), text))
        findings.extend(_scan_pem_blocks(rel, text))

    if findings:
        print(f"SECRET SCAN FAIL: {len(findings)} finding(s)")
        for entry in sorted(set(findings)):
            print(f"  - {entry}")
        return 1
    print(f"SECRET SCAN PASS: {len(tracked_names)} tracked files, no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
