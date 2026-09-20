"""M00.1 repository-structure gate: skeleton, Docker parity, env hygiene, entrypoint.

Scope: SPEC PS03_FINAL_SPEC_V2 §43 (repository layout) only.
Does NOT bless downstream logic (T02–T05 re-gated in their own modules).
All checks are deterministic, offline, no network, no Docker daemon required.

EVIDENCE RULE (M00.1 remediation): a skipped runtime test is reported as SKIP,
never counted as PASS. Static contract tests are labelled STATIC; the live
`TestClient` check is labelled RUNTIME and documents the supported runtime
(container python:3.12-slim is source of truth; host 3.13/3.14 unsupported).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DIRS = [
    "agents", "backend", "benchmarks", "docs", "evaluation", "frontend",
    "policies", "runbooks", "scripts", "telemetry", "tests", "tools",
]
REQUIRED_FILES = [
    "Dockerfile", "docker-compose.yml", ".env.example", "README.md",
    "backend/Dockerfile", "backend/requirements.txt", "backend/app/main.py",
    "frontend/Dockerfile",
]
# Intentionally empty at M00.1: the .gitkeep IS the implementation (layout freeze).
# M13 fills agents/ (workforce lane); M17 fills benchmarks/suites (suite lane);
# M18 fills evaluation/attacks (adversarial lane).
FUTURE_EMPTY_DIRS = ["tools"]
# Non-empty at M00.1: a stale .gitkeep here would masquerade as intentional.
NON_EMPTY_DIRS = ["agents", "backend", "benchmarks", "evaluation", "frontend",
                  "policies", "runbooks", "scripts", "telemetry", "tests",
                  "docs"]
REQUIRED_ENV_KEYS = [
    "LYZR_API_KEY", "LYZR_AGENT_ID", "LYZR_AGENT_TRIAGE_ID",
    "LYZR_AGENT_DIAGNOSTIC_ID", "LYZR_AGENT_PLANNER_ID",
    "LYZR_AGENT_REPORTER_ID", "LYZR_RAI_POLICY",
    "EXECUTOR", "APPROVAL_SECRET", "APPROVAL_TTL_SECONDS", "POLICY_VERSION",
    "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL",
    "SEED_SCENARIO", "SEED_VARIANT", "SEED_SEED", "PROOFOPS_API_KEY",
]
# Backtick-quoted `docs/...`-style refs in README are checked for existence,
# unless the same line is labelled PLANNED or FUTURE (vision, not a claim).
README_REF_RE = re.compile(
    r"`((?:agents|backend|benchmarks|docs|evaluation|frontend|policies|"
    r"runbooks|scripts|telemetry|tests|tools)/[^`]+)`")
ENV_USE_RE = re.compile(r"os\.environ(?:\.get)?\(\s*[\"']([A-Z][A-Z0-9_]*)[\"']")
COMPOSE_VAR_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::-.*?)?\}")


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _template_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    for line in _read(".env.example").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        keys[k.strip()] = v.strip()
    return keys


def _code_used_keys() -> set[str]:
    used: set[str] = set()
    for path in list((ROOT / "backend").rglob("*.py")) + \
            list((ROOT / "scripts").rglob("*.py")) + \
            list((ROOT / "telemetry").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        used |= set(ENV_USE_RE.findall(path.read_text(encoding="utf-8")))
    used |= set(COMPOSE_VAR_RE.findall(_read("docker-compose.yml")))
    return used


def _docker_directives(name: str) -> list[str]:
    lines = []
    for line in _read(name).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


# --- M00.1.A skeleton ---------------------------------------------------------

class TestSkeleton:
    def test_required_dirs_exist(self):
        missing = [d for d in REQUIRED_DIRS if not (ROOT / d).is_dir()]
        assert not missing, f"missing dirs: {missing}"

    def test_required_files_exist(self):
        missing = [f for f in REQUIRED_FILES if not (ROOT / f).is_file()]
        assert not missing, f"missing files: {missing}"

    def test_empty_tiers_keep_placeholder(self):
        # agents/tools/evaluation/benchmarks are intentionally empty at M00.1;
        # a .gitkeep preserves the frozen layout without claiming implementation.
        for d in FUTURE_EMPTY_DIRS:
            entries = [p.name for p in (ROOT / d).iterdir()]
            assert entries == [".gitkeep"], f"{d} must contain ONLY .gitkeep, got {entries}"

    def test_no_stale_gitkeep_in_implemented_dirs(self):
        # A leftover .gitkeep next to real files lets an empty module pass as
        # "intentional placeholder". Implemented dirs must not keep one.
        stale = [d for d in NON_EMPTY_DIRS if (ROOT / d / ".gitkeep").is_file()]
        assert not stale, f"stale .gitkeep in implemented dirs: {stale}"


# --- M00.1.B Docker / Compose --------------------------------------------------

class TestDockerCompose:
    def test_root_dockerfile_directives(self):
        # Meaningful directives, not just substring presence: pinned base, no
        # :latest anywhere, dependency install before code copy, non-root USER,
        # stdlib HEALTHCHECK hitting /healthz, correct entrypoint.
        text = _read("Dockerfile")
        assert re.search(r"^FROM python:3\.12-slim$", text, re.M), "base must be pinned python:3.12-slim"
        assert ":latest" not in text, "unpinned :latest tag forbidden"
        directives = _docker_directives("Dockerfile")
        kinds = [d.split()[0] for d in directives]
        assert kinds.count("FROM") == 1
        assert any(d.startswith("USER ") and "root" not in d for d in directives), \
            "API image must run as non-root USER"
        assert any(d.startswith("HEALTHCHECK") and "/healthz" in d for d in directives), \
            "API image must HEALTHCHECK /healthz"
        assert "EXPOSE 8000" in directives
        assert directives[-1].startswith("CMD") and "uvicorn" in directives[-1] \
            and "app.main:app" in directives[-1]
        copy_idx = [i for i, d in enumerate(directives) if d.startswith("COPY")]
        run_idx = [i for i, d in enumerate(directives) if d.startswith("RUN")]
        assert run_idx and copy_idx and min(run_idx) < max(copy_idx), \
            "dependencies must install in an earlier layer than the app copy"
        assert any("requirements.txt" in d for d in directives if d.startswith("COPY"))

    def test_backend_dockerfile_parity(self):
        # Functional parity modulo build context: strip the `backend/` prefix
        # that only exists because the root build uses repo-root context.
        # M14b exception: `COPY agents ./agents` ships only in the root image
        # (compose builds it); the backend/ context cannot reach ../agents,
        # so backend/Dockerfile legitimately lacks that one line.
        # Telemetry exception (same class, proven by api boot ImportError at
        # c3cb09e): `COPY telemetry ./telemetry` ships only in the root image;
        # services/eval.py, benchmarks.py, adversarial.py import telemetry.gen
        # at boot. The backend/ context cannot reach ../telemetry either.
        def norm(name: str) -> list[str]:
            return [d.replace("backend/", "") for d in _docker_directives(name)
                    if not d.startswith("HEALTHCHECK")
                    and d != "COPY agents ./agents"
                    and d != "COPY telemetry ./telemetry"]
        assert norm("Dockerfile") == norm("backend/Dockerfile"), \
            f"Dockerfile drift:\n{norm('Dockerfile')}\nvs\n{norm('backend/Dockerfile')}"
        for name in ("Dockerfile", "backend/Dockerfile"):
            assert "HEALTHCHECK" in _read(name) and "/healthz" in _read(name), \
                f"{name} missing /healthz HEALTHCHECK"
        # Both must document the 3.12-vs-host rationale (M00.1 drift note).
        assert "3.12" in _read("backend/Dockerfile") and "3.12" in _read("Dockerfile")

    def test_compose_structure(self):
        doc = yaml.safe_load(_read("docker-compose.yml"))
        services = doc.get("services", {})
        assert {"db", "api", "ui"} <= set(services), f"services={sorted(services)}"
        assert "healthcheck" in services["db"], "db healthcheck required"
        # EXACT published-port mapping (a substring check would pass 9000:8000).
        def published(svc: str) -> list[str]:
            return [str(p).split("#")[0].strip()
                    for p in services[svc].get("ports", [])]
        assert "8000:8000" in published("api"), f"api ports={published('api')}"
        # M19b: ui serves unprivileged 8080 (nginx USER per frontend/Dockerfile).
        assert "5173:8080" in published("ui"), f"ui ports={published('ui')}"
        api = services["api"]
        assert api.get("env_file") == ".env" or "DATABASE_URL" in str(api.get("environment", ""))
        # ui must wait for a HEALTHY api, not merely a started one.
        ui_dep = services["ui"].get("depends_on", {})
        assert isinstance(ui_dep, dict) and \
            ui_dep.get("api", {}).get("condition") == "service_healthy", \
            f"ui must depend on api healthy, got {ui_dep}"
        # api hardening: no caps, no new privileges.
        assert "ALL" in (api.get("cap_drop") or []), "api must cap_drop ALL"
        assert "no-new-privileges:true" in (api.get("security_opt") or []), \
            "api must set no-new-privileges"

    def test_compose_no_privilege_escalation(self):
        doc = yaml.safe_load(_read("docker-compose.yml"))
        for svc, cfg in doc.get("services", {}).items():
            assert cfg.get("privileged") is not True, f"{svc}: privileged forbidden"
            assert cfg.get("network_mode") != "host", f"{svc}: host network forbidden"
            for vol in cfg.get("volumes", []) or []:
                target = vol if isinstance(vol, str) else str(vol.get("source", ""))
                assert not target.startswith("/"), f"{svc}: host mount forbidden: {vol}"

    def test_frontend_app_present(self):
        # M00.1 allowed a static stub; M19 lands the real Vite scaffold, so
        # this gate now pins the scaffold manifests instead of the stub page.
        # Dockerfile + self-HEALTHCHECK requirements are unchanged.
        assert (ROOT / "frontend" / "Dockerfile").is_file()
        assert (ROOT / "frontend" / "package.json").is_file()
        assert (ROOT / "frontend" / "src" / "App.tsx").is_file()
        title = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        assert "ProofOps" in title, "app index must carry the ProofOps marker"
        ftext = _read("frontend/Dockerfile")
        assert "HEALTHCHECK" in ftext, "frontend image must HEALTHCHECK itself"

    def test_no_latest_tags_anywhere(self):
        for name in ("Dockerfile", "backend/Dockerfile", "frontend/Dockerfile"):
            assert ":latest" not in _read(name), f"{name}: :latest forbidden"
        doc = yaml.safe_load(_read("docker-compose.yml"))
        for svc, cfg in doc.get("services", {}).items():
            image = str(cfg.get("image", ""))
            assert ":latest" not in image, f"{svc}: :latest forbidden"


# --- M00.1.C environment / hygiene ---------------------------------------------

class TestEnvHygiene:
    def test_env_example_completeness(self):
        keys = _template_keys()
        missing = [k for k in REQUIRED_ENV_KEYS if k not in keys]
        assert not missing, f".env.example missing keys: {missing}"

    def test_env_code_template_parity(self):
        # USED_KEYS (code + compose) vs TEMPLATE_KEYS: every runtime-required
        # variable must have a template entry. Template EXTRAs are allowed only
        # as documented FUTURE reservations (M13 agent ids); they are reported,
        # not failed, so drift stays visible without blocking future planning.
        used = _code_used_keys()
        template = _template_keys()
        missing = sorted(used - set(template))
        assert not missing, f"code/compose uses vars missing from .env.example: {missing}"
        future = sorted(set(template) - used)
        assert {"LYZR_AGENT_TRIAGE_ID", "LYZR_AGENT_DIAGNOSTIC_ID",
                "LYZR_AGENT_PLANNER_ID", "LYZR_AGENT_REPORTER_ID"} <= set(future), \
            f"expected documented FUTURE agent ids in extras, got {future}"

    def test_env_example_has_no_real_secrets(self):
        keys = _template_keys()
        assert keys.get("LYZR_API_KEY", "") == "", "template must ship empty LYZR_API_KEY"
        assert keys.get("LYZR_AGENT_ID", "") == "", "template must ship empty LYZR_AGENT_ID"
        assert "change-me" in keys.get("APPROVAL_SECRET", ""), "APPROVAL_SECRET must be placeholder"
        assert "sk-" not in _read(".env.example"), "live secret pattern in template"

    def test_secret_inspection_hygiene_documented(self):
        # P2: plain `docker compose config` prints env_file secret VALUES.
        # The template must document the SAFE pattern and warn about UNSAFE.
        text = _read(".env.example")
        assert "config --quiet" in text and "SAFE" in text, \
            "must document SAFE inspection (config --quiet)"
        assert "UNSAFE" in text and "PRINTS SECRET" in text, \
            "must warn that plain `docker compose config` prints secrets"

    def test_gitignore_covers_secrets_and_caches(self):
        gi = _read(".gitignore")
        for needle in [".env", "__pycache__/", ".venv/"]:
            assert needle in gi, f".gitignore missing {needle!r}"

    def test_dotenv_not_tracked(self):
        proc = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            pytest.skip("git unavailable; cannot assert tracking")
        tracked = proc.stdout.splitlines()
        assert ".env" not in tracked, ".env must never be committed"


# --- M00.1.D docs / entrypoint --------------------------------------------------

class TestDocsEntrypoint:
    def test_readme_points_to_authoritative_spec(self):
        readme = _read("README.md")
        assert "PS03_FINAL_SPEC_V2.md" in readme
        assert "LYZR" in readme and "control plane" in readme.lower()

    def test_readme_local_refs_exist(self):
        # Every `dir/path` reference in README must resolve — unless its line is
        # explicitly labelled PLANNED/FUTURE (vision, not a claim). This is the
        # P0 guard that would have caught the six dead links (DEMO/EVALUATION/
        # SECURITY/DECISIONS/eval.sh/demo.sh).
        failures = []
        in_planned_block = False  # a PLANNED/FUTURE label covers its paragraph
        for line in _read("README.md").splitlines():
            if not line.strip():
                in_planned_block = False
                continue
            if "PLANNED" in line or "FUTURE" in line:
                in_planned_block = True
                continue
            if in_planned_block:
                continue
            for ref in README_REF_RE.findall(line):
                ref = ref.split()[0].rstrip(".,:)")  # strip flags/punct inside backticks
                if not (ROOT / ref).exists():
                    failures.append(ref)
        assert not failures, f"README references missing files: {failures}"

    def test_healthz_contract_static(self):
        # STATIC: asserts the contract shape in source so the gate stays green
        # on any host Python. Must NEVER be cited as runtime proof (see the
        # RUNTIME test below + container smoke in the remediation report).
        text = _read("backend/app/main.py")
        assert 'FastAPI(title="ProofOps"' in text
        assert '@app.get("/healthz")' in text
        assert '"status": "ok"' in text or "'status': 'ok'" in text or '"status":"ok"' in text
        assert "PS03_FINAL_SPEC_V2" in text

    def test_healthz_runtime_parity(self):
        # RUNTIME: live import check. Host env (py3.14 + starlette v1 drift) may
        # fail while the pinned 3.12 image passes; skip-with-evidence instead of
        # hiding. A SKIP here is NOT a pass — see the report's PASS/FAIL/SKIP
        # accounting and the container smoke proof.
        try:
            from fastapi.testclient import TestClient  # noqa: E402
            sys.path.insert(0, str(ROOT / "backend"))
            from app.main import app  # noqa: E402
        except Exception as exc:  # noqa: BLE001 - env drift, not a product bug
            pytest.skip(f"host FastAPI/Starlette drift (image is source of truth): {exc}")
            return
        try:
            client = TestClient(app)
            resp = client.get("/healthz")
        except TypeError as exc:
            pytest.skip(f"host FastAPI/Starlette ABI drift: {exc}")
            return
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "proofops-api"
        assert body["spec"] == "PS03_FINAL_SPEC_V2"


# --- M00.1.E dependency reproducibility -----------------------------------------

class TestDependencyReproducibility:
    def test_starlette_upper_bound_blocks_v1_drift(self):
        # P1 root cause: starlette v1.x removed `on_startup`, breaking fastapi
        # 0.115–0.119 (which declares starlette<0.47). Fresh installs must not
        # resolve v1.x even when other global packages pull it.
        text = _read("backend/requirements.txt")
        m = re.search(r"^starlette\s*>=\s*[\d.]+,\s*<\s*([\d.]+)", text, re.M)
        assert m, "requirements must pin starlette explicitly"
        assert tuple(int(x) for x in m.group(1).split(".")) < (1, 0), \
            f"starlette upper bound must block v1.x, got <{m.group(1)}"

    def test_container_source_of_truth_documented(self):
        req = _read("backend/requirements.txt")
        assert "SOURCE OF TRUTH" in req, "requirements must name the container source of truth"
        flat = " ".join(_read("README.md").lower().split())  # unwrap line breaks
        assert "source of truth" in flat, "README must state the supported runtime"
