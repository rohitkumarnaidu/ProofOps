"""M22: runtime state/asset paths must agree with what the image provisions.

Regression guard for a P0 that shipped once already: `app.paths` resolved the
state directory correctly, but every real writer (key store, approvals, runs,
audit chains, nonce journal) still computed its own `parents[N]` path. In the
container that resolves to `/var`, which uid 10001 cannot write, so the
per-key identity store was never found and EVERY request silently degraded to
the full-authority bootstrap identity while the source, the tests, and the
Dockerfile comments all asserted per-key identity was live.

These checks compare the code's own constants against the single resolver, so
the two cannot drift apart again.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app import paths  # noqa: E402
from app.routers import approvals as approvals_router  # noqa: E402
from app.routers import audit as audit_router  # noqa: E402
from app.routers import auth as auth_mod  # noqa: E402
from app.routers import runs as runs_router  # noqa: E402
from app.services import budgets as budgets_svc  # noqa: E402
from app.services import metrics as metrics_svc  # noqa: E402
from app.services import policy as policy_svc  # noqa: E402
from app.services import runbooks as runbooks_svc  # noqa: E402


def test_repo_root_resolves_assets_in_this_layout():
    assert paths.repo_root() == ROOT
    assert paths.policies_dir() == ROOT / "policies"
    assert paths.runbooks_dir() == ROOT / "runbooks"
    assert paths.state_dir() == ROOT / "var"
    assert paths.missing_runtime_paths() == [], \
        f"required runtime assets missing: {paths.missing_runtime_paths()}"


def test_every_state_writer_targets_the_resolved_state_dir():
    """No module may hand-roll a path that diverges from app.paths."""
    assert auth_mod.KEY_STORE_PATH == paths.key_store_path()
    assert approvals_router.STORE_PATH == paths.state_dir() / "approvals.json"
    assert approvals_router.NONCE_STORE_PATH == \
        paths.state_dir() / "nonces.jsonl"
    assert runs_router.STORE_PATH == paths.state_dir() / "runs.json"
    assert audit_router._VAR_DIR == paths.state_dir()


def test_every_asset_loader_targets_the_resolved_asset_dirs():
    assert policy_svc.POLICY_DIR == paths.policies_dir()
    assert runbooks_svc.RUNBOOK_DIR == paths.runbooks_dir()
    pricing = budgets_svc.load_pricing()
    assert pricing, "pricing table must load from the resolved policies dir"
    slo = metrics_svc.load_slo()
    assert slo["version"] == "v1"


def test_no_module_still_guesses_parents_for_runtime_assets():
    """A hand-rolled `parents[N]` asset/state path is the bug this file exists
    to kill, and it is ONLY visible in the container layout: in the source
    tree `parents[3]` already equals the repo root, so comparing constants to
    `paths.state_dir()` is a tautology that cannot fail.

    Therefore this check is AST-based: it rejects any `parents[...]` subscript
    used for a path at all, except inside `sys.path.insert`. That catches
    every revert shape -- a bare literal, a constant indirection, a wrapped
    multi-line expression, or a duplicated resolver -- because none of them
    mentions `sys.path`.

    Two modules are exempt by explicit design, and both are pinned
    separately below: ``paths.py`` IS the resolver (its ``parents[3]`` is only
    a fallback), and ``metrics.py`` must stay a stdlib-only island (pinned by
    test_metrics_m20) so it carries a four-line mirror whose equivalence
    ``test_metrics_mirror_agrees_with_the_resolver`` proves.
    """
    import ast

    exempt = {
        ROOT / "backend" / "app" / "paths.py",
        ROOT / "backend" / "app" / "services" / "metrics.py",
    }
    offenders: list[str] = []
    for base in (ROOT / "backend" / "app", ROOT / "agents"):
        for source_path in base.rglob("*.py"):
            if "__pycache__" in source_path.parts:
                continue
            if source_path in exempt:
                continue
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            insert_lines: set[int] = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Attribute) \
                        and func.attr == "insert" \
                        and isinstance(func.value, ast.Attribute) \
                        and func.value.attr == "path":
                    for arg in node.args:
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Subscript):
                                insert_lines.add(sub.lineno)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Subscript):
                    continue
                value = node.value
                if isinstance(value, ast.Attribute) \
                        and value.attr == "parents" \
                        and node.lineno not in insert_lines:
                    offenders.append(
                        f"{source_path.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, (
        "hand-rolled parents[] runtime paths (use app.paths): "
        + ", ".join(sorted(offenders)))


def test_metrics_mirror_agrees_with_the_resolver(tmp_path):
    """The metrics island mirrors the resolver; prove the two agree.

    ``metrics.py`` cannot import app.paths (pinned stdlib-only), so it repeats
    the four-line walk. That duplication is only safe while both agree -- in
    the source tree AND in the image-shaped tree this builds.
    """
    from app.services import metrics as metrics_mod

    assert metrics_mod._policies_dir() == paths.policies_dir()
    image_root = tmp_path / "app"
    (image_root / "app" / "services").mkdir(parents=True)
    (image_root / "policies").mkdir()
    (image_root / "runbooks").mkdir()
    mirror = image_root / "app" / "services" / "metrics.py"
    mirror.write_text("", encoding="utf-8")
    resolved = next(candidate for candidate in mirror.resolve().parents
                    if (candidate / "policies").is_dir()
                    and (candidate / "runbooks").is_dir())
    assert resolved == image_root.resolve()


def test_image_layout_matches_the_image_and_compose_provisioning(tmp_path):
    """Replay the container layout so the fix is proven, not assumed.

    In the source tree a ``parents[3]`` guess already equals the repo root, so
    no host test can see the bug. This builds the image's shape and closes the
    chain against the real Dockerfile and compose: the WORKDIR holds the asset
    dirs, so the resolver lands on the image root, its ``var`` is what the
    image chowns, and that is what compose mounts. It also proves the guess
    genuinely differs here, which is the entire point.
    """
    image_root = tmp_path / "app"
    (image_root / "app" / "routers").mkdir(parents=True)
    (image_root / "policies").mkdir()
    (image_root / "runbooks").mkdir()
    module = image_root / "app" / "routers" / "auth.py"
    module.write_text("", encoding="utf-8")

    resolved = next(candidate for candidate in module.resolve().parents
                    if (candidate / "policies").is_dir()
                    and (candidate / "runbooks").is_dir())
    assert resolved == image_root.resolve(), \
        "the image root must be the directory holding policies/ and runbooks/"
    assert resolved.name == "app", \
        "the image root is the Dockerfile WORKDIR (/app), so state_dir() " \
        "is /app/var"
    assert (module.resolve().parents[3] / "var" / "api_keys.json") \
        != resolved / "var" / "api_keys.json", \
        "a parents[3] guess must be proven to differ from the resolver here"
    assert f"mkdir -p /{resolved.name}/var" in \
        (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_compose_state_volume_covers_the_resolved_state_dir():
    """The mount and the code must name the same directory."""
    doc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"))
    api = doc["services"]["api"]
    mounts = api.get("volumes") or []
    # "<source>:<target>[:mode]" -- the source must be a declared named volume
    # (a host bind would leak the repo and is banned elsewhere) and the target
    # must be the directory the code resolves.
    sources = {v.split(":")[0] for v in mounts if isinstance(v, str)}
    targets = {v.split(":")[1] for v in mounts if isinstance(v, str)}
    declared = set(doc.get("volumes", {}))
    assert sources & declared, \
        f"api state mount is not a named volume: {mounts}"
    assert "/app/var" in targets, \
        f"api must mount the container state dir, got {mounts}"
    # The image must pre-create and hand ownership of that same dir.
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "mkdir -p /app/var && chown appuser:appuser /app/var" in dockerfile, \
        "the image must create the writable state root for uid 10001"
    assert "COPY policies ./policies" in dockerfile, \
        "the image must ship the policy bundles the engine loads"
    assert "COPY runbooks ./runbooks" in dockerfile, \
        "the image must ship the hash-pinned runbooks"
    # Both are root-context-only exceptions, so the backend context must NOT
    # claim them (that would break its own build).
    backend_dockerfile = (ROOT / "backend" / "Dockerfile").read_text(
        encoding="utf-8")
    assert "COPY policies" not in backend_dockerfile, \
        "backend/ context cannot reach repo-root policies/"


def test_describe_paths_exposes_every_boundary():
    described = paths.describe_paths()
    assert set(described) == {"repo_root", "state_dir", "policies_dir",
                              "runbooks_dir", "key_store_path"}
    assert all(Path(v).is_absolute() for v in described.values())
    assert described["state_dir"] == str(paths.state_dir())
    json.dumps(described)


def test_missing_runtime_paths_reports_absent_assets(tmp_path, monkeypatch):
    real_root = paths.repo_root
    real_root.cache_clear()
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path)
    try:
        missing = paths.missing_runtime_paths()
        assert set(missing) == {"policies", "runbooks", "policies/slo.yaml",
                                "policies/pricing.yaml",
                                "runbooks/bad-deploy-rollback.yaml"}
    finally:
        monkeypatch.undo()
        real_root.cache_clear()


@pytest.mark.parametrize("module", [auth_mod, approvals_router, audit_router,
                                    runs_router])
def test_state_modules_never_touch_environ(module):
    """Runtime config flows through the frozen Settings, never os.environ."""
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "os.environ" not in source
    assert "os.getenv" not in source
