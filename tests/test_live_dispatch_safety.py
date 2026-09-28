"""Zero-trust tests for live-tier dispatch in the pipeline.

The hazard these exist to prevent is not a crash. It is a *plausible success*.

`pipeline._apply_action` used to catch every exception from the live Kubernetes
executor and fall through to the in-memory sandbox, which then reported success.
A cluster refusing an action for lack of permission, or failing mid-rollout, was
recorded as "action applied, now verifying" -- against a dict that never touched
the cluster. The audit chain would carry a remediation that did not happen, and
the verifier would agree with it, because both were looking at the same
fiction. That is worse than an outage: it is an outage reported as a fix.

Every test here is about what the dispatch must *not* do.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "backend" / "app" / "services" / "pipeline.py"
CONFIG = ROOT / "backend" / "app" / "config.py"
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
LIVE_TIER = ROOT / "scripts" / "live_tier.sh"


def _fn(name: str) -> ast.FunctionDef:
    tree = ast.parse(PIPELINE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in pipeline.py")


def _body_code(name: str) -> str:
    node = _fn(name)
    return "\n".join(ast.dump(s) for s in node.body)


# ---------------------------------------------------------------------------
# No silent downgrade
# ---------------------------------------------------------------------------

def test_live_execution_never_falls_back_to_the_mock():
    """A live-tier failure must propagate, not become a mock success."""
    body = _body_code("_apply_action")
    # No `except Exception` anywhere in the dispatch.
    assert "ExceptHandler" not in body, (
        "_apply_action must not catch exceptions from the live executor. A "
        "caught live failure that falls through to the mock is reported as a "
        "remediation that never happened.")
    assert "pass" not in [
        n.id for n in ast.walk(_fn("_apply_action"))
        if isinstance(n, ast.Name)
    ], "a bare `pass` in the dispatch swallows a live failure"


def test_live_execution_requires_the_cluster_to_be_reachable():
    """Opting into live with no cluster is an error, not a mock run.

    The operator asked for real execution. Quietly giving them the mock would
    make the setting a lie in the one situation where someone is watching to see
    whether the live tier really works.
    """
    node = _fn("_apply_action")
    body = ast.unparse(node)
    assert "LIVE_CLUSTER" in body
    assert "is_connected" in body, (
        "the live path must check reachability and refuse if absent")
    assert "PipelineError" in body or "raise" in body, (
        "an enabled-but-unreachable live cluster must raise, not fall through")


# ---------------------------------------------------------------------------
# Reachability is not consent
# ---------------------------------------------------------------------------

def test_reachability_alone_never_selects_the_live_executor():
    """The live tier is opt-in, not auto-detected.

    A developer with a KIND cluster running must not silently acquire real
    cluster mutations. The mock is the documented default (AGENTS.md 6.5).
    """
    body = ast.unparse(_fn("_apply_action"))
    # is_connected must not be the *first* condition guarding the live branch;
    # LIVE_CLUSTER has to be the gate.
    first_live = body.find("LIVE_CLUSTER")
    first_conn = body.find("is_connected")
    assert first_live != -1, "the live tier must be gated on explicit config"
    assert first_conn == -1 or first_live < first_conn, (
        "LIVE_CLUSTER must be checked before is_connected so reachability "
        "cannot select the live executor by itself")


def test_live_cluster_is_off_by_default_everywhere():
    """Default off in config, compose, and the env template.

    All three must agree. A default that is on in any one of them is a default
    that reaches production.
    """
    tree = ast.parse(CONFIG.read_text(encoding="utf-8"))
    defaults: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                defaults[node.target.id] = node.value
    assert "LIVE_CLUSTER" in defaults, "LIVE_CLUSTER must be a declared setting"
    assert isinstance(defaults["LIVE_CLUSTER"], ast.Constant)
    assert defaults["LIVE_CLUSTER"].value is False, (
        "LIVE_CLUSTER must default to False -- reaching a cluster is not "
        "consent to mutate it")

    compose = COMPOSE.read_text(encoding="utf-8")
    assert "LIVE_CLUSTER: ${LIVE_CLUSTER:-false}" in compose, (
        "compose must default LIVE_CLUSTER to false")
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "LIVE_CLUSTER=false" in env, "the env template must default it to false"


# ---------------------------------------------------------------------------
# The setting is governed, not ad hoc
# ---------------------------------------------------------------------------

def test_live_cluster_is_registered_in_the_config_inventory():
    """Parity with every other setting: inventory, docs, template.

    An unregistered setting is a setting nobody can discover or audit, which is
    how a live-mutation switch becomes folklore.
    """
    inventory = CONFIG.read_text(encoding="utf-8")
    assert '"LIVE_CLUSTER"' in inventory, (
        "LIVE_CLUSTER must appear in Settings.inventory()")

    docs = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    assert "LIVE_CLUSTER" in docs, "LIVE_CLUSTER must be documented"


def test_the_pipeline_reads_live_cluster_through_settings():
    """No direct os.environ in the dispatch path.

    Mirrors test_config_hardening's rule: everything resolves through Settings so
    the inventory stays truthful.
    """
    node = _fn("_apply_action")
    body = ast.unparse(node)
    assert "get_settings" in body, (
        "_apply_action must read LIVE_CLUSTER through get_settings()")
    assert "os.environ" not in body


@pytest.mark.parametrize(
    "marker",
    ["K8S_EXECUTOR", "sandbox_svc"],
)
def test_both_tiers_remain_reachable(marker):
    """Both dispatch targets must still be used.

    Guards against a well-intentioned "fix" that hardcodes one tier and quietly
    removes the other, which would make the mock unreachable for tests and the
    live tier unreachable for operators.
    """
    body = ast.unparse(_fn("_apply_action"))
    assert marker in body, f"{marker} must remain a dispatch target"


# ---------------------------------------------------------------------------
# The provisioning script. These are the two ways it could be "green" while
# leaving the operator worse off than before.
# ---------------------------------------------------------------------------


def test_live_tier_pulls_no_unpinned_images() -> None:
    """No `:latest` in the provisioning script.

    The repository pins every base it builds, and `tests/test_compose.py`
    asserts that for compose services. This script was outside that assertion,
    so it had drifted to `prom/prometheus:latest`: the live tier would pull a
    different Prometheus on every machine and on every rebuild, and a green run
    would not mean the version anyone tested.
    """
    source = LIVE_TIER.read_text(encoding="utf-8")
    offenders = [
        line.strip() for line in source.splitlines()
        if ":latest" in line and not line.strip().startswith("#")
    ]
    assert not offenders, (
        "live_tier.sh must pin every image it pulls; unpinned: "
        f"{offenders}. A demo that silently upgrades itself is not a demo you "
        "can trust or reproduce."
    )


def test_teardown_leaves_the_stack_startable() -> None:
    """`down` must not break the next `docker compose up`.

    `kind delete cluster` also removes the `kind` Docker network, and
    docker-compose.yml declares that network `external: true` with the api
    service attached to it. Compose treats a missing external network as a hard
    error, not a warning. So tearing down the live tier used to make the stack
    unstartable, for a reason that had nothing to do with the live tier and
    nothing in its own output to hint at.
    """
    source = LIVE_TIER.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")

    # Precondition: the hazard is real, so this test cannot rot into a no-op.
    assert "external: true" in compose, (
        "compose no longer declares an external network; if the kind network is "
        "no longer external this test is obsolete and should be deleted rather "
        "than left passing"
    )

    delete_at = source.index("kind delete cluster")
    down_at = source.index("down() {")
    after_delete = source[delete_at:]
    assert "docker network create" in after_delete, (
        "down() must recreate the 'kind' network after deleting the cluster, or "
        "the next `docker compose up` fails on a missing external network"
    )
    # And the recreate must be inside down(), not somewhere unrelated.
    assert down_at < delete_at < source.index("case \"${1:-up}\""), (
        "the network recreation has drifted outside down(); the teardown path is "
        "the only place it is correct"
    )
