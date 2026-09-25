"""Resolve runtime assets and state across source-tree and container layouts.

The source tree keeps the backend under ``backend/app`` and keeps policies and
runbooks at the repository root, while the API image flattens the backend to
``/app/app`` and copies the runtime assets beside it at ``/app/policies`` and
``/app/runbooks``. This module is the single path boundary for both layouts;
runtime state is resolved separately so it can be mounted persistently.

Resolution is LOCATION-derived, never environment-derived: the project
governance pin (``test_config_hardening.py``) forbids ``os.environ`` access
anywhere under ``backend/`` so that every configuration read flows through the
frozen ``Settings`` object. ``config.py`` is frozen, so there is no
``Settings`` field for a path override and none is invented here. An operator
relocates state by mounting a volume at the resolved ``state_dir()``.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def repo_root() -> Path:
    """Find the repository or image root containing runtime asset folders."""
    module_path = Path(__file__).resolve()
    for candidate in module_path.parents:
        if (candidate / "policies").is_dir() and \
                (candidate / "runbooks").is_dir():
            return candidate
    parents = module_path.parents
    return parents[3] if len(parents) > 3 else parents[-1]


def state_dir() -> Path:
    """Return the resolved state directory without creating it."""
    return repo_root() / "var"


def policies_dir() -> Path:
    """Return the directory containing versioned policy assets."""
    return repo_root() / "policies"


def runbooks_dir() -> Path:
    """Return the directory containing pinned runbook assets."""
    return repo_root() / "runbooks"


def key_store_path() -> Path:
    """Return the persistent API key-store path without creating its parent."""
    return state_dir() / "api_keys.json"


def describe_paths() -> dict[str, str]:
    """Return all resolved runtime paths as strings."""
    return {
        "repo_root": str(repo_root()),
        "state_dir": str(state_dir()),
        "policies_dir": str(policies_dir()),
        "runbooks_dir": str(runbooks_dir()),
        "key_store_path": str(key_store_path()),
    }


def missing_runtime_paths() -> list[str]:
    """List required runtime assets that are absent, without raising."""
    required = (
        "policies",
        "runbooks",
        "policies/slo.yaml",
        "policies/pricing.yaml",
        "runbooks/bad-deploy-rollback.yaml",
    )
    try:
        policy_root = policies_dir()
        runbook_root = runbooks_dir()
        checks = (
            ("policies", policy_root, True),
            ("runbooks", runbook_root, True),
            ("policies/slo.yaml", policy_root / "slo.yaml", False),
            ("policies/pricing.yaml", policy_root / "pricing.yaml", False),
            (
                "runbooks/bad-deploy-rollback.yaml",
                runbook_root / "bad-deploy-rollback.yaml",
                False,
            ),
        )
    except Exception:
        return list(required)

    missing: list[str] = []
    for name, path, directory in checks:
        try:
            present = path.is_dir() if directory else path.is_file()
        except Exception:
            present = False
        if not present:
            missing.append(name)
    return missing
