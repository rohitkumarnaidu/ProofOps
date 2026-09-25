"""M11 runbook loader: versioned YAML load + tamper-evident hash + param check.

Ownership: M11 owns THIS FILE (``backend/app/services/runbooks.py``).
Shape validation is M01.6 (``app.contracts.runbook.Runbook``); this module
owns file intake, integrity, version-pin enforcement at load, id binding,
and parameter validation against the shipped ``parameters_schema`` dialect.

Hash = SHA256(canonical YAML-dict minus the `hash` field). Any edit without
re-stamping fails verification -> poisoned-runbook defense in depth.
A loaded ``Runbook`` is well-formed DATA, never a trusted instruction:
policy (M06) still decides every action.

Fail-closed rules (M11.2-M11.5):
- runbook_id is an identifier (letters/digits/_/-), never a path: traversal,
  separators, blank or padded ids are rejected BEFORE any filesystem touch.
- YAML must decode to a mapping; empty/scalar/list documents rejected.
- Stored `hash` must equal recomputed content hash (missing hash rejected).
- Loaded ``runbook_id`` must equal the requested id (swap/impostor defense).
- ``version`` pin is enforced by the M01.6 contract (floating rejected).
- ``validate_parameters`` honors exactly the shipped dialect: `string`
  (required non-blank unpadded text) and `integer-lo-hi` (required int,
  bool excluded, range inclusive). All declared params are required;
  undeclared params and unknown type tokens are rejected, never guessed.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.contracts.runbook import Runbook  # noqa: E402 (M01.6 canonical)
from app.contracts.values import canonical_json, sha256_hex  # noqa: E402

def _runbooks_dir() -> Path:
    """Runbook directory, resolved through app.paths.

    A parents[N] guess resolved to /runbooks in the container image, which the
    image never creates, so the hash-pinned runbook loader found nothing at
    runtime. app.paths resolves the directory the image actually ships.
    """
    from app import paths
    return paths.runbooks_dir()


RUNBOOK_DIR = _runbooks_dir()

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
_INT_RANGE_RE = re.compile(r"integer-(-?\d+)-(-?\d+)")


def content_hash(data: dict) -> str:
    body = {k: v for k, v in data.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


def _check_id(runbook_id: str) -> str:
    """Identifier gate: reject paths, blanks, padding before FS touch."""
    if not isinstance(runbook_id, str) or not runbook_id:
        raise ValueError("runbook_id must be a non-empty string")
    if runbook_id != runbook_id.strip():
        raise ValueError("runbook_id must not have leading/trailing whitespace")
    if _ID_RE.fullmatch(runbook_id) is None:
        raise ValueError(f"runbook_id is not a plain identifier: {runbook_id!r}")
    return runbook_id


def load_runbook(runbook_id: str, directory: Path = RUNBOOK_DIR) -> Runbook:
    _check_id(runbook_id)
    path = Path(directory) / f"{runbook_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"runbook not found: {runbook_id}")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"runbook document must be a mapping: {runbook_id}")
    if data.get("hash") != content_hash(data):
        raise ValueError(f"runbook hash mismatch (tampered?): {runbook_id}")
    loaded = Runbook(**data)
    if loaded.runbook_id != runbook_id:
        raise ValueError(
            f"runbook id mismatch: file holds {loaded.runbook_id!r}, "
            f"requested {runbook_id!r}"
        )
    return loaded


def validate_parameters(runbook: Runbook, params: Mapping[str, Any]) -> dict[str, Any]:
    """Check caller params against the runbook's parameters_schema dialect.

    Returns a plain-dict copy on success; raises ValueError (fail-closed) on:
    non-mapping params, missing/undeclared params, blank/padded strings,
    non-int or out-of-range integers, unknown type tokens.
    """
    if not isinstance(params, Mapping):
        raise ValueError("params must be a mapping")
    schema = runbook.parameters_schema.to_plain()
    for name in schema:
        if name not in params:
            raise ValueError(f"missing required runbook param: {name!r}")
    for name in params:
        if name not in schema:
            raise ValueError(f"undeclared runbook param: {name!r}")
    checked: dict[str, Any] = {}
    for name, token in schema.items():
        value = params[name]
        if token == "string":
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"param {name!r} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"param {name!r} must not be padded")
            checked[name] = value
            continue
        m = _INT_RANGE_RE.fullmatch(token) if isinstance(token, str) else None
        if m is not None:
            lo, hi = int(m.group(1)), int(m.group(2))
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"param {name!r} must be an integer")
            if not lo <= value <= hi:
                raise ValueError(f"param {name!r} must be within {lo}..{hi}")
            checked[name] = value
            continue
        raise ValueError(f"unknown runbook param type for {name!r}: {token!r}")
    return checked


def stamp_hashes(directory: Path = RUNBOOK_DIR) -> None:
    """Maintainer op: recompute `hash` after an intentional, reviewed edit."""
    for path in sorted(Path(directory).glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        data["hash"] = content_hash(data)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
